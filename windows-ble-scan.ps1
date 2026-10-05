#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServiceUuid,

    [ValidateRange(1, 3600)]
    [int]$DurationSeconds = 30,

    [switch]$CompileOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Initialize-BleWatcherBridge {
    if ('XXPhoneInputGuardBleV1.BleWatcherBridge' -as [type]) {
        return
    }

    $runtimeDirectory = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $winMetadataDirectory = Join-Path $env:windir 'System32\WinMetadata'
    $references = @(
        (Join-Path $runtimeDirectory 'System.Runtime.WindowsRuntime.dll'),
        (Join-Path $runtimeDirectory 'Facades\System.Runtime.dll'),
        (Join-Path $winMetadataDirectory 'Windows.Foundation.winmd'),
        (Join-Path $winMetadataDirectory 'Windows.Devices.winmd')
    )

    foreach ($reference in $references) {
        if (-not (Test-Path -LiteralPath $reference)) {
            throw "Required Windows Runtime metadata is unavailable: $reference"
        }
    }

    $source = @'
using System;
using System.Collections.Generic;
using System.Threading;
using Windows.Devices.Bluetooth.Advertisement;

namespace XXPhoneInputGuardBleV1
{
    public sealed class BleSample
    {
        public DateTime SeenUtc { get; set; }
        public ulong Address { get; set; }
        public short Rssi { get; set; }
        public string LocalName { get; set; }
    }

    public sealed class BleWatcherBridge : IDisposable
    {
        private readonly object sync = new object();
        private readonly Queue<BleSample> samples = new Queue<BleSample>();
        private readonly Guid targetUuid;
        private readonly BluetoothLEAdvertisementWatcher watcher;
        private int totalPackets;
        private int matchingPackets;
        private bool disposed;

        public BleWatcherBridge(Guid targetUuid)
        {
            this.targetUuid = targetUuid;
            watcher = new BluetoothLEAdvertisementWatcher();
            watcher.ScanningMode = BluetoothLEScanningMode.Active;
            watcher.Received += OnReceived;
        }

        public string Status
        {
            get { return watcher.Status.ToString(); }
        }

        public int TotalPackets
        {
            get { return Volatile.Read(ref totalPackets); }
        }

        public int MatchingPackets
        {
            get { return Volatile.Read(ref matchingPackets); }
        }

        public void Start()
        {
            if (disposed)
                throw new ObjectDisposedException("BleWatcherBridge");
            watcher.Start();
        }

        private void OnReceived(
            BluetoothLEAdvertisementWatcher sender,
            BluetoothLEAdvertisementReceivedEventArgs args)
        {
            Interlocked.Increment(ref totalPackets);

            bool isTarget = false;
            foreach (Guid uuid in args.Advertisement.ServiceUuids)
            {
                if (uuid == targetUuid)
                {
                    isTarget = true;
                    break;
                }
            }

            if (!isTarget)
                return;

            Interlocked.Increment(ref matchingPackets);
            BleSample sample = new BleSample {
                SeenUtc = DateTime.UtcNow,
                Address = args.BluetoothAddress,
                Rssi = args.RawSignalStrengthInDBm,
                LocalName = args.Advertisement.LocalName ?? String.Empty
            };

            lock (sync)
            {
                samples.Enqueue(sample);
                while (samples.Count > 1024)
                    samples.Dequeue();
            }
        }

        public BleSample[] Drain()
        {
            lock (sync)
            {
                BleSample[] result = samples.ToArray();
                samples.Clear();
                return result;
            }
        }

        public void Dispose()
        {
            if (disposed)
                return;

            disposed = true;
            watcher.Received -= OnReceived;
            try
            {
                watcher.Stop();
            }
            catch
            {
            }
        }
    }
}
'@

    # Windows PowerShell 5.1's Add-Type tries to load .winmd files as ordinary
    # CLR assemblies before compiling and fails with 0x80131047.  The .NET
    # Framework C# compiler understands WinRT metadata directly, so invoke it
    # first and then load the resulting ordinary managed assembly.
    $compilerCandidates = @(
        (Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
    )
    $compiler = $compilerCandidates |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
    if ($null -eq $compiler) {
        throw 'The built-in .NET Framework C# compiler (csc.exe) is unavailable.'
    }

    $buildDirectory = Join-Path ([IO.Path]::GetTempPath()) (
        'XXPhoneInputGuardBle-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $buildDirectory -Force | Out-Null
    $sourcePath = Join-Path $buildDirectory 'BleWatcherBridge.cs'
    $assemblyPath = Join-Path $buildDirectory 'BleWatcherBridge.dll'
    Set-Content -LiteralPath $sourcePath -Value $source -Encoding UTF8

    $compilerArguments = @(
        '/nologo',
        '/target:library',
        '/optimize+',
        (('/out:{0}' -f $assemblyPath))
    )
    foreach ($reference in $references) {
        $compilerArguments += ('/reference:{0}' -f $reference)
    }
    $compilerArguments += $sourcePath
    $compilerOutput = @(& $compiler @compilerArguments 2>&1 |
        ForEach-Object { $_.ToString() })
    if (($LASTEXITCODE -ne 0) -or -not (Test-Path -LiteralPath $assemblyPath)) {
        throw ('C# compiler failed:' + [Environment]::NewLine +
            ($compilerOutput -join [Environment]::NewLine))
    }

    Add-Type -LiteralPath $assemblyPath
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This scanner must be run on Microsoft Windows 10 or Windows 11.'
}

$targetUuid = [Guid]::Empty
if (-not [Guid]::TryParse($ServiceUuid, [ref]$targetUuid)) {
    throw "Invalid 128-bit service UUID: $ServiceUuid"
}

Initialize-BleWatcherBridge

if ($CompileOnly) {
    Write-Host 'BLE bridge compiled successfully.' -ForegroundColor Green
    exit 0
}

$bridge = [XXPhoneInputGuardBleV1.BleWatcherBridge]::new($targetUuid)

try {
    $bridge.Start()
    Start-Sleep -Milliseconds 750
    Write-Host ('Watcher status: ' + $bridge.Status)
    Write-Host ('Scanning for {0} for {1} seconds...' -f $targetUuid, $DurationSeconds)

    $finish = [DateTime]::UtcNow.AddSeconds($DurationSeconds)
    while ([DateTime]::UtcNow -lt $finish) {
        foreach ($sample in @($bridge.Drain())) {
            $address = '{0:X12}' -f [UInt64]$sample.Address
            Write-Host ('{0:HH:mm:ss.fff}  RSSI={1,4} dBm  Address={2}' -f `
                $sample.SeenUtc.ToLocalTime(), [int]$sample.Rssi, $address) -ForegroundColor Green
        }
        Start-Sleep -Milliseconds 100
    }
}
finally {
    $bridge.Dispose()
}

Write-Host
Write-Host ('Total BLE packets received: {0}' -f $bridge.TotalPackets)
Write-Host ('Matching KIDZ packets:     {0}' -f $bridge.MatchingPackets)
