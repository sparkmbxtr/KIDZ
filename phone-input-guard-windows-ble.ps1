#requires -Version 5.1
<#
.SYNOPSIS
  Per-user BLE phone-presence input guard for Microsoft Windows 10/11.

.DESCRIPTION
  Receives a private 128-bit BLE service UUID advertised by a phone.  It keeps
  the desktop visible but blocks keyboard and mouse input when the signal is
  weak or advertisements stop arriving.  Installation and startup use only
  the current user's profile; administrator access is not required.

  Public-repository placeholders intentionally use XX.  Supply personal values
  to Install instead of editing them into this file.

  Safety controls:
    - Install leaves the guard disarmed.
    - Observe never blocks input.
    - SelfTest blocks input for only 250 ms and immediately releases it.
    - Arm refuses to start unless the phone is near or an exclusion Wi-Fi is on.
    - Three complete charger unplug/replug cycles within 60 seconds release it.
    - Each charger state must remain stable for one second.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Install', 'Run', 'Observe', 'Check', 'SelfTest', 'Arm', 'Disarm', 'Uninstall', 'CompileOnly')]
    [string]$Command = 'Check',

    [string]$ServiceUuid = '00000000-0000-4000-8000-000000000000',

    [ValidateRange(-127, -1)]
    [int]$LockRssi = -82,

    [ValidateRange(-127, -1)]
    [int]$UnlockRssi = -78,

    [ValidateRange(3, 120)]
    [int]$AbsenceSeconds = 8,

    [string[]]$ExcludedWifiNames = @('XX1', 'XX2', 'XX3'),

    [string]$BannerText = 'XX',

    [ValidateRange(5, 3600)]
    [int]$ObserveSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:GuardVersion = '2.0.1'
$Script:InstallRoot = Join-Path $env:LOCALAPPDATA 'KIDZ'
$Script:InstalledScript = Join-Path $Script:InstallRoot 'phone-input-guard-windows-ble.ps1'
$Script:ConfigPath = Join-Path $Script:InstallRoot 'windows-ble-config.json'
$Script:LogPath = Join-Path $Script:InstallRoot 'windows-ble-guard.log'
$Script:StatePath = Join-Path $Script:InstallRoot 'windows-ble-state.json'
$Script:PidPath = Join-Path $Script:InstallRoot 'windows-ble-guard.pid'
$Script:ArmedPath = Join-Path $Script:InstallRoot 'windows-ble-armed.flag'
$Script:StopPath = Join-Path $Script:InstallRoot 'windows-ble-stop.flag'
$Script:RunKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Script:RunValueName = 'KIDZ Phone Input Guard'

function Assert-Windows {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This script must be run on Microsoft Windows 10 or Windows 11.'
    }
}

function Write-GuardLog {
    param([Parameter(Mandatory = $true)][string]$Message)

    try {
        if (-not (Test-Path -LiteralPath $Script:InstallRoot)) {
            return
        }
        if ((Test-Path -LiteralPath $Script:LogPath) -and
            ((Get-Item -LiteralPath $Script:LogPath).Length -gt 1048576)) {
            Move-Item -LiteralPath $Script:LogPath -Destination ($Script:LogPath + '.old') -Force
        }
        Add-Content -LiteralPath $Script:LogPath -Encoding UTF8 -Value (
            '{0:u} {1}' -f [DateTime]::UtcNow, $Message)
    }
    catch {
        # Logging must never determine whether input is blocked or released.
    }
}

function Initialize-NativeMethods {
    if ('XXPhoneInputGuardV2.NativeMethods' -as [type]) {
        return
    }

    $source = @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

namespace XXPhoneInputGuardV2
{
    public static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_POWER_STATUS
        {
            public byte ACLineStatus;
            public byte BatteryFlag;
            public byte BatteryLifePercent;
            public byte SystemStatusFlag;
            public uint BatteryLifeTime;
            public uint BatteryFullLifeTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int X;
            public int Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr Hwnd;
            public uint Message;
            public UIntPtr WParam;
            public IntPtr LParam;
            public uint Time;
            public POINT Point;
            public uint Private;
        }

        private delegate IntPtr LowLevelHookProc(int code, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(
            int hookId, LowLevelHookProc callback, IntPtr module, uint threadId);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hook);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(
            IntPtr hook, int code, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int GetMessage(
            out MSG message, IntPtr window, uint minimum, uint maximum);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TranslateMessage(ref MSG message);

        [DllImport("user32.dll")]
        private static extern IntPtr DispatchMessage(ref MSG message);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PostThreadMessage(
            uint threadId, uint message, UIntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PeekMessage(
            out MSG message, IntPtr window, uint minimum, uint maximum, uint removeMessage);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string moduleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SetThreadExecutionState(uint executionState);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

        private const uint ES_CONTINUOUS = 0x80000000;
        private const uint ES_SYSTEM_REQUIRED = 0x00000001;
        private const uint ES_DISPLAY_REQUIRED = 0x00000002;
        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const uint WM_QUIT = 0x0012;
        private const uint PM_NOREMOVE = 0x0000;

        private static readonly object HookSync = new object();
        private static readonly ManualResetEvent HookReady = new ManualResetEvent(false);
        private static readonly LowLevelHookProc KeyboardProcedure = KeyboardHook;
        private static readonly LowLevelHookProc MouseProcedure = MouseHook;
        private static Thread hookThread;
        private static IntPtr keyboardHook = IntPtr.Zero;
        private static IntPtr mouseHook = IntPtr.Zero;
        private static uint hookThreadId;
        private static volatile bool suppressInput;
        private static int hookError;

        private static IntPtr KeyboardHook(int code, IntPtr wParam, IntPtr lParam)
        {
            if (code >= 0 && suppressInput)
                return new IntPtr(1);
            return CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
        }

        private static IntPtr MouseHook(int code, IntPtr wParam, IntPtr lParam)
        {
            if (code >= 0 && suppressInput)
                return new IntPtr(1);
            return CallNextHookEx(IntPtr.Zero, code, wParam, lParam);
        }

        private static IntPtr InstallHook(
            int hookId, LowLevelHookProc callback, IntPtr module)
        {
            IntPtr hook = SetWindowsHookEx(hookId, callback, module, 0);
            if (hook == IntPtr.Zero && module != IntPtr.Zero)
                hook = SetWindowsHookEx(hookId, callback, IntPtr.Zero, 0);
            return hook;
        }

        private static void HookThreadMain()
        {
            try
            {
                hookThreadId = GetCurrentThreadId();
                MSG initialMessage;
                PeekMessage(out initialMessage, IntPtr.Zero, 0, 0, PM_NOREMOVE);

                IntPtr module = GetModuleHandle(null);
                keyboardHook = InstallHook(WH_KEYBOARD_LL, KeyboardProcedure, module);
                if (keyboardHook == IntPtr.Zero)
                {
                    hookError = Marshal.GetLastWin32Error();
                    return;
                }

                mouseHook = InstallHook(WH_MOUSE_LL, MouseProcedure, module);
                if (mouseHook == IntPtr.Zero)
                {
                    hookError = Marshal.GetLastWin32Error();
                    return;
                }

                HookReady.Set();
                MSG message;
                int result;
                while ((result = GetMessage(out message, IntPtr.Zero, 0, 0)) > 0)
                {
                    TranslateMessage(ref message);
                    DispatchMessage(ref message);
                }
                if (result < 0)
                    hookError = Marshal.GetLastWin32Error();
            }
            finally
            {
                suppressInput = false;
                if (mouseHook != IntPtr.Zero)
                    UnhookWindowsHookEx(mouseHook);
                if (keyboardHook != IntPtr.Zero)
                    UnhookWindowsHookEx(keyboardHook);

                lock (HookSync)
                {
                    mouseHook = IntPtr.Zero;
                    keyboardHook = IntPtr.Zero;
                    hookThreadId = 0;
                    hookThread = null;
                }
                HookReady.Set();
            }
        }

        private static bool StartHooks()
        {
            Thread threadToStart;
            lock (HookSync)
            {
                if (hookThread != null && hookThread.IsAlive &&
                    keyboardHook != IntPtr.Zero && mouseHook != IntPtr.Zero)
                {
                    suppressInput = true;
                    return true;
                }

                hookError = 0;
                suppressInput = true;
                HookReady.Reset();
                hookThread = new Thread(HookThreadMain);
                hookThread.IsBackground = true;
                hookThread.Name = "XX input-blocking hooks";
                threadToStart = hookThread;
            }

            threadToStart.Start();
            if (!HookReady.WaitOne(3000))
            {
                suppressInput = false;
                hookError = 1460;
                return false;
            }

            lock (HookSync)
            {
                bool installed = keyboardHook != IntPtr.Zero && mouseHook != IntPtr.Zero;
                if (!installed)
                    suppressInput = false;
                return installed;
            }
        }

        private static bool StopHooks()
        {
            Thread threadToStop;
            uint threadId;
            suppressInput = false;
            lock (HookSync)
            {
                threadToStop = hookThread;
                threadId = hookThreadId;
            }

            if (threadId != 0)
                PostThreadMessage(threadId, WM_QUIT, UIntPtr.Zero, IntPtr.Zero);
            if (threadToStop != null && threadToStop.IsAlive &&
                threadToStop != Thread.CurrentThread)
                threadToStop.Join(2000);
            return true;
        }

        public static bool BlockInput(bool block)
        {
            return block ? StartHooks() : StopHooks();
        }

        public static int GetLastError()
        {
            return hookError;
        }

        public static bool SetKeepAwake(bool enabled)
        {
            uint flags = ES_CONTINUOUS;
            if (enabled)
                flags |= ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED;
            return SetThreadExecutionState(flags) != 0;
        }

        // 1 = AC connected, 0 = battery, -1 = unavailable or unknown.
        public static int GetACLineStatus()
        {
            SYSTEM_POWER_STATUS status;
            if (!GetSystemPowerStatus(out status) || status.ACLineStatus == 255)
                return -1;
            return status.ACLineStatus == 1 ? 1 : 0;
        }
    }
}
'@

    Add-Type -TypeDefinition $source -Language CSharp
}

function Initialize-BleWatcherBridge {
    if ('XXPhoneInputGuardBleV2.BleWatcherBridge' -as [type]) {
        return
    }

    $runtimeDirectory = [Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $winMetadataDirectory = Join-Path $env:windir 'System32\WinMetadata'
    try {
        $systemRuntimeReference = [Reflection.Assembly]::Load(
            'System.Runtime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a').Location
        $winRtInteropFacadeReference = [Reflection.Assembly]::Load(
            'System.Runtime.InteropServices.WindowsRuntime, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a').Location
    }
    catch {
        throw ('Required .NET runtime facades are unavailable: ' + $_.Exception.Message)
    }

    $references = @(
        (Join-Path $runtimeDirectory 'System.Runtime.WindowsRuntime.dll'),
        $systemRuntimeReference,
        $winRtInteropFacadeReference,
        (Join-Path $winMetadataDirectory 'Windows.Foundation.winmd'),
        (Join-Path $winMetadataDirectory 'Windows.Devices.winmd')
    )
    foreach ($reference in $references) {
        if ([string]::IsNullOrWhiteSpace([string]$reference) -or
            -not (Test-Path -LiteralPath $reference)) {
            throw "Required Windows Runtime metadata is unavailable: $reference"
        }
    }

    $source = @'
using System;
using System.Collections.Generic;
using System.Threading;
using Windows.Devices.Bluetooth.Advertisement;

namespace XXPhoneInputGuardBleV2
{
    public sealed class BleSample
    {
        public DateTime SeenUtc { get; set; }
        public ulong Address { get; set; }
        public short Rssi { get; set; }
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
                Rssi = args.RawSignalStrengthInDBm
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
        'XXPhoneInputGuardBleV2-' + [Guid]::NewGuid().ToString('N'))
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

function ConvertTo-TargetGuid {
    param([Parameter(Mandatory = $true)][string]$Value)

    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($Value, [ref]$guid) -or $guid -eq [Guid]::Empty) {
        throw 'Supply the non-zero 128-bit BLE ServiceUuid advertised by the phone.'
    }
    return $guid
}

function Assert-Thresholds {
    param(
        [Parameter(Mandatory = $true)][int]$WeakThreshold,
        [Parameter(Mandatory = $true)][int]$NearThreshold
    )

    if ($WeakThreshold -ge $NearThreshold) {
        throw 'LockRssi must be lower (more negative) than UnlockRssi.'
    }
}

function New-GuardConfig {
    Assert-Thresholds -WeakThreshold $LockRssi -NearThreshold $UnlockRssi
    $targetGuid = ConvertTo-TargetGuid -Value $ServiceUuid

    return [pscustomobject][ordered]@{
        version                         = $Script:GuardVersion
        service_uuid                    = $targetGuid.ToString()
        lock_rssi_dbm                   = $LockRssi
        unlock_rssi_dbm                 = $UnlockRssi
        absence_seconds                 = $AbsenceSeconds
        weak_samples_required           = 2
        weak_window_samples             = 3
        startup_scan_seconds            = 12
        excluded_wifi_names             = @($ExcludedWifiNames)
        banner_text                     = $BannerText
        poll_milliseconds               = 200
        wifi_poll_milliseconds          = 2000
        rescue_power_cycles             = 3
        rescue_window_seconds           = 60
        power_state_stable_milliseconds = 1000
    }
}

function Get-GuardConfig {
    if (-not (Test-Path -LiteralPath $Script:ConfigPath)) {
        throw 'The BLE guard is not installed. Run Install with the service UUID first.'
    }
    $config = Get-Content -LiteralPath $Script:ConfigPath -Raw | ConvertFrom-Json
    [void](ConvertTo-TargetGuid -Value ([string]$config.service_uuid))
    Assert-Thresholds `
        -WeakThreshold ([int]$config.lock_rssi_dbm) `
        -NearThreshold ([int]$config.unlock_rssi_dbm)
    return $config
}

function Get-ActiveWifiNames {
    $names = @()
    try {
        $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
        foreach ($line in @(& $netsh wlan show interfaces 2>$null)) {
            if ([string]$line -match '^\s*SSID\s*:\s*(.+?)\s*$') {
                $candidate = [string]$Matches[1]
                if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                    $names += $candidate
                }
            }
        }
    }
    catch {
        Write-GuardLog ('Wi-Fi SSID query failed: ' + $_.Exception.Message)
    }

    try {
        $names += @(Get-NetConnectionProfile -ErrorAction Stop |
            Where-Object {
                ($_.IPv4Connectivity -ne 'Disconnected') -or
                ($_.IPv6Connectivity -ne 'Disconnected')
            } |
            ForEach-Object { [string]$_.Name })
    }
    catch {
    }

    return @($names |
        Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
        Select-Object -Unique)
}

function Get-ExcludedWifiMatch {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][string[]]$ActiveNames
    )

    foreach ($activeName in @($ActiveNames)) {
        foreach ($excludedName in @($Config.excluded_wifi_names)) {
            if ([string]::Equals(
                    [string]$activeName,
                    [string]$excludedName,
                    [StringComparison]::OrdinalIgnoreCase)) {
                return [string]$activeName
            }
        }
    }
    return $null
}

function New-PresenceState {
    return @{
        Near       = $null
        LastSeenMs = [long]-1
        LastRssi   = $null
        RecentRssi = New-Object 'System.Collections.Generic.List[int]'
        Reason     = 'learning'
    }
}

function Add-PresenceSample {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][int]$Rssi,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    $State.LastSeenMs = $NowMilliseconds
    $State.LastRssi = $Rssi
    [void]$State.RecentRssi.Add($Rssi)
    while ($State.RecentRssi.Count -gt [int]$Config.weak_window_samples) {
        $State.RecentRssi.RemoveAt(0)
    }

    if ($Rssi -ge [int]$Config.unlock_rssi_dbm) {
        $State.Near = $true
        $State.Reason = 'strong advertisement'
        return
    }

    $weakCount = @($State.RecentRssi |
        Where-Object { [int]$_ -le [int]$Config.lock_rssi_dbm }).Count
    if ($weakCount -ge [int]$Config.weak_samples_required) {
        $State.Near = $false
        $State.Reason = 'weak advertisements'
    }
}

function Update-PresenceTimeout {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    $startupMilliseconds = [long]$Config.startup_scan_seconds * 1000
    $absenceMilliseconds = [long]$Config.absence_seconds * 1000
    if ([long]$State.LastSeenMs -lt 0) {
        if ($NowMilliseconds -ge $startupMilliseconds) {
            $State.Near = $false
            $State.Reason = 'no advertisement during startup scan'
        }
        return
    }

    if (($NowMilliseconds - [long]$State.LastSeenMs) -ge $absenceMilliseconds) {
        $State.Near = $false
        $State.Reason = 'advertisements missing'
    }
}

function Get-PresenceText {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    if ($null -eq $State.Near) {
        return 'LEARNING'
    }
    if ([bool]$State.Near) {
        return 'NEAR'
    }
    if ([long]$State.LastSeenMs -lt 0) {
        return 'MISSING'
    }
    return 'FAR'
}

function New-GuardBanner {
    param([Parameter(Mandatory = $true)][string]$Text)

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
    $form.ShowInTaskbar = $false
    $form.TopMost = $true
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
    $form.BackColor = [System.Drawing.Color]::FromArgb(22, 22, 22)
    $form.ClientSize = New-Object System.Drawing.Size(236, 30)
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::None

    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $form.Location = New-Object System.Drawing.Point($screen.Left, $screen.Top)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.Dock = [System.Windows.Forms.DockStyle]::Fill
    $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $label.ForeColor = [System.Drawing.Color]::White
    $label.BackColor = $form.BackColor
    $label.Font = New-Object System.Drawing.Font(
        'Segoe UI Semibold', 10, [System.Drawing.FontStyle]::Bold,
        [System.Drawing.GraphicsUnit]::Point)
    $form.Controls.Add($label)
    return $form
}

function Reset-PowerRescueState {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    $ac = [XXPhoneInputGuardV2.NativeMethods]::GetACLineStatus()
    $State.StableAC = $ac
    $State.CandidateAC = $ac
    $State.CandidateSince = $NowMilliseconds
    $State.SawDisconnect = $false
    $State.ReconnectTimes = @()
}

function Update-PowerRescueState {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    $rawAC = [XXPhoneInputGuardV2.NativeMethods]::GetACLineStatus()
    if ($rawAC -lt 0) {
        return $false
    }
    if ($rawAC -ne [int]$State.CandidateAC) {
        $State.CandidateAC = $rawAC
        $State.CandidateSince = $NowMilliseconds
        return $false
    }

    $stableFor = $NowMilliseconds - [long]$State.CandidateSince
    if (($rawAC -eq [int]$State.StableAC) -or
        ($stableFor -lt [long]$Config.power_state_stable_milliseconds)) {
        return $false
    }

    $oldAC = [int]$State.StableAC
    $State.StableAC = $rawAC
    if ($oldAC -lt 0) {
        return $false
    }
    if (($oldAC -eq 1) -and ($rawAC -eq 0)) {
        $State.SawDisconnect = $true
        Write-GuardLog 'Emergency release: stable charger disconnect observed.'
        return $false
    }
    if (($oldAC -eq 0) -and ($rawAC -eq 1) -and [bool]$State.SawDisconnect) {
        $State.SawDisconnect = $false
        $windowMilliseconds = [long]$Config.rescue_window_seconds * 1000
        $recent = @($State.ReconnectTimes | Where-Object {
                ($NowMilliseconds - [long]$_) -le $windowMilliseconds
            })
        $recent += $NowMilliseconds
        $State.ReconnectTimes = @($recent)
        Write-GuardLog ('Emergency release: charger cycle {0}/{1} observed.' -f
            $State.ReconnectTimes.Count, [int]$Config.rescue_power_cycles)
        return ($State.ReconnectTimes.Count -ge [int]$Config.rescue_power_cycles)
    }
    return $false
}

function Write-GuardState {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][hashtable]$Presence,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds,
        [AllowNull()][string]$ExcludedWifi,
        [Parameter(Mandatory = $true)][bool]$InputBlocked,
        [Parameter(Mandatory = $true)][bool]$RescueActive,
        [Parameter(Mandatory = $true)][string]$WatcherStatus
    )

    try {
        $age = if ([long]$Presence.LastSeenMs -lt 0) {
            $null
        }
        else {
            [Math]::Round(($NowMilliseconds - [long]$Presence.LastSeenMs) / 1000.0, 1)
        }
        $state = [pscustomobject][ordered]@{
            updated_utc          = [DateTime]::UtcNow.ToString('o')
            watcher_status       = $WatcherStatus
            phone_state          = Get-PresenceText -State $Presence -NowMilliseconds $NowMilliseconds
            last_rssi_dbm        = $Presence.LastRssi
            last_seen_age_seconds = $age
            reason               = [string]$Presence.Reason
            excluded_wifi        = $ExcludedWifi
            input_blocked        = $InputBlocked
            emergency_release    = $RescueActive
            lock_rssi_dbm        = [int]$Config.lock_rssi_dbm
            unlock_rssi_dbm      = [int]$Config.unlock_rssi_dbm
            absence_seconds      = [int]$Config.absence_seconds
        }
        $temporaryPath = $Script:StatePath + '.tmp'
        $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
        Move-Item -LiteralPath $temporaryPath -Destination $Script:StatePath -Force
    }
    catch {
        Write-GuardLog ('State write failed: ' + $_.Exception.Message)
    }
}

function Test-GuardProcess {
    if (-not (Test-Path -LiteralPath $Script:PidPath)) {
        return $false
    }
    try {
        $guardPid = [int](Get-Content -LiteralPath $Script:PidPath -Raw)
        return ($null -ne (Get-Process -Id $guardPid -ErrorAction Stop))
    }
    catch {
        return $false
    }
}

function Start-GuardProcess {
    if (Test-GuardProcess) {
        return
    }
    if (-not (Test-Path -LiteralPath $Script:InstalledScript)) {
        throw 'Installed guard script is missing. Run Install again.'
    }
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Sta -File "{0}" Run' -f
        $Script:InstalledScript
    Start-Process -FilePath $windowsPowerShell -ArgumentList $arguments -WindowStyle Hidden | Out-Null
}

function Test-BleNearNow {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [ValidateRange(3, 30)][int]$Seconds = 10
    )

    Initialize-BleWatcherBridge
    $guid = ConvertTo-TargetGuid -Value ([string]$Config.service_uuid)
    $bridge = [XXPhoneInputGuardBleV2.BleWatcherBridge]::new($guid)
    $bestRssi = -127
    try {
        $bridge.Start()
        $finish = [DateTime]::UtcNow.AddSeconds($Seconds)
        while ([DateTime]::UtcNow -lt $finish) {
            foreach ($sample in @($bridge.Drain())) {
                $rssi = [int]$sample.Rssi
                if ($rssi -gt $bestRssi) {
                    $bestRssi = $rssi
                }
                if ($rssi -ge [int]$Config.unlock_rssi_dbm) {
                    return [pscustomobject]@{ Near = $true; BestRssi = $bestRssi }
                }
            }
            Start-Sleep -Milliseconds 100
        }
    }
    finally {
        $bridge.Dispose()
    }
    return [pscustomobject]@{ Near = $false; BestRssi = $bestRssi }
}

function Invoke-Observe {
    Assert-Windows
    Initialize-BleWatcherBridge
    $config = if (Test-Path -LiteralPath $Script:ConfigPath) {
        Get-GuardConfig
    }
    else {
        New-GuardConfig
    }
    $guid = ConvertTo-TargetGuid -Value ([string]$config.service_uuid)
    $bridge = [XXPhoneInputGuardBleV2.BleWatcherBridge]::new($guid)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $presence = New-PresenceState
    $nextLine = [long]0
    try {
        $bridge.Start()
        Start-Sleep -Milliseconds 600
        Write-Host ('Watcher status: {0}' -f $bridge.Status)
        Write-Host ('Observe is read-only: input cannot be frozen for the next {0} seconds.' -f $ObserveSeconds)
        $finish = [long]$ObserveSeconds * 1000
        while ([long]$clock.ElapsedMilliseconds -lt $finish) {
            $now = [long]$clock.ElapsedMilliseconds
            foreach ($sample in @($bridge.Drain())) {
                Add-PresenceSample -State $presence -Config $config `
                    -Rssi ([int]$sample.Rssi) -NowMilliseconds $now
            }
            Update-PresenceTimeout -State $presence -Config $config -NowMilliseconds $now

            if ($now -ge $nextLine) {
                $ageText = if ([long]$presence.LastSeenMs -lt 0) {
                    'never'
                }
                else {
                    '{0:N1}s' -f (($now - [long]$presence.LastSeenMs) / 1000.0)
                }
                $rssiText = if ($null -eq $presence.LastRssi) { '--' } else { [string]$presence.LastRssi }
                Write-Host ('{0:HH:mm:ss}  State={1,-8} RSSI={2,4} dBm  Age={3,-6}  {4}' -f
                    [DateTime]::Now,
                    (Get-PresenceText -State $presence -NowMilliseconds $now),
                    $rssiText,
                    $ageText,
                    [string]$presence.Reason)
                $nextLine = $now + 1000
            }
            Start-Sleep -Milliseconds 100
        }
    }
    finally {
        $bridge.Dispose()
    }
    Write-Host
    Write-Host ('Total BLE packets:   {0}' -f $bridge.TotalPackets)
    Write-Host ('Matching XX packets: {0}' -f $bridge.MatchingPackets)
}

function Invoke-GuardLoop {
    Assert-Windows
    Initialize-NativeMethods
    Initialize-BleWatcherBridge

    if (-not (Test-Path -LiteralPath $Script:ArmedPath)) {
        return
    }

    $createdNew = $false
    $mutex = New-Object Threading.Mutex($true, 'Local\XX-Phone-Input-Guard-BLE-V2', [ref]$createdNew)
    if (-not $createdNew) {
        $mutex.Dispose()
        return
    }

    $config = Get-GuardConfig
    $guid = ConvertTo-TargetGuid -Value ([string]$config.service_uuid)
    $bridge = [XXPhoneInputGuardBleV2.BleWatcherBridge]::new($guid)
    $banner = New-GuardBanner -Text ([string]$config.banner_text)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $presence = New-PresenceState
    $initialAC = [XXPhoneInputGuardV2.NativeMethods]::GetACLineStatus()
    $powerState = @{
        StableAC       = $initialAC
        CandidateAC    = $initialAC
        CandidateSince = [long]0
        SawDisconnect  = $false
        ReconnectTimes = @()
    }
    $activeWifi = @()
    $excludedWifi = $null
    $nextWifiPoll = [long]0
    $nextStateWrite = [long]0
    $lastBlockAssert = [long]-10000
    $inputBlocked = $false
    $rescueActive = $false
    $lastRisk = $null
    $PID | Set-Content -LiteralPath $Script:PidPath -Encoding ASCII
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue

    Write-GuardLog ('BLE guard {0} started. UUID={1}; lock={2}; unlock={3}; absence={4}s.' -f
        $Script:GuardVersion, $config.service_uuid, $config.lock_rssi_dbm,
        $config.unlock_rssi_dbm, $config.absence_seconds)

    try {
        $bridge.Start()
        while ((Test-Path -LiteralPath $Script:ArmedPath) -and
            -not (Test-Path -LiteralPath $Script:StopPath)) {
            $now = [long]$clock.ElapsedMilliseconds
            foreach ($sample in @($bridge.Drain())) {
                Add-PresenceSample -State $presence -Config $config `
                    -Rssi ([int]$sample.Rssi) -NowMilliseconds $now
            }
            Update-PresenceTimeout -State $presence -Config $config -NowMilliseconds $now

            if ($now -ge $nextWifiPoll) {
                $activeWifi = @(Get-ActiveWifiNames)
                $excludedWifi = Get-ExcludedWifiMatch -Config $config -ActiveNames $activeWifi
                $nextWifiPoll = $now + [long]$config.wifi_poll_milliseconds
            }

            $learning = ($null -eq $presence.Near)
            $baseRisk = (-not $learning) -and (-not [bool]$presence.Near) -and
                ($null -eq $excludedWifi)

            if (-not $baseRisk) {
                if ($rescueActive) {
                    Write-GuardLog 'Emergency release reset because the phone or an exclusion Wi-Fi returned.'
                }
                $rescueActive = $false
                Reset-PowerRescueState -State $powerState -NowMilliseconds $now
            }
            elseif (-not $rescueActive) {
                if (Update-PowerRescueState -State $powerState -Config $config -NowMilliseconds $now) {
                    $rescueActive = $true
                    Write-GuardLog 'Emergency release activated after three charger cycles.'
                }
            }

            $shouldBlock = $baseRisk -and (-not $rescueActive)
            if ($shouldBlock) {
                if ((-not $inputBlocked) -or (($now - $lastBlockAssert) -ge 1000)) {
                    $blockedNow = [XXPhoneInputGuardV2.NativeMethods]::BlockInput($true)
                    if ($blockedNow) {
                        $inputBlocked = $true
                    }
                    elseif (-not $inputBlocked) {
                        Write-GuardLog ('Input hooks failed; Win32 error {0}.' -f
                            [XXPhoneInputGuardV2.NativeMethods]::GetLastError())
                    }
                    $lastBlockAssert = $now
                }
                if ($inputBlocked -and -not $banner.Visible) {
                    $banner.Show()
                    $banner.BringToFront()
                    $banner.Refresh()
                }
                [void][XXPhoneInputGuardV2.NativeMethods]::SetKeepAwake($true)
            }
            else {
                if ($banner.Visible) {
                    $banner.Hide()
                }
                if ($inputBlocked) {
                    [void][XXPhoneInputGuardV2.NativeMethods]::BlockInput($false)
                    $inputBlocked = $false
                }
                [void][XXPhoneInputGuardV2.NativeMethods]::SetKeepAwake($false)
            }

            if (($null -eq $lastRisk) -or ([bool]$baseRisk -ne [bool]$lastRisk)) {
                if ($baseRisk) {
                    Write-GuardLog ('Phone classified FAR: {0}; input block requested.' -f $presence.Reason)
                }
                else {
                    $releaseReason = if ($null -ne $excludedWifi) {
                        'exclusion Wi-Fi ' + [string]$excludedWifi
                    }
                    elseif ($learning) {
                        'startup scan'
                    }
                    else {
                        'phone near'
                    }
                    Write-GuardLog ('Input released: ' + $releaseReason + '.')
                }
                $lastRisk = $baseRisk
            }

            if ($now -ge $nextStateWrite) {
                Write-GuardState -Config $config -Presence $presence -NowMilliseconds $now `
                    -ExcludedWifi $excludedWifi -InputBlocked $inputBlocked `
                    -RescueActive $rescueActive -WatcherStatus $bridge.Status
                $nextStateWrite = $now + 1000
            }

            [System.Windows.Forms.Application]::DoEvents()
            [Threading.Thread]::Sleep([int]$config.poll_milliseconds)
        }
    }
    catch {
        Write-GuardLog ('Guard stopped by error: ' + $_.Exception.ToString())
        throw
    }
    finally {
        [void][XXPhoneInputGuardV2.NativeMethods]::BlockInput($false)
        [void][XXPhoneInputGuardV2.NativeMethods]::SetKeepAwake($false)
        if ($null -ne $banner) {
            $banner.Close()
            $banner.Dispose()
        }
        if ($null -ne $bridge) {
            $bridge.Dispose()
        }
        try {
            if ((Test-Path -LiteralPath $Script:PidPath) -and
                ([int](Get-Content -LiteralPath $Script:PidPath -Raw) -eq $PID)) {
                Remove-Item -LiteralPath $Script:PidPath -Force
            }
        }
        catch {
        }
        Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
        $mutex.ReleaseMutex()
        $mutex.Dispose()
        Write-GuardLog 'Guard stopped; input released.'
    }
}

function Install-Guard {
    Assert-Windows
    Initialize-NativeMethods
    Initialize-BleWatcherBridge
    $config = New-GuardConfig

    New-Item -ItemType Directory -Path $Script:InstallRoot -Force | Out-Null
    $sourcePath = [IO.Path]::GetFullPath($PSCommandPath)
    $destinationPath = [IO.Path]::GetFullPath($Script:InstalledScript)
    if (-not [string]::Equals($sourcePath, $destinationPath, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
    }
    Unblock-File -LiteralPath $destinationPath -ErrorAction SilentlyContinue
    $config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Script:ConfigPath -Encoding UTF8

    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $runCommand = '"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Sta -File "{1}" Run' -f
        $windowsPowerShell, $Script:InstalledScript
    New-Item -Path $Script:RunKeyPath -Force | Out-Null
    New-ItemProperty -Path $Script:RunKeyPath -Name $Script:RunValueName `
        -Value $runCommand -PropertyType String -Force | Out-Null

    Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue

    Write-Host 'Installed for the current user without administrator access.' -ForegroundColor Green
    Write-Host ('Installed script: ' + $Script:InstalledScript)
    Write-Host 'The startup entry is installed, but the guard is deliberately DISARMED.' -ForegroundColor Yellow
    Write-Host 'Run Observe, then SelfTest, and finally Arm.'
}

function Invoke-SelfTest {
    Assert-Windows
    Initialize-NativeMethods
    $blocked = $false
    try {
        $blocked = [XXPhoneInputGuardV2.NativeMethods]::BlockInput($true)
        if (-not $blocked) {
            throw ('Input hooks could not be installed; Win32 error {0}.' -f
                [XXPhoneInputGuardV2.NativeMethods]::GetLastError())
        }
        Start-Sleep -Milliseconds 250
    }
    finally {
        [void][XXPhoneInputGuardV2.NativeMethods]::BlockInput($false)
    }
    Write-Host 'Non-admin input-hook self-test passed; input was released.' -ForegroundColor Green
}

function Arm-Guard {
    Assert-Windows
    Initialize-NativeMethods
    $config = Get-GuardConfig
    $activeWifi = @(Get-ActiveWifiNames)
    $excludedWifi = Get-ExcludedWifiMatch -Config $config -ActiveNames $activeWifi

    if ($null -eq $excludedWifi) {
        Write-Host 'Checking the BLE phone before arming (up to 10 seconds)...'
        $preflight = Test-BleNearNow -Config $config -Seconds 10
        if (-not [bool]$preflight.Near) {
            throw ('Refusing to arm: no nearby advertisement reached {0} dBm. Best RSSI={1} dBm.' -f
                [int]$config.unlock_rssi_dbm, [int]$preflight.BestRssi)
        }
        Write-Host ('Phone detected at {0} dBm.' -f [int]$preflight.BestRssi) -ForegroundColor Green
    }
    else {
        Write-Host ('Exclusion Wi-Fi active: ' + [string]$excludedWifi)
    }

    New-Item -ItemType File -Path $Script:ArmedPath -Force | Out-Null
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
    Start-GuardProcess
    Start-Sleep -Milliseconds 800
    if (-not (Test-GuardProcess)) {
        throw 'The guard process did not remain running. Check windows-ble-guard.log.'
    }
    Write-Host 'BLE Phone Input Guard is armed and will start automatically at sign-in.' -ForegroundColor Green
}

function Disarm-Guard {
    Assert-Windows
    Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Script:InstallRoot)) {
        Write-Host 'The guard is not installed.'
        return
    }
    New-Item -ItemType File -Path $Script:StopPath -Force | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(6)
    while ((Test-GuardProcess) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 200
    }
    if (Test-GuardProcess) {
        Write-Warning 'The process has not exited yet. Use the charger rescue if input is blocked.'
    }
    else {
        Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
        Write-Host 'BLE Phone Input Guard is disarmed; input is released.' -ForegroundColor Green
    }
}

function Show-GuardCheck {
    Assert-Windows
    $installed = Test-Path -LiteralPath $Script:ConfigPath
    $startupValue = $null
    try {
        $startupValue = (Get-ItemProperty -Path $Script:RunKeyPath `
            -Name $Script:RunValueName -ErrorAction Stop).($Script:RunValueName)
    }
    catch {
    }

    $config = if ($installed) { Get-GuardConfig } else { $null }
    $activeWifi = @(Get-ActiveWifiNames)
    $excludedWifi = if ($installed) {
        Get-ExcludedWifiMatch -Config $config -ActiveNames $activeWifi
    }
    else {
        $null
    }

    [pscustomobject][ordered]@{
        Version             = $Script:GuardVersion
        Installed           = $installed
        Armed               = Test-Path -LiteralPath $Script:ArmedPath
        ProcessRunning      = Test-GuardProcess
        StartupEntry        = if ($null -ne $startupValue) { 'Installed' } else { 'Missing' }
        ServiceUuid         = if ($installed) { [string]$config.service_uuid } else { 'Not configured' }
        LockRssi            = if ($installed) { [int]$config.lock_rssi_dbm } else { $null }
        UnlockRssi          = if ($installed) { [int]$config.unlock_rssi_dbm } else { $null }
        MissingTimeout      = if ($installed) { ([string]$config.absence_seconds + ' seconds') } else { $null }
        ActiveNetworks      = if ($activeWifi.Count) { $activeWifi -join ', ' } else { 'None' }
        ExclusionActive     = if ($null -ne $excludedWifi) { $excludedWifi } else { 'No' }
        EmergencyRelease    = '3 unplug/replug cycles; each state stable 1 second; all within 60 seconds'
    } | Format-List | Out-Host

    if (Test-Path -LiteralPath $Script:StatePath) {
        Write-Host 'Last guard state:'
        Get-Content -LiteralPath $Script:StatePath -Raw |
            ConvertFrom-Json |
            Format-List |
            Out-Host
    }
}

function Uninstall-Guard {
    Assert-Windows
    Disarm-Guard
    if (Test-GuardProcess) {
        throw 'Refusing to uninstall while the guard process is still running.'
    }

    Remove-ItemProperty -Path $Script:RunKeyPath -Name $Script:RunValueName `
        -Force -ErrorAction SilentlyContinue

    if (Test-Path -LiteralPath $Script:InstallRoot) {
        $localRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\') + '\'
        $validatedRoot = [IO.Path]::GetFullPath($Script:InstallRoot).TrimEnd('\') + '\'
        if (-not $validatedRoot.StartsWith($localRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an installation path outside LocalAppData.'
        }
        Remove-Item -LiteralPath $Script:InstallRoot -Recurse -Force
    }
    Write-Host 'BLE Phone Input Guard was removed; input is released.' -ForegroundColor Green
}

try {
    switch ($Command) {
        'Install'     { Install-Guard }
        'Run'         { Invoke-GuardLoop }
        'Observe'     { Invoke-Observe }
        'Check'       { Show-GuardCheck }
        'SelfTest'    { Invoke-SelfTest }
        'Arm'         { Arm-Guard }
        'Disarm'      { Disarm-Guard }
        'Uninstall'   { Uninstall-Guard }
        'CompileOnly' {
            Assert-Windows
            Initialize-NativeMethods
            Initialize-BleWatcherBridge
            Write-Host 'BLE guard bridges compiled successfully.' -ForegroundColor Green
        }
    }
}
catch {
    Write-Error $_
    exit 1
}
