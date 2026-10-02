#requires -Version 5.1
<#
.SYNOPSIS
  XX Phone Input Guard for Microsoft Windows 10/11.

.DESCRIPTION
  Freezes physical keyboard and mouse input when the configured Bluetooth phone
  is no longer connected, while leaving the desktop and display visible.

  Requested policy:
    - Phone: XX:XX:XX:XX:XX:XX (XX)
    - Wi-Fi exclusions: XX1, XX2, XX3
    - Emergency release: three complete AC unplug/replug cycles in 60 seconds
    - Each AC state must remain stable for one second
    - Banner while frozen: XX
    - Continues operating while the computer is on battery power

  Run Windows PowerShell as Administrator, then use one of:
    .\phone-input-guard-windows.ps1 Install
    .\phone-input-guard-windows.ps1 Check
    .\phone-input-guard-windows.ps1 Arm
    .\phone-input-guard-windows.ps1 Disarm
    .\phone-input-guard-windows.ps1 Uninstall

  "Run" is the internal scheduled-task mode.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Install', 'Run', 'Check', 'Arm', 'Disarm', 'Uninstall')]
    [string]$Command = 'Install',

    [string]$PhoneAddress = 'XX:XX:XX:XX:XX:XX',

    [string]$PhoneName = 'XX',

    [string[]]$ExcludedWifiNames = @('XX1', 'XX2', 'XX3'),

    [string]$BannerText = 'XX'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:GuardVersion = '1.0.0'
$Script:TaskName = 'XX Phone Input Guard'
$Script:InstallRoot = Join-Path $env:ProgramData 'XX\PhoneInputGuard'
$Script:InstalledScript = Join-Path $Script:InstallRoot 'phone-input-guard-windows.ps1'
$Script:ConfigPath = Join-Path $Script:InstallRoot 'config.json'
$Script:LogPath = Join-Path $Script:InstallRoot 'guard.log'

function Test-Windows {
    return ($env:OS -eq 'Windows_NT')
}

function Assert-Windows {
    if (-not (Test-Windows)) {
        throw 'This script must be run on Microsoft Windows 10 or Windows 11.'
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'Open Windows PowerShell with "Run as administrator", then run this command again.'
    }
}

function New-DefaultConfig {
    return [pscustomobject][ordered]@{
        version                       = $Script:GuardVersion
        phone_address                 = $PhoneAddress
        phone_name                    = $PhoneName
        excluded_wifi_names           = @($ExcludedWifiNames)
        banner_text                   = $BannerText
        poll_milliseconds              = 250
        rescue_power_cycles            = 3
        rescue_window_seconds          = 60
        power_state_stable_milliseconds = 1000
    }
}

function Get-GuardConfig {
    if (Test-Path -LiteralPath $Script:ConfigPath) {
        return (Get-Content -LiteralPath $Script:ConfigPath -Raw | ConvertFrom-Json)
    }
    return (New-DefaultConfig)
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
        $line = '{0:u} {1}' -f [DateTime]::UtcNow, $Message
        Add-Content -LiteralPath $Script:LogPath -Value $line -Encoding UTF8
    }
    catch {
        # Logging must never decide whether input is blocked or released.
    }
}

function Initialize-NativeMethods {
    if ('XXPhoneInputGuard.NativeMethods' -as [type]) {
        return
    }

    $source = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace XXPhoneInputGuard
{
    public sealed class BluetoothSnapshot
    {
        public string Address { get; set; }
        public string Name { get; set; }
        public bool Connected { get; set; }
        public bool Remembered { get; set; }
        public bool Authenticated { get; set; }
    }

    public static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEMTIME
        {
            public ushort Year;
            public ushort Month;
            public ushort DayOfWeek;
            public ushort Day;
            public ushort Hour;
            public ushort Minute;
            public ushort Second;
            public ushort Milliseconds;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct BLUETOOTH_DEVICE_INFO
        {
            public uint Size;
            public ulong Address;
            public uint ClassOfDevice;
            [MarshalAs(UnmanagedType.Bool)] public bool Connected;
            [MarshalAs(UnmanagedType.Bool)] public bool Remembered;
            [MarshalAs(UnmanagedType.Bool)] public bool Authenticated;
            public SYSTEMTIME LastSeen;
            public SYSTEMTIME LastUsed;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 248)]
            public string Name;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BLUETOOTH_DEVICE_SEARCH_PARAMS
        {
            public uint Size;
            [MarshalAs(UnmanagedType.Bool)] public bool ReturnAuthenticated;
            [MarshalAs(UnmanagedType.Bool)] public bool ReturnRemembered;
            [MarshalAs(UnmanagedType.Bool)] public bool ReturnUnknown;
            [MarshalAs(UnmanagedType.Bool)] public bool ReturnConnected;
            [MarshalAs(UnmanagedType.Bool)] public bool IssueInquiry;
            public byte TimeoutMultiplier;
            public IntPtr Radio;
        }

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

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool BlockInputNative([MarshalAs(UnmanagedType.Bool)] bool block);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SetThreadExecutionState(uint executionState);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

        [DllImport("bthprops.cpl", SetLastError = true)]
        private static extern IntPtr BluetoothFindFirstDevice(
            ref BLUETOOTH_DEVICE_SEARCH_PARAMS searchParams,
            ref BLUETOOTH_DEVICE_INFO deviceInfo);

        [DllImport("bthprops.cpl", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool BluetoothFindNextDevice(
            IntPtr findHandle,
            ref BLUETOOTH_DEVICE_INFO deviceInfo);

        [DllImport("bthprops.cpl", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool BluetoothFindDeviceClose(IntPtr findHandle);

        private const uint ES_CONTINUOUS = 0x80000000;
        private const uint ES_SYSTEM_REQUIRED = 0x00000001;
        private const uint ES_DISPLAY_REQUIRED = 0x00000002;

        public static bool BlockInput(bool block)
        {
            return BlockInputNative(block);
        }

        public static bool SetKeepAwake(bool enabled)
        {
            uint flags = ES_CONTINUOUS;
            if (enabled)
                flags |= ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED;
            return SetThreadExecutionState(flags) != 0;
        }

        // 1 = AC connected, 0 = battery, -1 = unavailable/unknown.
        public static int GetACLineStatus()
        {
            SYSTEM_POWER_STATUS status;
            if (!GetSystemPowerStatus(out status) || status.ACLineStatus == 255)
                return -1;
            return status.ACLineStatus == 1 ? 1 : 0;
        }

        private static string FormatAddress(ulong address)
        {
            string hex = (address & 0x0000FFFFFFFFFFFFUL).ToString("X12");
            return String.Format("{0}:{1}:{2}:{3}:{4}:{5}",
                hex.Substring(0, 2), hex.Substring(2, 2), hex.Substring(4, 2),
                hex.Substring(6, 2), hex.Substring(8, 2), hex.Substring(10, 2));
        }

        public static BluetoothSnapshot[] EnumerateBluetoothDevices()
        {
            List<BluetoothSnapshot> devices = new List<BluetoothSnapshot>();
            BLUETOOTH_DEVICE_SEARCH_PARAMS search = new BLUETOOTH_DEVICE_SEARCH_PARAMS();
            search.Size = (uint)Marshal.SizeOf(typeof(BLUETOOTH_DEVICE_SEARCH_PARAMS));
            search.ReturnAuthenticated = true;
            search.ReturnRemembered = true;
            search.ReturnUnknown = true;
            search.ReturnConnected = true;
            search.IssueInquiry = false;
            search.TimeoutMultiplier = 0;
            search.Radio = IntPtr.Zero;

            BLUETOOTH_DEVICE_INFO info = new BLUETOOTH_DEVICE_INFO();
            info.Size = (uint)Marshal.SizeOf(typeof(BLUETOOTH_DEVICE_INFO));

            IntPtr findHandle = BluetoothFindFirstDevice(ref search, ref info);
            if (findHandle == IntPtr.Zero)
                return devices.ToArray();

            try
            {
                do
                {
                    devices.Add(new BluetoothSnapshot {
                        Address = FormatAddress(info.Address),
                        Name = info.Name ?? String.Empty,
                        Connected = info.Connected,
                        Remembered = info.Remembered,
                        Authenticated = info.Authenticated
                    });
                    info = new BLUETOOTH_DEVICE_INFO();
                    info.Size = (uint)Marshal.SizeOf(typeof(BLUETOOTH_DEVICE_INFO));
                }
                while (BluetoothFindNextDevice(findHandle, ref info));
            }
            finally
            {
                BluetoothFindDeviceClose(findHandle);
            }

            return devices.ToArray();
        }
    }
}
'@

    Add-Type -TypeDefinition $source -Language CSharp
}

function Normalize-BluetoothAddress {
    param([AllowNull()][string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) {
        return ''
    }
    return (($Address -replace '[^0-9A-Fa-f]', '').ToUpperInvariant())
}

function Get-BluetoothDevices {
    Initialize-NativeMethods
    return @([XXPhoneInputGuard.NativeMethods]::EnumerateBluetoothDevices())
}

function Get-PhoneState {
    param([Parameter(Mandatory = $true)]$Config)

    $wantedAddress = Normalize-BluetoothAddress ([string]$Config.phone_address)
    $wantedName = [string]$Config.phone_name
    $devices = @(Get-BluetoothDevices)
    $match = $null

    if ($wantedAddress.Length -gt 0) {
        $match = $devices |
            Where-Object { (Normalize-BluetoothAddress $_.Address) -eq $wantedAddress } |
            Sort-Object -Property Connected -Descending |
            Select-Object -First 1
    }

    if (($null -eq $match) -and -not [string]::IsNullOrWhiteSpace($wantedName)) {
        $match = $devices |
            Where-Object { [string]::Equals($_.Name, $wantedName, [StringComparison]::OrdinalIgnoreCase) } |
            Sort-Object -Property Connected -Descending |
            Select-Object -First 1
    }

    if ($null -eq $match) {
        return [pscustomobject]@{
            Found     = $false
            Connected = $false
            Name      = $wantedName
            Address   = [string]$Config.phone_address
            Devices   = $devices
        }
    }

    return [pscustomobject]@{
        Found     = $true
        Connected = [bool]$match.Connected
        Name      = [string]$match.Name
        Address   = [string]$match.Address
        Devices   = $devices
    }
}

function Get-ActiveNetworkNames {
    try {
        $profiles = @(Get-NetConnectionProfile -ErrorAction Stop)
        return @($profiles |
            Where-Object {
                ($_.IPv4Connectivity -ne 'Disconnected') -or
                ($_.IPv6Connectivity -ne 'Disconnected')
            } |
            ForEach-Object { [string]$_.Name } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique)
    }
    catch {
        Write-GuardLog ('Wi-Fi/profile check failed: ' + $_.Exception.Message)
        return @()
    }
}

function Get-ExcludedNetworkMatch {
    param([Parameter(Mandatory = $true)]$Config)

    $activeNames = @(Get-ActiveNetworkNames)
    foreach ($activeName in $activeNames) {
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
    $form.ClientSize = New-Object System.Drawing.Size(226, 30)
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
        'Segoe UI Semibold',
        10,
        [System.Drawing.FontStyle]::Bold,
        [System.Drawing.GraphicsUnit]::Point)
    $form.Controls.Add($label)
    return $form
}

function Update-PowerRescueState {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)]$Config,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    $rawAC = [XXPhoneInputGuard.NativeMethods]::GetACLineStatus()
    if ($rawAC -lt 0) {
        return $false
    }

    if ($rawAC -ne $State.CandidateAC) {
        $State.CandidateAC = $rawAC
        $State.CandidateSince = $NowMilliseconds
        return $false
    }

    $stableFor = $NowMilliseconds - [long]$State.CandidateSince
    if (($rawAC -eq $State.StableAC) -or
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

function Reset-PowerRescueState {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    $ac = [XXPhoneInputGuard.NativeMethods]::GetACLineStatus()
    $State.StableAC = $ac
    $State.CandidateAC = $ac
    $State.CandidateSince = $NowMilliseconds
    $State.SawDisconnect = $false
    $State.ReconnectTimes = @()
}

function Invoke-GuardLoop {
    Assert-Windows
    Initialize-NativeMethods

    $createdNew = $false
    $mutex = New-Object Threading.Mutex($true, 'Local\XX-Phone-Input-Guard', [ref]$createdNew)
    if (-not $createdNew) {
        $mutex.Dispose()
        return
    }

    $config = Get-GuardConfig
    $banner = New-GuardBanner -Text ([string]$config.banner_text)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $initialAC = [XXPhoneInputGuard.NativeMethods]::GetACLineStatus()
    $powerState = @{
        StableAC       = $initialAC
        CandidateAC    = $initialAC
        CandidateSince = [long]0
        SawDisconnect  = $false
        ReconnectTimes = @()
    }

    $inputBlocked = $false
    $rescueActive = $false
    $lastBaseRisk = $null
    $lastBlockAssert = [long]-10000

    Write-GuardLog ('Guard {0} started for {1} ({2}).' -f
        $Script:GuardVersion, [string]$config.phone_name, [string]$config.phone_address)

    try {
        while ($true) {
            $now = [long]$clock.ElapsedMilliseconds
            $phone = Get-PhoneState -Config $config
            $excludedNetwork = Get-ExcludedNetworkMatch -Config $config
            $baseRisk = (-not [bool]$phone.Connected) -and ($null -eq $excludedNetwork)

            if (-not $baseRisk) {
                if ($rescueActive) {
                    Write-GuardLog 'Emergency release reset because the phone or an excluded network returned.'
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
                # Reassert periodically because Windows deliberately releases BlockInput
                # when Ctrl+Alt+Delete is pressed.
                if ((-not $inputBlocked) -or (($now - $lastBlockAssert) -ge 1000)) {
                    $blockResult = [XXPhoneInputGuard.NativeMethods]::BlockInput($true)
                    if ($blockResult) {
                        $inputBlocked = $true
                    }
                    $lastBlockAssert = $now
                }

                if (-not $banner.Visible) {
                    $banner.Show()
                    $banner.BringToFront()
                    $banner.Refresh()
                }
                [void][XXPhoneInputGuard.NativeMethods]::SetKeepAwake($true)
            }
            else {
                if ($banner.Visible) {
                    $banner.Hide()
                }
                [void][XXPhoneInputGuard.NativeMethods]::BlockInput($false)
                $inputBlocked = $false
                [void][XXPhoneInputGuard.NativeMethods]::SetKeepAwake($false)
            }

            if (($null -eq $lastBaseRisk) -or ($baseRisk -ne $lastBaseRisk)) {
                if ($baseRisk) {
                    Write-GuardLog 'Phone absent and no excluded Wi-Fi: input frozen.'
                }
                else {
                    $reason = if ([bool]$phone.Connected) {
                        'phone connected'
                    }
                    else {
                        'excluded network ' + [string]$excludedNetwork
                    }
                    Write-GuardLog ('Input released: ' + $reason + '.')
                }
                $lastBaseRisk = $baseRisk
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
        [void][XXPhoneInputGuard.NativeMethods]::BlockInput($false)
        [void][XXPhoneInputGuard.NativeMethods]::SetKeepAwake($false)
        if ($null -ne $banner) {
            $banner.Close()
            $banner.Dispose()
        }
        $mutex.ReleaseMutex()
        $mutex.Dispose()
        Write-GuardLog 'Guard stopped; input released.'
    }
}

function Show-GuardCheck {
    Assert-Windows
    Initialize-NativeMethods
    $config = Get-GuardConfig
    $phone = Get-PhoneState -Config $config
    $activeNetworks = @(Get-ActiveNetworkNames)
    $excludedNetwork = Get-ExcludedNetworkMatch -Config $config
    $acStatus = [XXPhoneInputGuard.NativeMethods]::GetACLineStatus()

    $taskState = 'Not installed'
    try {
        $taskState = [string](Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop).State
    }
    catch {
    }

    $acText = switch ($acStatus) {
        1 { 'Connected' }
        0 { 'Battery' }
        default { 'Unknown' }
    }

    [pscustomobject][ordered]@{
        Version                  = $Script:GuardVersion
        ScheduledTask           = $taskState
        ConfiguredPhone          = ('{0} ({1})' -f [string]$config.phone_name, [string]$config.phone_address)
        PhoneFound               = [bool]$phone.Found
        PhoneConnected           = [bool]$phone.Connected
        DetectedPhone            = if ([bool]$phone.Found) { '{0} ({1})' -f $phone.Name, $phone.Address } else { 'None' }
        ActiveNetworkProfiles    = if ($activeNetworks.Count) { $activeNetworks -join ', ' } else { 'None' }
        ExclusionActive          = if ($null -ne $excludedNetwork) { $excludedNetwork } else { 'No' }
        Power                    = $acText
        WouldFreezeInputNow      = ((-not [bool]$phone.Connected) -and ($null -eq $excludedNetwork))
        EmergencyRelease         = '3 unplug/replug cycles; each state stable 1 second; all within 60 seconds'
    } | Format-List | Out-Host

    if (-not [bool]$phone.Found) {
        Write-Host 'Known classic Bluetooth devices visible to Windows:' -ForegroundColor Yellow
        if (@($phone.Devices).Count -eq 0) {
            Write-Host '  None. Pair the phone in Windows Settings > Bluetooth & devices.'
        }
        else {
            @($phone.Devices) |
                Select-Object Address, Name, Connected, Remembered, Authenticated |
                Format-Table -AutoSize |
                Out-Host
        }
    }
}

function Install-Guard {
    Assert-Windows
    Assert-Administrator
    Initialize-NativeMethods

    New-Item -ItemType Directory -Path $Script:InstallRoot -Force | Out-Null
    $sourcePath = [IO.Path]::GetFullPath($PSCommandPath)
    $destinationPath = [IO.Path]::GetFullPath($Script:InstalledScript)
    if (-not [string]::Equals($sourcePath, $destinationPath, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
    }
    Unblock-File -LiteralPath $destinationPath -ErrorAction SilentlyContinue

    $config = New-DefaultConfig
    $config | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Script:ConfigPath -Encoding UTF8

    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" Run' -f $destinationPath
    $action = New-ScheduledTaskAction -Execute $windowsPowerShell -Argument $arguments
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser
    $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew

    Register-ScheduledTask `
        -TaskName $Script:TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description 'Freezes keyboard and mouse when the configured phone is absent.' `
        -Force | Out-Null

    $phone = Get-PhoneState -Config $config
    $excludedNetwork = Get-ExcludedNetworkMatch -Config $config
    if ([bool]$phone.Connected -or ($null -ne $excludedNetwork)) {
        Enable-ScheduledTask -TaskName $Script:TaskName | Out-Null
        Start-ScheduledTask -TaskName $Script:TaskName
        Write-Host 'Installed, armed, and running.' -ForegroundColor Green
    }
    else {
        Disable-ScheduledTask -TaskName $Script:TaskName | Out-Null
        Write-Warning 'Installed but left DISARMED because the phone is not connected and no exclusion Wi-Fi is active.'
        Write-Host 'Connect the phone, run Check, then run Arm.'
    }

    Write-Host ('Installed script: ' + $destinationPath)
    Write-Host ('Scheduled task:  ' + $Script:TaskName)
    Write-Host 'Use Check before testing by switching off Bluetooth on the phone.'
}

function Arm-Guard {
    Assert-Windows
    Assert-Administrator
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop
    Write-Host 'Arming now. If neither the phone nor an exclusion Wi-Fi is detected, input will freeze immediately.' -ForegroundColor Yellow
    Enable-ScheduledTask -InputObject $task | Out-Null
    Start-ScheduledTask -TaskName $Script:TaskName
    Write-Host 'Phone Input Guard is armed and running.' -ForegroundColor Green
}

function Disarm-Guard {
    Assert-Windows
    Assert-Administrator
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction Stop
    Disable-ScheduledTask -InputObject $task | Out-Null
    Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Initialize-NativeMethods
    [void][XXPhoneInputGuard.NativeMethods]::BlockInput($false)
    [void][XXPhoneInputGuard.NativeMethods]::SetKeepAwake($false)
    Write-Host 'Phone Input Guard is stopped and disabled; input is released.' -ForegroundColor Green
}

function Uninstall-Guard {
    Assert-Windows
    Assert-Administrator
    try {
        Disable-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue | Out-Null
        Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    finally {
        Initialize-NativeMethods
        [void][XXPhoneInputGuard.NativeMethods]::BlockInput($false)
        [void][XXPhoneInputGuard.NativeMethods]::SetKeepAwake($false)
    }

    if (Test-Path -LiteralPath $Script:InstallRoot) {
        $programDataRoot = [IO.Path]::GetFullPath($env:ProgramData).TrimEnd('\') + '\'
        $validatedRoot = [IO.Path]::GetFullPath($Script:InstallRoot).TrimEnd('\') + '\'
        if (-not $validatedRoot.StartsWith($programDataRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to remove an installation path outside ProgramData.'
        }
        Remove-Item -LiteralPath $Script:InstallRoot -Recurse -Force
    }
    Write-Host 'Phone Input Guard was removed; input is released.' -ForegroundColor Green
}

try {
    switch ($Command) {
        'Install'   { Install-Guard }
        'Run'       { Invoke-GuardLoop }
        'Check'     { Show-GuardCheck }
        'Arm'       { Arm-Guard }
        'Disarm'    { Disarm-Guard }
        'Uninstall' { Uninstall-Guard }
    }
}
catch {
    Write-Error $_
    exit 1
}
