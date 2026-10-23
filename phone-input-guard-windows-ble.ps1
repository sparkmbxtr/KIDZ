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
    [ValidateSet('Install', 'Run', 'Startup', 'RepairStartup', 'Observe', 'Check', 'SelfTest', 'Arm', 'Disarm', 'Uninstall', 'CompileOnly')]
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
    [int]$ObserveSeconds = 60,

    [switch]$StartupFallback,

    [switch]$FailClosedStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:GuardVersion = '2.3.0'
$Script:NativeMethodsType = $null
$Script:BleWatcherBridgeType = $null
$Script:InstallRoot = Join-Path $env:LOCALAPPDATA 'KIDZ'
$Script:InstalledScript = Join-Path $Script:InstallRoot 'phone-input-guard-windows-ble.ps1'
$Script:InputHookHelper = Join-Path $Script:InstallRoot 'windows-input-hook-helper.exe'
$Script:StartupLauncherFileVersion = $Script:GuardVersion + '.0'
$Script:StartupLauncher = Join-Path $Script:InstallRoot (
    'phone-input-guard-startup-{0}.exe' -f $Script:GuardVersion)
$Script:InputHookHelperSha256 = '0adc71ca80b19003db434b2bff0bf3dc63bb686d180095e67f6478c77d8c2d66'
$Script:ConfigPath = Join-Path $Script:InstallRoot 'windows-ble-config.json'
$Script:LogPath = Join-Path $Script:InstallRoot 'windows-ble-guard.log'
$Script:StatePath = Join-Path $Script:InstallRoot 'windows-ble-state.json'
$Script:PidPath = Join-Path $Script:InstallRoot 'windows-ble-guard.pid'
$Script:IdentityPath = Join-Path $Script:InstallRoot 'windows-ble-identity.json'
$Script:ReadyPath = Join-Path $Script:InstallRoot 'windows-ble-ready.json'
$Script:StartupStatePath = Join-Path $Script:InstallRoot 'windows-ble-startup.json'
$Script:ArmedPath = Join-Path $Script:InstallRoot 'windows-ble-armed.flag'
$Script:StopPath = Join-Path $Script:InstallRoot 'windows-ble-stop.flag'
$Script:RunKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Script:RunValueName = 'KIDZ Phone Input Guard'
$Script:RunApprovalKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run'
$Script:StartupTaskName = 'KIDZ Phone Input Guard Logon'
$Script:StartupSupervisorMutexName = 'Local\XX-Phone-Input-Guard-Startup-Supervisor-V1'
$Script:GuardMutexName = 'Local\XX-Phone-Input-Guard-BLE-V2'

function Assert-Windows {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This script must be run on Microsoft Windows 10 or Windows 11.'
    }
}

function Assert-InputHookHelper {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Native input-hook helper is missing: $Path"
    }
    $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $Script:InputHookHelperSha256) {
        throw ('Native input-hook helper failed its SHA-256 integrity check. Expected {0}; got {1}.' -f
            $Script:InputHookHelperSha256, $actualHash)
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

function Test-WindowsGuiExecutable {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite)
        if ($stream.Length -lt 96) {
            return $false
        }
        $reader = New-Object IO.BinaryReader($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) {
            return $false
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if (($peOffset -lt 64) -or (($peOffset + 94) -gt $stream.Length)) {
            return $false
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            return $false
        }
        $stream.Position = $peOffset + 24
        $optionalHeaderMagic = $reader.ReadUInt16()
        if (($optionalHeaderMagic -ne 0x010B) -and
            ($optionalHeaderMagic -ne 0x020B)) {
            return $false
        }
        # IMAGE_OPTIONAL_HEADER.Subsystem is 68 bytes into the optional
        # header for both PE32 and PE32+.  Value 2 is Windows GUI.
        $stream.Position = $peOffset + 24 + 68
        return ($reader.ReadUInt16() -eq 2)
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
        elseif ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Test-StartupLauncher {
    if (-not (Test-WindowsGuiExecutable -Path $Script:StartupLauncher)) {
        return $false
    }
    try {
        $fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo(
            $Script:StartupLauncher).FileVersion
        return [string]::Equals(
            [string]$fileVersion,
            $Script:StartupLauncherFileVersion,
            [StringComparison]::Ordinal)
    }
    catch {
        return $false
    }
}

function Get-RunningStartupLaunchers {
    $installPrefix = [IO.Path]::GetFullPath($Script:InstallRoot).TrimEnd('\') + '\'
    return @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $processPath = [string]$_.Path
                $fileName = [IO.Path]::GetFileName($processPath)
                if ($processPath.StartsWith(
                        $installPrefix,
                        [StringComparison]::OrdinalIgnoreCase) -and
                    $fileName.StartsWith(
                        'phone-input-guard-startup-',
                        [StringComparison]::OrdinalIgnoreCase) -and
                    $fileName.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) {
                    $_
                }
            }
            catch {
            }
        })
}

function Test-StartupSupervisorMutexAvailable {
    $createdNew = $false
    $mutex = New-Object Threading.Mutex(
        $false,
        $Script:StartupSupervisorMutexName,
        [ref]$createdNew)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
        }
        return $acquired
    }
    finally {
        if ($acquired) {
            try {
                $mutex.ReleaseMutex()
            }
            catch {
            }
        }
        $mutex.Dispose()
    }
}

function Test-GuardMutexAvailable {
    $createdNew = $false
    $mutex = New-Object Threading.Mutex(
        $false,
        $Script:GuardMutexName,
        [ref]$createdNew)
    $acquired = $false
    try {
        try {
            $acquired = $mutex.WaitOne(0)
        }
        catch [Threading.AbandonedMutexException] {
            $acquired = $true
        }
        return $acquired
    }
    finally {
        if ($acquired) {
            try { $mutex.ReleaseMutex() } catch { }
        }
        $mutex.Dispose()
    }
}

function Wait-StartupLaunchersExit {
    param([ValidateRange(1, 60)][int]$Seconds = 10)

    $waitClock = [Diagnostics.Stopwatch]::StartNew()
    while ($waitClock.ElapsedMilliseconds -lt ([long]$Seconds * 1000)) {
        if ((@(Get-RunningStartupLaunchers).Count -eq 0) -and
            (Test-StartupSupervisorMutexAvailable)) {
            return $true
        }
        Start-Sleep -Milliseconds 200
    }
    return ((@(Get-RunningStartupLaunchers).Count -eq 0) -and
        (Test-StartupSupervisorMutexAvailable))
}

function Write-StartupLauncher {
    # A GUI-subsystem executable has no console of its own.  CREATE_NO_WINDOW
    # also prevents its Windows PowerShell child from acquiring a console, so
    # a default-terminal redirector cannot turn a hidden startup into a flash.
    # The versioned filename avoids replacing an image that an armed, long-lived
    # startup supervisor still has open during a software update.
    if (Test-StartupLauncher) {
        return
    }

    $buildToken = [Guid]::NewGuid().ToString('N')
    $launcherSource = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

[assembly: AssemblyVersion("$($Script:StartupLauncherFileVersion)")]
[assembly: AssemblyFileVersion("$($Script:StartupLauncherFileVersion)")]

namespace XXPhoneInputGuardStartup_$buildToken
{
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            try
            {
                if (args == null || args.Length != 1)
                {
                    return 64;
                }

                bool fallback;
                if (string.Equals(args[0], "task", StringComparison.OrdinalIgnoreCase))
                {
                    fallback = false;
                }
                else if (string.Equals(args[0], "fallback", StringComparison.OrdinalIgnoreCase))
                {
                    fallback = true;
                }
                else
                {
                    return 64;
                }

                string launcherPath = Assembly.GetExecutingAssembly().Location;
                string installRoot = Path.GetDirectoryName(launcherPath);
                string guardPath = Path.Combine(
                    installRoot,
                    "phone-input-guard-windows-ble.ps1");

                string systemDirectory = Environment.GetFolderPath(
                    Environment.SpecialFolder.System);
                if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
                {
                    systemDirectory = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                        "Sysnative");
                }
                string powerShellPath = Path.Combine(
                    systemDirectory,
                    "WindowsPowerShell",
                    "v1.0",
                    "powershell.exe");
                if (!File.Exists(guardPath) || !File.Exists(powerShellPath))
                {
                    return 2;
                }

                string arguments =
                    "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
                    "-WindowStyle Hidden -Sta -File " + Quote(guardPath) + " Startup";
                if (fallback)
                {
                    arguments += " -StartupFallback";
                }

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = powerShellPath;
                startInfo.Arguments = arguments;
                startInfo.WorkingDirectory = installRoot;
                startInfo.UseShellExecute = false;
                startInfo.CreateNoWindow = true;
                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.ErrorDialog = false;

                using (Process process = Process.Start(startInfo))
                {
                    if (process == null)
                    {
                        return 2;
                    }
                    process.WaitForExit();
                    return process.ExitCode;
                }
            }
            catch
            {
                return 2;
            }
        }

        private static string Quote(string value)
        {
            return "\"" + value + "\"";
        }
    }
}
"@

    $temporaryPath = Join-Path $Script:InstallRoot (
        'phone-input-guard-startup-{0}.tmp.exe' -f $buildToken)
    try {
        Add-Type -TypeDefinition $launcherSource -Language CSharp `
            -OutputAssembly $temporaryPath -OutputType WindowsApplication `
            -ErrorAction Stop
        if (-not (Test-WindowsGuiExecutable -Path $temporaryPath)) {
            throw 'The compiled startup launcher is not a Windows GUI executable.'
        }
        $compiledVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo(
            $temporaryPath).FileVersion
        if (-not [string]::Equals(
                [string]$compiledVersion,
                $Script:StartupLauncherFileVersion,
                [StringComparison]::Ordinal)) {
            throw ('The compiled startup launcher has unexpected version {0}.' -f
                [string]$compiledVersion)
        }
        Move-Item -LiteralPath $temporaryPath `
            -Destination $Script:StartupLauncher -Force
        Unblock-File -LiteralPath $Script:StartupLauncher -ErrorAction SilentlyContinue
    }
    catch {
        throw (('Could not create the consoleless native startup launcher. ' +
            'Disarm the guard, wait for it to stop, then run RepairStartup. {0}') -f
            $_.Exception.Message)
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

function Get-StartupArguments {
    param([switch]$RegistryFallback)

    return $(if ($RegistryFallback) { 'fallback' } else { 'task' })
}

function Get-StartupRunCommand {
    # HKCU Run is interpreted as a complete CreateProcess command line.
    return ('"{0}" {1}' -f
        $Script:StartupLauncher,
        (Get-StartupArguments -RegistryFallback))
}

function Write-StartupState {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][int]$Attempt,
        [AllowEmptyString()][string]$Message = ''
    )

    try {
        if (-not (Test-Path -LiteralPath $Script:InstallRoot)) {
            return
        }
        $state = [pscustomobject][ordered]@{
            updated_utc = [DateTime]::UtcNow.ToString('o')
            pid         = $PID
            version     = $Script:GuardVersion
            status      = $Status
            attempt     = $Attempt
            message     = $Message
        }
        $temporaryPath = $Script:StartupStatePath + '.tmp'
        $state | ConvertTo-Json -Depth 2 |
            Set-Content -LiteralPath $temporaryPath -Encoding UTF8
        Move-Item -LiteralPath $temporaryPath `
            -Destination $Script:StartupStatePath -Force
    }
    catch {
        Write-GuardLog ('Startup status write failed: ' + $_.Exception.Message)
    }
}

function Get-RunStartupApproval {
    if (-not (Test-Path -LiteralPath $Script:RunApprovalKeyPath)) {
        return 'Enabled (no disabled override)'
    }
    try {
        $item = Get-ItemProperty -Path $Script:RunApprovalKeyPath -ErrorAction Stop
        $property = $item.PSObject.Properties[$Script:RunValueName]
        if ($null -eq $property) {
            return 'Enabled (no disabled override)'
        }
        $value = $property.Value
        if (($value -is [byte[]]) -and ($value.Count -gt 0)) {
            switch ([int]$value[0]) {
                2 { return 'Enabled' }
                3 { return 'Disabled by Windows startup settings' }
                default { return ('Unknown ({0})' -f [int]$value[0]) }
            }
        }
        return 'Unknown'
    }
    catch {
        return 'Unknown'
    }
}

function Test-StartupTaskUserMatchesCurrentIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$UserId
    )

    if ([string]::IsNullOrWhiteSpace($UserId)) {
        return $false
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    foreach ($expectedUserId in @(
            [string]$identity.Name,
            [string]$identity.User.Value
        )) {
        if ((-not [string]::IsNullOrWhiteSpace($expectedUserId)) -and
            [string]::Equals(
                $UserId,
                $expectedUserId,
                [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    # Task Scheduler can also return an unqualified or otherwise normalized
    # account name. Resolve that account back to its SID so validation remains
    # strict without depending on the COM API's chosen string representation.
    try {
        $account = New-Object -TypeName Security.Principal.NTAccount `
            -ArgumentList $UserId
        $resolvedSid = $account.Translate(
            [Security.Principal.SecurityIdentifier])
        return [string]::Equals(
            [string]$resolvedSid.Value,
            [string]$identity.User.Value,
            [StringComparison]::OrdinalIgnoreCase)
    }
    catch {
    }
    return $false
}

function Get-StartupTaskInfo {
    $stateNames = @{
        0 = 'Unknown'
        1 = 'Disabled'
        2 = 'Queued'
        3 = 'Ready'
        4 = 'Running'
    }
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $task = $service.GetFolder('\').GetTask('\' + $Script:StartupTaskName)
        $action = $task.Definition.Actions.Item(1)
        $actionPath = [string]$action.Path
        $actionArguments = [string]$action.Arguments
        $actionWorkingDirectory = [string]$action.WorkingDirectory
        $actionMatches = (
            [string]::Equals(
                $actionPath,
                $Script:StartupLauncher,
                [StringComparison]::OrdinalIgnoreCase) -and
            [string]::Equals(
                $actionArguments,
                (Get-StartupArguments),
                [StringComparison]::Ordinal) -and
            [string]::Equals(
                $actionWorkingDirectory,
                $Script:InstallRoot,
                [StringComparison]::OrdinalIgnoreCase))
        $triggerCount = [int]$task.Definition.Triggers.Count
        $hasLogonTrigger = $false
        $hasUnlockTrigger = $false
        $hasResumeTrigger = $false
        for ($triggerIndex = 1; $triggerIndex -le $triggerCount; $triggerIndex++) {
            $registeredTrigger = $task.Definition.Triggers.Item($triggerIndex)
            $registeredTriggerType = [int]$registeredTrigger.Type
            if ($registeredTriggerType -eq 9) {
                $triggerUserMatches = Test-StartupTaskUserMatchesCurrentIdentity `
                    -UserId ([string]$registeredTrigger.UserId)
                if ([bool]$registeredTrigger.Enabled -and
                    $triggerUserMatches -and
                    [string]::Equals(
                        [string]$registeredTrigger.Delay,
                        'PT5S',
                        [StringComparison]::OrdinalIgnoreCase)) {
                    $hasLogonTrigger = $true
                }
            }
            elseif ($registeredTriggerType -eq 11) {
                $triggerUserMatches = Test-StartupTaskUserMatchesCurrentIdentity `
                    -UserId ([string]$registeredTrigger.UserId)
                if (([int]$registeredTrigger.StateChange -eq 8) -and
                    [bool]$registeredTrigger.Enabled -and
                    $triggerUserMatches -and
                    [string]::Equals(
                        [string]$registeredTrigger.Delay,
                        'PT2S',
                        [StringComparison]::OrdinalIgnoreCase)) {
                    $hasUnlockTrigger = $true
                }
            }
            elseif (($registeredTriggerType -eq 0) -and
                [bool]$registeredTrigger.Enabled -and
                [string]::Equals(
                    [string]$registeredTrigger.Delay,
                    'PT2S',
                    [StringComparison]::OrdinalIgnoreCase) -and
                ([string]$registeredTrigger.Subscription -match
                    'Microsoft-Windows-Kernel-Power') -and
                ([string]$registeredTrigger.Subscription -match
                    'EventID\s*=\s*107') -and
                ([string]$registeredTrigger.Subscription -match
                    'EventID\s*=\s*507')) {
                $hasResumeTrigger = $true
            }
        }
        $triggersMatch = ($triggerCount -eq 3) -and
            $hasLogonTrigger -and $hasUnlockTrigger -and $hasResumeTrigger
        $stateNumber = [int]$task.State
        $lastResultUnsigned = [BitConverter]::ToUInt32(
            [BitConverter]::GetBytes([int32]$task.LastTaskResult),
            0)
        $stateText = if ($stateNames.ContainsKey($stateNumber)) {
            [string]$stateNames[$stateNumber]
        }
        else {
            'Unknown (' + $stateNumber + ')'
        }
        return [pscustomobject]@{
            Registered = $true
            Enabled    = [bool]$task.Enabled
            State      = $stateText
            LastResult = ('0x{0:X8}' -f $lastResultUnsigned)
            ActionPath = $actionPath
            ActionArguments = $actionArguments
            ActionMatches = $actionMatches
            TriggerCount = $triggerCount
            TriggersMatch = $triggersMatch
            HasLogonTrigger = $hasLogonTrigger
            HasUnlockTrigger = $hasUnlockTrigger
            HasResumeTrigger = $hasResumeTrigger
            TriggerSummary = $(if ($triggersMatch) {
                    'Logon + session unlock + system resume'
                }
                else {
                    'Outdated or incomplete'
                })
            Error      = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Registered = $false
            Enabled    = $false
            State      = 'Missing'
            LastResult = $null
            ActionPath = $null
            ActionArguments = $null
            ActionMatches = $false
            TriggerCount = 0
            TriggersMatch = $false
            HasLogonTrigger = $false
            HasUnlockTrigger = $false
            HasResumeTrigger = $false
            TriggerSummary = 'Missing'
            Error      = $_.Exception.Message
        }
    }
}

function Install-StartupLaunchers {
    Assert-Windows
    if (-not (Test-Path -LiteralPath $Script:InstalledScript -PathType Leaf)) {
        throw 'Installed guard script is missing. Run Install again.'
    }
    Write-StartupLauncher

    $runCommand = Get-StartupRunCommand
    $runInstalled = $false
    $runError = $null
    try {
        if ($runCommand.Length -le 260) {
            New-Item -Path $Script:RunKeyPath -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $Script:RunKeyPath -Name $Script:RunValueName `
                -Value $runCommand -PropertyType String -Force -ErrorAction Stop | Out-Null
            $runInstalled = $true
        }
        else {
            $runError = ('The HKCU Run command is {0} characters; Windows allows 260.' -f
                $runCommand.Length)
            if (Test-Path -LiteralPath $Script:RunKeyPath) {
                $runItem = Get-ItemProperty -Path $Script:RunKeyPath -ErrorAction Stop
                if ($null -ne $runItem.PSObject.Properties[$Script:RunValueName]) {
                    Remove-ItemProperty -Path $Script:RunKeyPath `
                        -Name $Script:RunValueName -Force -ErrorAction Stop
                }
            }
        }
    }
    catch {
        $runError = $_.Exception.Message
    }
    $staleRunError = $null
    try {
        $currentRunValue = $null
        if (Test-Path -LiteralPath $Script:RunKeyPath) {
            $currentRunItem = Get-ItemProperty -Path $Script:RunKeyPath `
                -ErrorAction Stop
            $currentRunProperty = $currentRunItem.PSObject.Properties[$Script:RunValueName]
            if ($null -ne $currentRunProperty) {
                $currentRunValue = [string]$currentRunProperty.Value
            }
        }
        if (($null -ne $currentRunValue) -and
            [string]::Equals(
                $currentRunValue,
                $runCommand,
                [StringComparison]::Ordinal)) {
            $runInstalled = $true
            $runError = $null
        }
        else {
            $runInstalled = $false
            if ($null -ne $currentRunValue) {
                Remove-ItemProperty -Path $Script:RunKeyPath `
                    -Name $Script:RunValueName -Force -ErrorAction Stop
            }
            if ($null -eq $runError) {
                $runError = 'The HKCU Run value was not installed.'
            }
        }
    }
    catch {
        $runInstalled = $false
        $staleRunError = ('An outdated HKCU Run value could not be removed: ' +
            $_.Exception.Message)
        $runError = (($runError + ' ' + $staleRunError).Trim())
    }
    if ($null -ne $runError) {
        Write-GuardLog ('HKCU Run startup fallback was unavailable: ' + $runError)
    }

    # A previous Task Manager choice is recorded separately from the Run key.
    # Removing only this program's approval record lets the newly repaired Run
    # entry start again; it does not touch any other startup application.
    $approvalReset = $true
    $approvalError = $null
    try {
        if (Test-Path -LiteralPath $Script:RunApprovalKeyPath) {
            $approvalItem = Get-ItemProperty -Path $Script:RunApprovalKeyPath `
                -ErrorAction Stop
            if ($null -ne $approvalItem.PSObject.Properties[$Script:RunValueName]) {
                Remove-ItemProperty -Path $Script:RunApprovalKeyPath `
                    -Name $Script:RunValueName -Force -ErrorAction Stop
            }
        }
    }
    catch {
        $approvalReset = $false
        $approvalError = $_.Exception.Message
        Write-GuardLog ('Could not reset the Run startup approval record: ' + $approvalError)
    }

    $approvalState = Get-RunStartupApproval
    $runUsable = $runInstalled -and (
        $approvalReset -or $approvalState.StartsWith('Enabled', [StringComparison]::Ordinal))

    $taskInstalled = $false
    $taskError = $null
    $staleTaskError = $null
    try {
        # This task uses the current interactive user's token and limited run
        # level.  It neither requests elevation nor stores a password.
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        # Task Scheduler can canonicalize an interactive-token identity to its
        # account name even when registration supplied a SID. Register with the
        # canonical account name and accept either form during verification.
        $userId = [string]$identity.Name
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $rootFolder = $service.GetFolder('\')
        $definition = $service.NewTask(0)
        $definition.RegistrationInfo.Description =
            'Starts the KIDZ BLE input guard at sign-in, unlock, and system resume.'
        $definition.Principal.UserId = $userId
        $definition.Principal.LogonType = 3 # TASK_LOGON_INTERACTIVE_TOKEN
        $definition.Principal.RunLevel = 0 # TASK_RUNLEVEL_LUA (limited)

        $settings = $definition.Settings
        $settings.Enabled = $true
        $settings.Hidden = $true
        $settings.AllowDemandStart = $true
        $settings.StartWhenAvailable = $true
        $settings.DisallowStartIfOnBatteries = $false
        $settings.StopIfGoingOnBatteries = $false
        $settings.MultipleInstances = 2 # TASK_INSTANCES_IGNORE_NEW
        $settings.ExecutionTimeLimit = 'PT0S'
        $settings.RestartCount = 3
        $settings.RestartInterval = 'PT1M'

        $trigger = $definition.Triggers.Create(9) # TASK_TRIGGER_LOGON
        $trigger.Enabled = $true
        $trigger.UserId = $userId
        $trigger.Delay = 'PT5S'

        # Re-run the same hidden supervisor after workstation unlock.  This is
        # the non-admin recovery path when Modern Standby or lid handling ends
        # both long-lived processes without creating a new logon session.
        $unlockTrigger = $definition.Triggers.Create(11) # TASK_TRIGGER_SESSION_STATE_CHANGE
        $unlockTrigger.Enabled = $true
        $unlockTrigger.UserId = $userId
        $unlockTrigger.StateChange = 8 # TASK_SESSION_UNLOCK
        $unlockTrigger.Delay = 'PT2S'

        # Lid resume does not always produce a workstation-unlock event (for
        # example when Windows is configured not to require sign-in on wake).
        $resumeTrigger = $definition.Triggers.Create(0) # TASK_TRIGGER_EVENT
        $resumeTrigger.Enabled = $true
        $resumeTrigger.Delay = 'PT2S'
        $resumeTrigger.Subscription = '<QueryList><Query Id="0" Path="System"><Select Path="System">*[System[Provider[@Name="Microsoft-Windows-Kernel-Power"] and (EventID=107 or EventID=507)]]</Select></Query></QueryList>'

        $action = $definition.Actions.Create(0) # TASK_ACTION_EXEC
        $action.Path = $Script:StartupLauncher
        $action.Arguments = Get-StartupArguments
        $action.WorkingDirectory = $Script:InstallRoot

        # TASK_CREATE_OR_UPDATE=6.  InteractiveToken plus LUA keeps this a
        # genuinely non-admin, same-desktop startup task.
        $null = $rootFolder.RegisterTaskDefinition(
            $Script:StartupTaskName,
            $definition,
            6,
            $userId,
            $null,
            3,
            $null)
        $taskInstalled = $true
    }
    catch {
        # Some managed PCs forbid users from creating scheduled tasks.  The
        # HKCU Run entry remains a complete non-admin fallback.
        $taskError = $_.Exception.Message
        Write-GuardLog ('Per-user scheduled startup task was unavailable. Error: ' +
            $taskError)
    }

    # Verify the registered definition rather than trusting only the COM call's
    # return value. If a policy prevented replacement, remove this program's
    # stale legacy action so it cannot keep opening the old script-host chain.
    $taskInstalled = $false
    $registeredTask = Get-StartupTaskInfo
    if ([bool]$registeredTask.Registered -and
        [bool]$registeredTask.Enabled -and
        [bool]$registeredTask.ActionMatches -and
        [bool]$registeredTask.TriggersMatch) {
        $taskInstalled = $true
    }
    elseif ([bool]$registeredTask.Registered -and
        [bool]$registeredTask.ActionMatches -and
        [bool]$registeredTask.TriggersMatch) {
        $taskError = 'The scheduled startup task is registered but disabled.'
    }
    elseif ([bool]$registeredTask.Registered -and
        ((-not [bool]$registeredTask.ActionMatches) -or
            (-not [bool]$registeredTask.TriggersMatch))) {
        $taskInstalled = $false
        $verificationDetail = (
            'Verification failed: action={0}; triggers={1}; count={2}; ' +
            'logon={3}; unlock={4}; resume={5}.' -f
            [bool]$registeredTask.ActionMatches,
            [bool]$registeredTask.TriggersMatch,
            [int]$registeredTask.TriggerCount,
            [bool]$registeredTask.HasLogonTrigger,
            [bool]$registeredTask.HasUnlockTrigger,
            [bool]$registeredTask.HasResumeTrigger)
        try {
            $cleanupService = New-Object -ComObject 'Schedule.Service'
            $cleanupService.Connect()
            $cleanupService.GetFolder('\').DeleteTask($Script:StartupTaskName, 0)
            $taskError = (($taskError + ' ' + $verificationDetail +
                    ' Existing startup task used an outdated action or recovery ' +
                    'trigger and was removed.').Trim())
        }
        catch {
            $staleTaskError = ('An outdated scheduled startup task could not be removed: ' +
                $_.Exception.Message)
            $taskError = (($taskError + ' ' + $staleTaskError).Trim())
        }
        Write-GuardLog $taskError
    }
    elseif ($null -eq $taskError) {
        $taskError = [string]$registeredTask.Error
    }

    if ((-not $runUsable) -and (-not $taskInstalled)) {
        throw (('No automatic startup launcher could be installed. HKCU Run: {0} ' +
            'Scheduled task: {1}') -f
            $(if ($null -ne $runError) { $runError } elseif (-not $approvalReset) {
                    $approvalError
                } else { $approvalState }),
            $taskError)
    }

    # v2.2.1 used a WScript shim.  Once a native startup path is usable, remove
    # that app-owned shim so any stale legacy registration can no longer start
    # a visible PowerShell process while the repaired registration takes over.
    $legacyLauncher = Join-Path $Script:InstallRoot 'phone-input-guard-startup.vbs'
    try {
        if (Test-Path -LiteralPath $legacyLauncher -PathType Leaf) {
            Remove-Item -LiteralPath $legacyLauncher -Force -ErrorAction Stop
        }
    }
    catch {
        Write-GuardLog ('Could not remove the legacy WScript startup shim: ' +
            $_.Exception.Message)
    }

    if ($null -ne $staleRunError) {
        throw $staleRunError
    }
    if ($null -ne $staleTaskError) {
        throw $staleTaskError
    }

    return [pscustomobject]@{
        RunCommand    = $runCommand
        RunInstalled  = $runInstalled
        RunUsable     = $runUsable
        RunError      = $runError
        ApprovalReset = $approvalReset
        ApprovalError = $approvalError
        ApprovalState = $approvalState
        TaskInstalled = $taskInstalled
        TaskError     = $taskError
    }
}

function Remove-StartupLaunchers {
    $failures = @()
    foreach ($registryTarget in @(
            [pscustomobject]@{ Path = $Script:RunKeyPath; Name = $Script:RunValueName },
            [pscustomobject]@{ Path = $Script:RunApprovalKeyPath; Name = $Script:RunValueName }
        )) {
        try {
            if (Test-Path -LiteralPath $registryTarget.Path) {
                $item = Get-ItemProperty -Path $registryTarget.Path -ErrorAction Stop
                if ($null -ne $item.PSObject.Properties[$registryTarget.Name]) {
                    Remove-ItemProperty -Path $registryTarget.Path `
                        -Name $registryTarget.Name -Force -ErrorAction Stop
                }
            }
        }
        catch {
            $failures += ('Registry launcher removal failed for {0}: {1}' -f
                $registryTarget.Path, $_.Exception.Message)
        }
    }
    try {
        $service = New-Object -ComObject 'Schedule.Service'
        $service.Connect()
        $service.GetFolder('\').DeleteTask($Script:StartupTaskName, 0)
    }
    catch {
        # HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) means the task is already
        # absent.  Any other result must be surfaced so Uninstall cannot leave
        # an orphaned launcher while claiming success.
        $win32Code = ([long]$_.Exception.HResult) -band 65535
        if ($win32Code -ne 2) {
            $failures += ('Scheduled startup task removal failed: ' +
                $_.Exception.Message)
        }
    }
    if ($failures.Count -gt 0) {
        $message = $failures -join ' '
        Write-GuardLog $message
        throw $message
    }
}

function Initialize-NativeMethods {
    if ($null -ne $Script:NativeMethodsType) {
        return
    }

    $source = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace XXPhoneInputGuardV6
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
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
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

        [DllImport("user32.dll", EntryPoint = "SetWindowsHookExW", SetLastError = true)]
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

        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SetThreadExecutionState(uint executionState);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr securityAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr job, int informationClass,
            ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
            uint informationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(
            IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint ES_CONTINUOUS = 0x80000000;
        private const uint ES_SYSTEM_REQUIRED = 0x00000001;
        private const uint ES_DISPLAY_REQUIRED = 0x00000002;
        private const int WH_KEYBOARD_LL = 13;
        private const int WH_MOUSE_LL = 14;
        private const uint WM_QUIT = 0x0012;
        private const uint PM_NOREMOVE = 0x0000;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectExtendedLimitInformation = 9;

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
        private static string hookStage = "not started";
        private static readonly object BlockerSync = new object();
        private static Process blockerProcess;
        private static IntPtr blockerJob = IntPtr.Zero;
        private static int blockerError;
        private static string blockerStage = "not started";

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

        private static void HookThreadMain()
        {
            try
            {
                hookThreadId = GetCurrentThreadId();
                hookStage = "creating the hook message queue";
                MSG initialMessage;
                PeekMessage(out initialMessage, IntPtr.Zero, 0, 0, PM_NOREMOVE);

                // A global hook must identify the DLL that contains its procedure.
                // The PowerShell host module is not that DLL, so use this compiled
                // assembly's actual module handle.
                hookStage = "resolving the compiled hook DLL";
                IntPtr module = Marshal.GetHINSTANCE(typeof(NativeMethods).Module);
                if (module == IntPtr.Zero || module == new IntPtr(-1))
                {
                    hookError = 126;
                    return;
                }

                hookStage = "installing the keyboard hook";
                keyboardHook = SetWindowsHookEx(
                    WH_KEYBOARD_LL, KeyboardProcedure, module, 0);
                if (keyboardHook == IntPtr.Zero)
                {
                    hookError = Marshal.GetLastWin32Error();
                    return;
                }

                hookStage = "installing the mouse hook";
                mouseHook = SetWindowsHookEx(
                    WH_MOUSE_LL, MouseProcedure, module, 0);
                if (mouseHook == IntPtr.Zero)
                {
                    hookError = Marshal.GetLastWin32Error();
                    return;
                }

                hookStage = "active";
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
                hookStage = "starting the hook thread";
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
                hookStage = "waiting for the hook thread";
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

        public static string GetHookStage()
        {
            return hookStage;
        }

        private static bool EnsureKillOnCloseJob()
        {
            if (blockerJob != IntPtr.Zero)
                return true;

            blockerStage = "creating the safety job";
            blockerJob = CreateJobObject(IntPtr.Zero, null);
            if (blockerJob == IntPtr.Zero)
            {
                blockerError = Marshal.GetLastWin32Error();
                return false;
            }

            JOBOBJECT_EXTENDED_LIMIT_INFORMATION information =
                new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            information.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            blockerStage = "configuring the safety job";
            if (!SetInformationJobObject(
                    blockerJob,
                    JobObjectExtendedLimitInformation,
                    ref information,
                    (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
            {
                int informationError = Marshal.GetLastWin32Error();
                IntPtr unusableJob = blockerJob;
                blockerJob = IntPtr.Zero;
                if (unusableJob != IntPtr.Zero)
                    CloseHandle(unusableJob);
                blockerError = informationError;
                return false;
            }
            return true;
        }

        private static bool IsBlockerExitConfirmed(Process process, int waitMilliseconds)
        {
            try
            {
                process.Refresh();
                if (process.HasExited)
                    return true;
                if (waitMilliseconds <= 0)
                    return false;
                if (!process.WaitForExit(waitMilliseconds))
                    return false;
                process.Refresh();
                return process.HasExited;
            }
            catch (System.ComponentModel.Win32Exception error)
            {
                blockerError = error.NativeErrorCode;
                return false;
            }
            catch (InvalidOperationException)
            {
                blockerError = 6;
                return false;
            }
        }

        private static bool CompleteBlockerStop(Process process)
        {
            if (!IsBlockerExitConfirmed(process, 0))
                return false;

            blockerProcess = null;
            process.Dispose();
            blockerError = 0;
            blockerStage = "stopped";
            return true;
        }

        public static bool StartInputBlocker(string executablePath)
        {
            lock (BlockerSync)
            {
                if (blockerProcess != null)
                {
                    try
                    {
                        blockerProcess.Refresh();
                        if (!blockerProcess.HasExited)
                            return blockerStage == "active";
                        blockerError = blockerProcess.ExitCode;
                    }
                    catch (System.ComponentModel.Win32Exception error)
                    {
                        blockerError = error.NativeErrorCode;
                        blockerStage = "checking the existing native helper";
                        return false;
                    }
                    catch (InvalidOperationException)
                    {
                        blockerError = 6;
                        blockerStage = "checking the existing native helper";
                        return false;
                    }
                    blockerProcess.Dispose();
                    blockerProcess = null;
                }

                blockerError = 0;
                blockerStage = "validating the native helper";
                if (String.IsNullOrWhiteSpace(executablePath) ||
                    !File.Exists(executablePath))
                {
                    blockerError = 2;
                    return false;
                }
                if (!EnsureKillOnCloseJob())
                    return false;

                try
                {
                    blockerStage = "starting the native helper";
                    ProcessStartInfo startInfo = new ProcessStartInfo();
                    startInfo.FileName = executablePath;
                    startInfo.WorkingDirectory = Path.GetDirectoryName(executablePath);
                    startInfo.UseShellExecute = false;
                    startInfo.CreateNoWindow = true;
                    Process process = Process.Start(startInfo);
                    if (process == null)
                    {
                        blockerError = 31;
                        return false;
                    }
                    // Track the process immediately.  Any later failure must
                    // leave enough state for StopInputBlocker to confirm exit.
                    blockerProcess = process;

                    blockerStage = "placing the helper in the safety job";
                    if (!AssignProcessToJobObject(blockerJob, process.Handle))
                    {
                        int assignmentError = Marshal.GetLastWin32Error();
                        try { process.Kill(); } catch { }
                        if (IsBlockerExitConfirmed(process, 2000))
                        {
                            blockerProcess = null;
                            process.Dispose();
                        }
                        blockerError = assignmentError;
                        blockerStage = "placing the helper in the safety job";
                        return false;
                    }

                    Thread.Sleep(175);
                    blockerProcess.Refresh();
                    if (blockerProcess.HasExited)
                    {
                        blockerError = blockerProcess.ExitCode;
                        blockerStage = "the native helper exited during startup";
                        blockerProcess.Dispose();
                        blockerProcess = null;
                        return false;
                    }

                    blockerStage = "active";
                    return true;
                }
                catch (System.ComponentModel.Win32Exception error)
                {
                    blockerError = error.NativeErrorCode;
                    return false;
                }
                catch
                {
                    blockerError = 31;
                    return false;
                }
            }
        }

        public static bool StopInputBlocker()
        {
            lock (BlockerSync)
            {
                Process process = blockerProcess;
                if (process == null)
                {
                    blockerError = 0;
                    blockerStage = "stopped";
                    return true;
                }

                blockerError = 0;
                blockerStage = "stopping the native helper";
                if (CompleteBlockerStop(process))
                    return true;

                // Retry direct termination.  Keep blockerProcess assigned until
                // Windows confirms that the process really has exited.
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    try
                    {
                        process.Kill();
                    }
                    catch (System.ComponentModel.Win32Exception error)
                    {
                        blockerError = error.NativeErrorCode;
                    }
                    catch (InvalidOperationException)
                    {
                        blockerError = 6;
                    }

                    if (IsBlockerExitConfirmed(process, 500) &&
                        CompleteBlockerStop(process))
                        return true;
                }

                // Closing a KILL_ON_JOB_CLOSE job is an independent fallback
                // when direct Process.Kill did not produce a confirmed exit.
                blockerStage = "closing the safety job to stop the native helper";
                IntPtr job = blockerJob;
                if (job != IntPtr.Zero)
                {
                    if (CloseHandle(job))
                    {
                        blockerJob = IntPtr.Zero;
                    }
                    else
                    {
                        blockerError = Marshal.GetLastWin32Error();
                    }
                }

                if (IsBlockerExitConfirmed(process, 2000) &&
                    CompleteBlockerStop(process))
                    return true;

                if (blockerError == 0)
                    blockerError = 1460;
                blockerStage = "waiting for the native helper to exit";
                return false;
            }
        }

        public static int GetBlockerError()
        {
            return blockerError;
        }

        public static string GetBlockerStage()
        {
            return blockerStage;
        }

        public static bool SetKeepAwake(bool enabled)
        {
            uint flags = ES_CONTINUOUS;
            if (enabled)
                flags |= ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED;
            return SetThreadExecutionState(flags) != 0;
        }

        public static long GetMonotonicMilliseconds()
        {
            return unchecked((long)GetTickCount64());
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

    # A source-derived simple name prevents the CLR from unifying this bridge
    # with a different implementation already loaded in the same PowerShell
    # process.  Identical source reuses its exact loaded assembly and type.
    $sourceBytes = [Text.Encoding]::UTF8.GetBytes($source)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $sourceHash = [BitConverter]::ToString(
            $sha256.ComputeHash($sourceBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
    $assemblySimpleName = 'XXPhoneInputGuardNative_' + $sourceHash
    $nativeTypeName = 'XXPhoneInputGuardV6.NativeMethods'

    foreach ($loadedAssembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        try {
            if ($loadedAssembly.GetName().Name -ne $assemblySimpleName) {
                continue
            }
            $existingType = $loadedAssembly.GetType(
                $nativeTypeName, $false, $false)
            if ($null -eq $existingType) {
                throw ('Loaded native bridge assembly {0} lacks {1}.' -f
                    $assemblySimpleName, $nativeTypeName)
            }
            $Script:NativeMethodsType = $existingType
            return
        }
        catch {
            if ($_.Exception.Message -like 'Loaded native bridge assembly*') {
                throw
            }
        }
    }

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
        'XXNativeBuild-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $buildDirectory -Force | Out-Null
    $sourcePath = Join-Path $buildDirectory 'NativeMethods.cs'
    $assemblyPath = Join-Path $buildDirectory ($assemblySimpleName + '.dll')
    Set-Content -LiteralPath $sourcePath -Value $source -Encoding UTF8

    $compilerOutput = @(& $compiler /nologo /target:library /optimize+ `
        (('/out:{0}' -f $assemblyPath)) $sourcePath 2>&1 |
        ForEach-Object { $_.ToString() })
    if (($LASTEXITCODE -ne 0) -or -not (Test-Path -LiteralPath $assemblyPath)) {
        throw ('Native input-hook compiler failed:' + [Environment]::NewLine +
            ($compilerOutput -join [Environment]::NewLine))
    }

    $loadedAssembly = [Reflection.Assembly]::LoadFrom($assemblyPath)
    if ($loadedAssembly.GetName().Name -ne $assemblySimpleName) {
        throw ('The compiled native bridge has an unexpected assembly identity: {0}.' -f
            $loadedAssembly.GetName().Name)
    }
    $Script:NativeMethodsType = $loadedAssembly.GetType(
        $nativeTypeName, $false, $false)
    if ($null -eq $Script:NativeMethodsType) {
        throw 'The compiled native-method bridge loaded without its expected public type.'
    }
}

function Initialize-BleWatcherBridge {
    $cachedType = Get-Variable -Name BleWatcherBridgeType -Scope Script `
        -ErrorAction SilentlyContinue
    if (($null -ne $cachedType) -and ($null -ne $cachedType.Value)) {
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
        private readonly object lifecycleSync = new object();
        private readonly object sampleSync = new object();
        private readonly Queue<BleSample> samples = new Queue<BleSample>();
        private readonly Guid targetUuid;
        private BluetoothLEAdvertisementWatcher watcher;
        private BluetoothLEAdvertisementWatcher activeWatcher;
        private int totalPackets;
        private int matchingPackets;
        private volatile bool disposed;

        public BleWatcherBridge(Guid targetUuid)
        {
            this.targetUuid = targetUuid;
            watcher = CreateWatcher();
            activeWatcher = null;
        }

        private BluetoothLEAdvertisementWatcher CreateWatcher()
        {
            BluetoothLEAdvertisementWatcher created =
                new BluetoothLEAdvertisementWatcher();
            created.ScanningMode = BluetoothLEScanningMode.Active;
            created.Received += OnReceived;
            return created;
        }

        public string Status
        {
            get
            {
                lock (lifecycleSync)
                {
                    if (disposed)
                        throw new ObjectDisposedException("BleWatcherBridge");
                    return watcher.Status.ToString();
                }
            }
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
            lock (lifecycleSync)
            {
                if (disposed)
                    throw new ObjectDisposedException("BleWatcherBridge");
                watcher.Start();
                lock (sampleSync)
                {
                    samples.Clear();
                    activeWatcher = watcher;
                }
            }
        }

        public void Restart()
        {
            lock (lifecycleSync)
            {
                if (disposed)
                    throw new ObjectDisposedException("BleWatcherBridge");

                BluetoothLEAdvertisementWatcher previous = watcher;
                try
                {
                    previous.Received -= OnReceived;
                }
                catch
                {
                }
                lock (sampleSync)
                {
                    activeWatcher = null;
                    samples.Clear();
                }
                try
                {
                    previous.Stop();
                }
                catch
                {
                }

                // A new WinRT watcher is intentional.  Windows can
                // automatically stop the previous scanner during suspend,
                // and on some adapters its old instance does not resume
                // delivery even when Status later appears usable.
                BluetoothLEAdvertisementWatcher replacement = CreateWatcher();
                watcher = replacement;
                try
                {
                    replacement.Start();
                    lock (sampleSync)
                    {
                        activeWatcher = replacement;
                    }
                }
                catch
                {
                    try
                    {
                        replacement.Received -= OnReceived;
                    }
                    catch
                    {
                    }
                    try
                    {
                        replacement.Stop();
                    }
                    catch
                    {
                    }
                    lock (sampleSync)
                    {
                        activeWatcher = null;
                        samples.Clear();
                    }
                    throw;
                }
            }
        }

        private void OnReceived(
            BluetoothLEAdvertisementWatcher sender,
            BluetoothLEAdvertisementReceivedEventArgs args)
        {
            try
            {
                bool isTarget = false;
                foreach (Guid uuid in args.Advertisement.ServiceUuids)
                {
                    if (uuid == targetUuid)
                    {
                        isTarget = true;
                        break;
                    }
                }

                BleSample sample = null;
                if (isTarget)
                {
                    // Read all WinRT-projected properties before taking the
                    // queue lock, so a projection stall cannot block Restart.
                    sample = new BleSample {
                        SeenUtc = DateTime.UtcNow,
                        Address = args.BluetoothAddress,
                        Rssi = args.RawSignalStrengthInDBm
                    };
                }

                lock (sampleSync)
                {
                    // A callback already in flight from a replaced watcher
                    // must not reintroduce a pre-suspend advertisement.
                    if (disposed || !Object.ReferenceEquals(sender, activeWatcher))
                        return;

                    Interlocked.Increment(ref totalPackets);
                    if (!isTarget)
                        return;

                    Interlocked.Increment(ref matchingPackets);
                    samples.Enqueue(sample);
                    while (samples.Count > 1024)
                        samples.Dequeue();
                }
            }
            catch
            {
                // A transient WinRT projection error must not escape the
                // native event callback and terminate the guard process.
            }
        }

        public BleSample[] Drain()
        {
            lock (sampleSync)
            {
                BleSample[] result = samples.ToArray();
                samples.Clear();
                return result;
            }
        }

        public void Dispose()
        {
            BluetoothLEAdvertisementWatcher previous;
            lock (lifecycleSync)
            {
                if (disposed)
                    return;

                previous = watcher;
                try
                {
                    previous.Received -= OnReceived;
                }
                catch
                {
                }
                lock (sampleSync)
                {
                    disposed = true;
                    activeWatcher = null;
                    samples.Clear();
                }
            }
            try
            {
                previous.Stop();
            }
            catch
            {
            }
        }
    }
}
'@

    # The CLR identifies an unsigned assembly primarily by its simple name and
    # version.  Loading a newly compiled DLL under a reused name can therefore
    # return an older assembly that is already resident in Windows PowerShell.
    # Derive the simple name from the complete source text so changed source
    # always has a new process-wide identity, while identical source is reused.
    $sourceBytes = [Text.Encoding]::UTF8.GetBytes($source)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $sourceHash = [BitConverter]::ToString(
            $sha256.ComputeHash($sourceBytes)).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
    $assemblySimpleName = 'XXPhoneInputGuardBle_' + $sourceHash
    $bridgeTypeName = 'XXPhoneInputGuardBleV2.BleWatcherBridge'

    foreach ($loadedAssembly in [AppDomain]::CurrentDomain.GetAssemblies()) {
        try {
            if ($loadedAssembly.GetName().Name -ne $assemblySimpleName) {
                continue
            }
            $existingType = $loadedAssembly.GetType(
                $bridgeTypeName, $false, $false)
            if ($null -eq $existingType) {
                throw ('Loaded BLE bridge assembly {0} lacks {1}.' -f
                    $assemblySimpleName, $bridgeTypeName)
            }
            $Script:BleWatcherBridgeType = $existingType
            return
        }
        catch {
            if ($_.Exception.Message -like 'Loaded BLE bridge assembly*') {
                throw
            }
        }
    }

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
        'XXBleBuild-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $buildDirectory -Force | Out-Null
    $sourcePath = Join-Path $buildDirectory 'BleWatcherBridge.cs'
    $assemblyPath = Join-Path $buildDirectory ($assemblySimpleName + '.dll')
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

    $loadedAssembly = [Reflection.Assembly]::LoadFrom($assemblyPath)
    if ($loadedAssembly.GetName().Name -ne $assemblySimpleName) {
        throw ('The compiled BLE bridge has an unexpected assembly identity: {0}.' -f
            $loadedAssembly.GetName().Name)
    }
    $Script:BleWatcherBridgeType = $loadedAssembly.GetType(
        $bridgeTypeName, $false, $false)
    if ($null -eq $Script:BleWatcherBridgeType) {
        throw 'The compiled BLE bridge loaded without its expected public type.'
    }
}

function New-BleWatcherBridge {
    param([Parameter(Mandatory = $true)][Guid]$TargetUuid)

    Initialize-BleWatcherBridge
    return [Activator]::CreateInstance(
        $Script:BleWatcherBridgeType, [object[]]@($TargetUuid))
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
        [AllowEmptyCollection()]
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

    $form = $null
    try {
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
    catch {
        Write-GuardLog ('Lock banner is unavailable: ' + $_.Exception.Message)
        if ($null -ne $form) {
            try { $form.Dispose() } catch { }
        }
        return $null
    }
}

function Show-GuardBanner {
    param([AllowNull()]$Banner)

    if ($null -eq $Banner) {
        return
    }
    try {
        if (-not $Banner.Visible) {
            $Banner.Show()
            $Banner.BringToFront()
            $Banner.Refresh()
        }
    }
    catch {
        Write-GuardLog ('Lock banner could not be shown: ' + $_.Exception.Message)
    }
}

function Hide-GuardBanner {
    param([AllowNull()]$Banner)

    if ($null -eq $Banner) {
        return
    }
    try {
        if ($Banner.Visible) {
            $Banner.Hide()
        }
    }
    catch {
        Write-GuardLog ('Lock banner could not be hidden: ' + $_.Exception.Message)
    }
}

function Close-GuardBanner {
    param([AllowNull()]$Banner)

    if ($null -eq $Banner) {
        return
    }
    try { $Banner.Close() } catch { }
    try { $Banner.Dispose() } catch { }
}

function Reset-PowerRescueState {
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][long]$NowMilliseconds
    )

    $nativeMethods = $Script:NativeMethodsType
    $ac = $nativeMethods::GetACLineStatus()
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

    $nativeMethods = $Script:NativeMethodsType
    $rawAC = $nativeMethods::GetACLineStatus()
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
        [Parameter(Mandatory = $true)][string]$WatcherStatus,
        [Parameter(Mandatory = $true)][int]$WatcherRestartCount,
        [AllowNull()][string]$WatcherRestartReason
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
            watcher_restart_count = $WatcherRestartCount
            watcher_restart_reason = $WatcherRestartReason
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

function Write-GuardReadyState {
    param(
        [Parameter(Mandatory = $true)][long]$ProcessStartTicks,
        [Parameter(Mandatory = $true)][string]$WatcherStatus,
        [Parameter(Mandatory = $true)][int]$WatcherRestartCount,
        [AllowNull()][string]$WatcherRestartReason,
        [bool]$Initialized = $true
    )

    try {
        $timestamp = [DateTime]::UtcNow.ToString('o')
        $readyState = [pscustomobject][ordered]@{
            pid                     = $PID
            process_start_utc_ticks = $ProcessStartTicks
            ready_utc               = $timestamp
            heartbeat_utc           = $timestamp
            version                 = $Script:GuardVersion
            initialized             = $Initialized
            watcher_status          = $WatcherStatus
            watcher_restart_count   = $WatcherRestartCount
            watcher_restart_reason  = $WatcherRestartReason
        }
        $temporaryReadyPath = $Script:ReadyPath + '.tmp'
        $readyState | ConvertTo-Json -Depth 2 |
            Set-Content -LiteralPath $temporaryReadyPath -Encoding UTF8
        Move-Item -LiteralPath $temporaryReadyPath `
            -Destination $Script:ReadyPath -Force
        return $true
    }
    catch {
        Write-GuardLog ('Ready heartbeat write failed: ' + $_.Exception.Message)
        return $false
    }
}

function Write-GuardIdentityState {
    param([Parameter(Mandatory = $true)][long]$ProcessStartTicks)

    try {
        $identityState = [pscustomobject][ordered]@{
            pid                     = $PID
            process_start_utc_ticks = $ProcessStartTicks
            created_utc             = [DateTime]::UtcNow.ToString('o')
            version                 = $Script:GuardVersion
        }
        $temporaryIdentityPath = $Script:IdentityPath + '.tmp'
        $identityState | ConvertTo-Json -Depth 2 |
            Set-Content -LiteralPath $temporaryIdentityPath -Encoding UTF8
        Move-Item -LiteralPath $temporaryIdentityPath `
            -Destination $Script:IdentityPath -Force
        return $true
    }
    catch {
        Write-GuardLog ('Guard identity write failed: ' + $_.Exception.Message)
        return $false
    }
}

function Get-OwnedGuardProcess {
    if (-not (Test-Path -LiteralPath $Script:PidPath)) {
        return $null
    }
    $process = $null
    try {
        $guardPid = [int](Get-Content -LiteralPath $Script:PidPath -Raw)
        $process = Get-Process -Id $guardPid -ErrorAction Stop
        # Pin this exact kernel process object before comparing metadata. Any
        # returned Process therefore remains safe across numeric PID reuse.
        $null = $process.Handle
        $actualStartTicks = $process.StartTime.ToUniversalTime().Ticks
        $owned = $false

        try {
            if (Test-Path -LiteralPath $Script:IdentityPath) {
                $identityState = Get-Content -LiteralPath $Script:IdentityPath -Raw |
                    ConvertFrom-Json
                $owned = (([int]$identityState.pid -eq $guardPid) -and
                    ([long]$identityState.process_start_utc_ticks -eq
                        [long]$actualStartTicks))
            }
        }
        catch {
            $owned = $false
        }

        # Version 2.2 did not have the immutable identity file, but its ready
        # state already carried the same PID/start-time pair for safe upgrade.
        if ((-not $owned) -and (Test-Path -LiteralPath $Script:ReadyPath)) {
            try {
                $readyState = Get-Content -LiteralPath $Script:ReadyPath -Raw |
                    ConvertFrom-Json
                $owned = (([int]$readyState.pid -eq $guardPid) -and
                    ([long]$readyState.process_start_utc_ticks -eq
                        [long]$actualStartTicks))
            }
            catch {
                $owned = $false
            }
        }

        if ($owned) {
            return $process
        }
    }
    catch {
    }
    if ($null -ne $process) {
        $process.Dispose()
    }
    return $null
}

function Test-GuardProcess {
    $process = Get-OwnedGuardProcess
    if ($null -ne $process) {
        $process.Dispose()
        return $true
    }
    # Missing/corrupt metadata must never be interpreted as a clean stop while
    # an unknown process still owns the guard mutex.
    return (-not (Test-GuardMutexAvailable))
}

function Stop-OwnedGuardProcess {
    $process = Get-OwnedGuardProcess
    if ($null -eq $process) {
        return $false
    }
    try {
        $process.Kill()
        if (-not $process.WaitForExit(5000)) {
            return $false
        }
        Write-GuardLog ('Force-stopped owned guard PID {0}.' -f $process.Id)
        return $true
    }
    catch {
        Write-GuardLog ('Owned guard could not be force-stopped: ' +
            $_.Exception.Message)
        return $false
    }
    finally {
        $process.Dispose()
    }
}

function Test-GuardReady {
    if (-not (Test-Path -LiteralPath $Script:ReadyPath) -or
        -not (Test-Path -LiteralPath $Script:PidPath)) {
        return $false
    }
    try {
        $guardPid = [int](Get-Content -LiteralPath $Script:PidPath -Raw)
        $readyState = Get-Content -LiteralPath $Script:ReadyPath -Raw | ConvertFrom-Json
        if ([int]$readyState.pid -ne $guardPid) {
            return $false
        }
        if (-not [string]::Equals(
                [string]$readyState.version,
                $Script:GuardVersion,
                [StringComparison]::Ordinal)) {
            return $false
        }
        $initializedProperty = $readyState.PSObject.Properties['initialized']
        if (($null -eq $initializedProperty) -or
            (-not [bool]$initializedProperty.Value)) {
            return $false
        }
        $process = Get-Process -Id $guardPid -ErrorAction Stop
        $startProperty = $readyState.PSObject.Properties['process_start_utc_ticks']
        if ($null -eq $startProperty) {
            return $false
        }
        $actualStartTicks = $process.StartTime.ToUniversalTime().Ticks
        if ([long]$startProperty.Value -ne [long]$actualStartTicks) {
            return $false
        }

        $heartbeatProperty = $readyState.PSObject.Properties['heartbeat_utc']
        if ($null -eq $heartbeatProperty) {
            return $false
        }
        $heartbeatUtc = [DateTime]::Parse(
            [string]$heartbeatProperty.Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal)
        $heartbeatAgeSeconds = ([DateTime]::UtcNow - $heartbeatUtc).TotalSeconds
        return (($heartbeatAgeSeconds -ge -5) -and ($heartbeatAgeSeconds -le 15))
    }
    catch {
        return $false
    }
}

function Get-GuardHeartbeatAgeSeconds {
    try {
        if (-not (Test-Path -LiteralPath $Script:ReadyPath)) {
            return $null
        }
        $readyState = Get-Content -LiteralPath $Script:ReadyPath -Raw |
            ConvertFrom-Json
        $heartbeatProperty = $readyState.PSObject.Properties['heartbeat_utc']
        if ($null -eq $heartbeatProperty) {
            return $null
        }
        $heartbeatUtc = [DateTime]::Parse(
            [string]$heartbeatProperty.Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal)
        return [Math]::Round(
            ([DateTime]::UtcNow - $heartbeatUtc).TotalSeconds,
            1)
    }
    catch {
        return $null
    }
}

function Get-GuardMetadataSnapshot {
    $identityPresent = Test-Path -LiteralPath $Script:IdentityPath
    $identityText = $null
    if ($identityPresent) {
        $identityText = Get-Content -LiteralPath $Script:IdentityPath -Raw
    }
    $readyPresent = Test-Path -LiteralPath $Script:ReadyPath
    $readyText = $null
    if ($readyPresent) {
        $readyText = Get-Content -LiteralPath $Script:ReadyPath -Raw
    }
    return [pscustomobject]@{
        IdentityPresent = [bool]$identityPresent
        IdentityText    = $identityText
        ReadyPresent    = [bool]$readyPresent
        ReadyText       = $readyText
    }
}

function Get-GuardLivenessSnapshot {
    $process = $null
    try {
        $process = Get-OwnedGuardProcess
        if ($null -eq $process) {
            return $null
        }
        $null = $process.Handle
        $process.Refresh()
        if ($process.HasExited) {
            return $null
        }
        $metadata = Get-GuardMetadataSnapshot
        return [pscustomobject]@{
            Pid             = [int]$process.Id
            ProcessStartTicks = [long]$process.StartTime.ToUniversalTime().Ticks
            IdentityPresent = [bool]$metadata.IdentityPresent
            IdentityText    = $metadata.IdentityText
            ReadyPresent    = [bool]$metadata.ReadyPresent
            ReadyText       = $metadata.ReadyText
        }
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }
}

function Test-GuardLivenessSnapshotEqual {
    param(
        [Parameter(Mandatory = $true)]$Left,
        [Parameter(Mandatory = $true)]$Right
    )

    return (([int]$Left.Pid -eq [int]$Right.Pid) -and
        ([long]$Left.ProcessStartTicks -eq [long]$Right.ProcessStartTicks) -and
        ([bool]$Left.IdentityPresent -eq [bool]$Right.IdentityPresent) -and
        ([string]::Equals(
            [string]$Left.IdentityText,
            [string]$Right.IdentityText,
            [StringComparison]::Ordinal)) -and
        ([bool]$Left.ReadyPresent -eq [bool]$Right.ReadyPresent) -and
        ([string]::Equals(
            [string]$Left.ReadyText,
            [string]$Right.ReadyText,
            [StringComparison]::Ordinal)))
}

function Stop-StaleGuardProcess {
    param(
        [ValidateRange(15, 300)][int]$MinimumHeartbeatAgeSeconds = 20,
        $ExpectedSnapshot = $null,
        [ValidateRange(0, 3600000)][long]$ObservedUnchangedMilliseconds = 0
    )

    $validatedProcess = $null
    try {
        $validatedProcess = Get-OwnedGuardProcess
        if ($null -eq $validatedProcess) {
            return $false
        }
        $guardPid = [int]$validatedProcess.Id
        $actualStartTicks = $validatedProcess.StartTime.ToUniversalTime().Ticks
        $metadata = Get-GuardMetadataSnapshot
        $currentSnapshot = [pscustomobject]@{
            Pid               = $guardPid
            ProcessStartTicks = [long]$actualStartTicks
            IdentityPresent   = [bool]$metadata.IdentityPresent
            IdentityText      = $metadata.IdentityText
            ReadyPresent      = [bool]$metadata.ReadyPresent
            ReadyText         = $metadata.ReadyText
        }

        $identityText = $null
        $readyText = $null
        $freshnessUtc = $validatedProcess.StartTime.ToUniversalTime()
        try {
            if (-not [bool]$metadata.IdentityPresent) {
                throw 'Guard identity metadata is absent.'
            }
            $candidateIdentityText = [string]$metadata.IdentityText
            $identityState = $candidateIdentityText | ConvertFrom-Json
            if (([int]$identityState.pid -eq $guardPid) -and
                ([long]$identityState.process_start_utc_ticks -eq
                    [long]$actualStartTicks)) {
                $identityText = $candidateIdentityText
                $freshnessUtc = [DateTime]::Parse(
                    [string]$identityState.created_utc,
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal -bor
                        [Globalization.DateTimeStyles]::AdjustToUniversal)
            }
        }
        catch {
        }

        try {
            if (-not [bool]$metadata.ReadyPresent) {
                throw 'Guard readiness metadata is absent.'
            }
            $candidateReadyText = [string]$metadata.ReadyText
            $readyState = $candidateReadyText | ConvertFrom-Json
            if (([int]$readyState.pid -eq $guardPid) -and
                ([long]$readyState.process_start_utc_ticks -eq
                    [long]$actualStartTicks)) {
                $readyText = $candidateReadyText
                $heartbeatProperty = $readyState.PSObject.Properties['heartbeat_utc']
                $readyProperty = $readyState.PSObject.Properties['ready_utc']
                $timestampText = if ($null -ne $heartbeatProperty) {
                    [string]$heartbeatProperty.Value
                }
                elseif ($null -ne $readyProperty) {
                    [string]$readyProperty.Value
                }
                else { $null }
                if (-not [string]::IsNullOrWhiteSpace($timestampText)) {
                    $freshnessUtc = [DateTime]::Parse(
                        $timestampText,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::AssumeUniversal -bor
                            [Globalization.DateTimeStyles]::AdjustToUniversal)
                }
                else {
                    $freshnessUtc = (Get-Item -LiteralPath $Script:ReadyPath).LastWriteTimeUtc
                }
            }
        }
        catch {
        }

        if (($null -eq $identityText) -and ($null -eq $readyText)) {
            return $false
        }

        $heartbeatAgeSeconds = ([DateTime]::UtcNow - $freshnessUtc).TotalSeconds
        $wallClockStale = ($heartbeatAgeSeconds -ge $MinimumHeartbeatAgeSeconds)
        $monotonicStale = (($null -ne $ExpectedSnapshot) -and
            ($ObservedUnchangedMilliseconds -ge
                ([long]$MinimumHeartbeatAgeSeconds * 1000)) -and
            (Test-GuardLivenessSnapshotEqual `
                -Left $ExpectedSnapshot -Right $currentSnapshot))

        # A future timestamp after a wall-clock rollback is not trusted as
        # either fresh or stale. The supervisor may still authorize recovery
        # after observing this exact process and exact metadata unchanged for
        # the full timeout on its monotonic Stopwatch.
        if ((-not $wallClockStale) -and (-not $monotonicStale)) {
            return $false
        }

        $validatedProcess.Refresh()
        if ($validatedProcess.HasExited -or
            ([long]$validatedProcess.StartTime.ToUniversalTime().Ticks -ne
                [long]$actualStartTicks)) {
            return $false
        }

        # Any metadata write or presence change since the first read proves
        # forward progress (or a race), so it cannot authorize termination.
        $latestMetadata = Get-GuardMetadataSnapshot
        $latestSnapshot = [pscustomobject]@{
            Pid               = $guardPid
            ProcessStartTicks = [long]$actualStartTicks
            IdentityPresent   = [bool]$latestMetadata.IdentityPresent
            IdentityText      = $latestMetadata.IdentityText
            ReadyPresent      = [bool]$latestMetadata.ReadyPresent
            ReadyText         = $latestMetadata.ReadyText
        }
        if (-not (Test-GuardLivenessSnapshotEqual `
                -Left $currentSnapshot -Right $latestSnapshot)) {
            return $false
        }

        # Kill through the already validated Process object instead of doing a
        # second numeric-PID lookup that could race PID reuse.
        $validatedProcess.Kill()
        if (-not $validatedProcess.WaitForExit(5000)) {
            Write-GuardLog ('Owned guard PID {0} did not confirm exit after Kill.' -f
                $guardPid)
            return $false
        }
        Write-GuardLog (('Stopped unresponsive guard PID {0}; heartbeat age={1:N1}s; ' +
                'metadata unchanged={2:N1}s.') -f
            $guardPid, $heartbeatAgeSeconds,
            ($ObservedUnchangedMilliseconds / 1000.0))
        return $true
    }
    catch {
        Write-GuardLog ('Stale guard recovery was not safe to perform: ' +
            $_.Exception.Message)
        return $false
    }
    finally {
        if ($null -ne $validatedProcess) {
            $validatedProcess.Dispose()
        }
    }
}

function Start-GuardProcess {
    param(
        [switch]$ForceAttempt,
        [switch]$FailClosed
    )

    if ((-not $ForceAttempt) -and (Test-GuardProcess)) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $Script:InstalledScript)) {
        throw 'Installed guard script is missing. Run Install again.'
    }
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Sta -File "{0}" Run' -f
        $Script:InstalledScript
    if ($FailClosed) {
        $arguments += ' -FailClosedStart'
    }
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $windowsPowerShell
    $startInfo.Arguments = $arguments
    $startInfo.WorkingDirectory = $Script:InstallRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.ErrorDialog = $false
    return [Diagnostics.Process]::Start($startInfo)
}

function Start-StartupSupervisorProcess {
    if (-not (Test-Path -LiteralPath $Script:StartupLauncher -PathType Leaf)) {
        throw 'The native startup supervisor launcher is missing. Run RepairStartup.'
    }
    if (-not (Test-WindowsGuiExecutable -Path $Script:StartupLauncher)) {
        throw 'The native startup supervisor launcher is invalid. Run RepairStartup.'
    }

    # Prefer a demand start through Task Scheduler. Its configured restart
    # policy then also protects the supervisor launched by Arm. Managed PCs
    # may forbid per-user tasks, so the same native launcher remains a full
    # non-admin fallback.
    $taskInfo = Get-StartupTaskInfo
    if ([bool]$taskInfo.Registered -and [bool]$taskInfo.Enabled -and
        [bool]$taskInfo.ActionMatches -and [bool]$taskInfo.TriggersMatch) {
        try {
            $service = New-Object -ComObject 'Schedule.Service'
            $service.Connect()
            $folder = $service.GetFolder('\')
            $task = $folder.GetTask('\' + $Script:StartupTaskName)
            $taskWaitClock = [Diagnostics.Stopwatch]::StartNew()
            while (([int]$task.State -eq 4) -and
                ($taskWaitClock.ElapsedMilliseconds -lt 5000)) {
                Start-Sleep -Milliseconds 250
                $task = $folder.GetTask('\' + $Script:StartupTaskName)
            }
            if ([int]$task.State -ne 4) {
                $null = $task.Run($null)
                [void](Write-GuardLog 'Startup supervisor demand-started by Task Scheduler.')
                return $null
            }
            [void](Write-GuardLog ('Scheduled startup task remained Running after its old ' +
                    'launcher exited; using direct supervisor fallback.'))
        }
        catch {
            [void](Write-GuardLog ('Scheduled supervisor demand start failed; using direct ' +
                    'fallback. ' + $_.Exception.Message))
        }
    }

    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Script:StartupLauncher
    $startInfo.Arguments = Get-StartupArguments
    $startInfo.WorkingDirectory = $Script:InstallRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $startInfo.ErrorDialog = $false
    return [Diagnostics.Process]::Start($startInfo)
}

function Invoke-StartupSupervisor {
    Assert-Windows
    Write-GuardLog ('Startup supervisor {0} invoked; fallback={1}.' -f
        $Script:GuardVersion, [bool]$StartupFallback)

    if (-not (Test-Path -LiteralPath $Script:ArmedPath)) {
        Write-StartupState -Status 'Disarmed' -Attempt 0 `
            -Message 'Startup did not run the guard because it is disarmed.'
        Write-GuardLog 'Startup supervisor exited because the guard is disarmed.'
        return
    }

    # The Run entry waits briefly so the scheduled task normally becomes the
    # single long-lived supervisor.  If policy blocked that task, HKCU Run then
    # takes over without requiring administrator access.
    if ($StartupFallback) {
        Start-Sleep -Seconds 12
        if ((Test-GuardReady) -and
            (-not (Test-StartupSupervisorMutexAvailable))) {
            Write-StartupState -Status 'Ready' -Attempt 0 `
                -Message 'The scheduled startup task started the guard.'
            return
        }
    }

    $supervisorMutexOwned = $false
    $supervisorMutex = New-Object Threading.Mutex(
        $false,
        $Script:StartupSupervisorMutexName)
    try {
        $supervisorMutexOwned = [bool]$supervisorMutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException] {
        $supervisorMutexOwned = $true
        Write-GuardLog 'Startup supervisor recovered abandoned supervision.'
    }
    if (-not $supervisorMutexOwned) {
        if ($StartupFallback) {
            $supervisorMutex.Dispose()
            Write-GuardLog 'A startup supervisor is already running.'
            return
        }

        # If HKCU Run won the race, keep the scheduled-task process as a quiet
        # standby.  It takes over only if the first supervisor exits or dies.
        Write-GuardLog 'Scheduled startup task is waiting behind another supervisor.'
        while (Test-Path -LiteralPath $Script:ArmedPath) {
            try {
                if ($supervisorMutex.WaitOne(5000)) {
                    $supervisorMutexOwned = $true
                    Write-GuardLog 'Scheduled startup task took over supervision.'
                    break
                }
            }
            catch [Threading.AbandonedMutexException] {
                $supervisorMutexOwned = $true
                Write-GuardLog 'Scheduled startup task recovered abandoned supervision.'
                break
            }
        }
        if (-not $supervisorMutexOwned) {
            $supervisorMutex.Dispose()
            return
        }
    }

    $attempt = 0
    $readyReported = $false
    $healthClock = [Diagnostics.Stopwatch]::StartNew()
    $lastSupervisorLoopMilliseconds = [long]$healthClock.ElapsedMilliseconds
    $lastSupervisorLoopUtc = [DateTime]::UtcNow
    $resumeRecoveryGraceUntilMilliseconds = [long]0
    $unhealthySnapshot = $null
    $unhealthySinceMilliseconds = [long]0
    $unhealthyObservationActive = $false
    try {
        while (Test-Path -LiteralPath $Script:ArmedPath) {
            $supervisorLoopMilliseconds = [long]$healthClock.ElapsedMilliseconds
            $supervisorLoopUtc = [DateTime]::UtcNow
            $supervisorLoopGapMilliseconds = [long][Math]::Max(
                [Math]::Max(
                    0,
                    ($supervisorLoopMilliseconds -
                        $lastSupervisorLoopMilliseconds)),
                [Math]::Max(
                    0,
                    ($supervisorLoopUtc - $lastSupervisorLoopUtc).TotalMilliseconds))
            $lastSupervisorLoopMilliseconds = $supervisorLoopMilliseconds
            $lastSupervisorLoopUtc = $supervisorLoopUtc
            if ($supervisorLoopGapMilliseconds -ge 5000) {
                # A pre-suspend unchanged-metadata observation cannot be used
                # to terminate a guard immediately after wake. Give its own
                # resume loop a full stale-heartbeat interval to recover.
                $unhealthySnapshot = $null
                $unhealthyObservationActive = $false
                $resumeRecoveryGraceUntilMilliseconds =
                    $supervisorLoopMilliseconds + 20000
                Write-GuardLog (('Supervisor detected an execution gap of {0:N1}s; ' +
                        'resume recovery grace restarted.') -f
                    ($supervisorLoopGapMilliseconds / 1000.0))
            }

            if (Test-GuardReady) {
                $unhealthySnapshot = $null
                $unhealthyObservationActive = $false
                $resumeRecoveryGraceUntilMilliseconds = [long]0
                if (-not $readyReported) {
                    Write-StartupState -Status 'Ready' -Attempt $attempt `
                        -Message 'Guard process is ready; supervisor is monitoring it.'
                    $readyReported = $true
                }
                Start-Sleep -Seconds 3
                continue
            }

            $readyReported = $false
            if (Test-GuardProcess) {
                $healthNow = [long]$healthClock.ElapsedMilliseconds
                $currentSnapshot = Get-GuardLivenessSnapshot
                if ($null -eq $currentSnapshot) {
                    if (-not $unhealthyObservationActive) {
                        $unhealthyObservationActive = $true
                        $unhealthySinceMilliseconds = $healthNow
                        Write-StartupState -Status 'Recovering' -Attempt $attempt `
                            -Message 'Guard is live but its exact identity is unavailable; waiting safely.'
                        Write-GuardLog ('Guard heartbeat is stale, but exact process identity ' +
                            'is unavailable; recovery is waiting safely.')
                    }
                    $unhealthySnapshot = $null
                    Start-Sleep -Seconds 3
                    continue
                }

                if ((-not $unhealthyObservationActive) -or
                    ($null -eq $unhealthySnapshot) -or
                    (-not (Test-GuardLivenessSnapshotEqual `
                            -Left $unhealthySnapshot -Right $currentSnapshot))) {
                    $unhealthyObservationActive = $true
                    $unhealthySnapshot = $currentSnapshot
                    $unhealthySinceMilliseconds = $healthNow
                    Write-StartupState -Status 'Recovering' -Attempt $attempt `
                        -Message 'Guard heartbeat is stale; allowing brief resume recovery grace.'
                    Write-GuardLog 'Guard heartbeat became stale; brief recovery grace started.'
                    Start-Sleep -Seconds 3
                    continue
                }

                $observedUnchangedMilliseconds = [long][Math]::Max(
                    0,
                    ($healthNow - $unhealthySinceMilliseconds))
                if ($observedUnchangedMilliseconds -lt 3000) {
                    Start-Sleep -Seconds 2
                    continue
                }
                if ($healthNow -lt $resumeRecoveryGraceUntilMilliseconds) {
                    Start-Sleep -Seconds 2
                    continue
                }
                if (Stop-StaleGuardProcess -MinimumHeartbeatAgeSeconds 20 `
                        -ExpectedSnapshot $unhealthySnapshot `
                        -ObservedUnchangedMilliseconds $observedUnchangedMilliseconds) {
                    $unhealthySnapshot = $null
                    $unhealthyObservationActive = $false
                    continue
                }
                # Never launch a competing child while an exact, still-live
                # guard identity exists. Recheck until its heartbeat reaches
                # the safe termination threshold or it recovers.
                Start-Sleep -Seconds 2
                continue
            }
            else {
                $unhealthySnapshot = $null
                $unhealthyObservationActive = $false
            }

            $attempt++
            Write-StartupState -Status 'Starting' -Attempt $attempt `
                -Message 'Launching the hidden guard process.'
            Write-GuardLog ('Startup supervisor launch attempt {0}.' -f $attempt)

            # Ignore an unverified stale PID file.  The guard's named mutex
            # prevents duplicate active monitors if another process is real.
            try {
                $child = Start-GuardProcess -ForceAttempt -FailClosed
                # Hold the exact kernel process identity for timeout handling;
                # never re-resolve this child by numeric PID.
                $null = $child.Handle
            }
            catch {
                $detail = 'Guard process could not be launched: ' + $_.Exception.Message
                Write-StartupState -Status 'Retrying' -Attempt $attempt -Message $detail
                Write-GuardLog ('Startup launch attempt {0} failed: {1}' -f
                    $attempt, $detail)
                Start-Sleep -Seconds ([Math]::Min(30, 4 + ($attempt * 2)))
                continue
            }
            $initializationClock = [Diagnostics.Stopwatch]::StartNew()
            while ((Test-Path -LiteralPath $Script:ArmedPath) -and
                ($initializationClock.ElapsedMilliseconds -lt 45000)) {
                if (Test-GuardReady) {
                    break
                }
                try {
                    $child.Refresh()
                    if ($child.HasExited) {
                        break
                    }
                }
                catch {
                    break
                }
                Start-Sleep -Milliseconds 250
            }

            if (Test-GuardReady) {
                Write-GuardLog ('Startup launch attempt {0} became ready.' -f $attempt)
                $child.Dispose()
                continue
            }
            if (-not (Test-Path -LiteralPath $Script:ArmedPath)) {
                # The child may already hold the native blocker but may not
                # yet have published readiness. Stop this exact cached process
                # before returning from a disarm request.
                try {
                    $child.Refresh()
                    if (-not $child.HasExited) {
                        $child.Kill()
                        if (-not $child.WaitForExit(5000)) {
                            Write-GuardLog ('Disarm could not confirm exit of the ' +
                                'initializing guard child.')
                        }
                    }
                }
                catch {
                    Write-GuardLog ('Disarm cleanup of the initializing guard child ' +
                        'reported: ' + $_.Exception.Message)
                }
                $child.Dispose()
                break
            }

            $detail = 'Guard exited before its readiness handshake.'
            $childExitConfirmed = $false
            try {
                $child.Refresh()
                if (-not $child.HasExited) {
                    # A fail-closed child can already be blocking input. Kill
                    # the exact cached process so its safety job closes too.
                    $child.Kill()
                    if ($child.WaitForExit(5000)) {
                        $detail = 'Guard initialization timed out and was stopped.'
                        $childExitConfirmed = $true
                    }
                    else {
                        $detail = 'Guard initialization timed out; exit was not confirmed.'
                    }
                }
                else {
                    $detail += ' Exit code=' + [string]$child.ExitCode + '.'
                    $childExitConfirmed = $true
                }
            }
            catch {
                $detail += ' ' + $_.Exception.Message
            }
            $child.Dispose()
            Write-StartupState -Status 'Retrying' -Attempt $attempt -Message $detail
            Write-GuardLog ('Startup launch attempt {0} failed: {1}' -f $attempt, $detail)
            if ($childExitConfirmed) {
                # Every child that reached initialization may already have
                # held the fail-closed blocker. Retry promptly after its exact
                # exit, with a floor that avoids a hot process-spawn loop on a
                # persistent pre-block initialization failure.
                Start-Sleep -Seconds 1
            }
            else {
                Start-Sleep -Seconds ([Math]::Min(30, 4 + ($attempt * 2)))
            }
        }

        Write-StartupState -Status 'Disarmed' -Attempt $attempt `
            -Message 'Startup supervisor stopped because the guard was disarmed.'
        Write-GuardLog 'Startup supervisor stopped because the guard was disarmed.'
    }
    finally {
        if ($supervisorMutexOwned) {
            $supervisorMutex.ReleaseMutex()
        }
        $supervisorMutex.Dispose()
    }
}

function Test-BleNearNow {
    param(
        [Parameter(Mandatory = $true)]$Config,
        [ValidateRange(3, 30)][int]$Seconds = 10
    )

    Initialize-BleWatcherBridge
    $guid = ConvertTo-TargetGuid -Value ([string]$Config.service_uuid)
    $bridge = New-BleWatcherBridge -TargetUuid $guid
    $bestRssi = -127
    try {
        $bridge.Start()
        $scanClock = [Diagnostics.Stopwatch]::StartNew()
        while ($scanClock.ElapsedMilliseconds -lt ([long]$Seconds * 1000)) {
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
    $bridge = New-BleWatcherBridge -TargetUuid $guid
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
    Assert-InputHookHelper -Path $Script:InputHookHelper
    $nativeMethods = $Script:NativeMethodsType

    if (-not (Test-Path -LiteralPath $Script:ArmedPath)) {
        return
    }

    $guardMutexOwned = $false
    $mutex = New-Object Threading.Mutex(
        $false,
        $Script:GuardMutexName)
    try {
        $guardMutexOwned = [bool]$mutex.WaitOne(0)
    }
    catch [Threading.AbandonedMutexException] {
        # WaitOne grants ownership when it reports abandonment.
        $guardMutexOwned = $true
    }
    if (-not $guardMutexOwned) {
        $mutex.Dispose()
        return
    }

    # A ready file belongs only to the process that currently owns the mutex.
    Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue

    $config = $null
    $bridge = $null
    $banner = $null
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $presence = $null
    $powerState = $null
    $activeWifi = @()
    $excludedWifi = $null
    $nextWifiPoll = [long]0
    $nextStateWrite = [long]0
    $nextWatcherHealthCheck = [long]0
    $nextWatcherRestartAttempt = [long]0
    $pendingWatcherRecoveryReason = $null
    $watcherRecoveryEpisodeActive = $false
    $watcherRestartCount = 0
    $lastWatcherRestartReason = $null
    $watcherStatus = 'Initializing'
    $lastLoopUtc = [DateTime]::UtcNow
    $lastLoopMonotonicMilliseconds = [long]$nativeMethods::GetMonotonicMilliseconds()
    $lastBlockAssert = [long]-10000
    $lastBlockFailureLog = [long]-10000
    $lastReleaseFailureLog = [long]-10000
    $inputBlocked = $false
    $rescueActive = $false
    $lastEffectiveBlock = $null
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue

    try {
        $currentProcess = Get-Process -Id $PID -ErrorAction Stop
        $processStartTicks = $currentProcess.StartTime.ToUniversalTime().Ticks

        # Establish an exact, recoverable process identity before this child
        # can block input. Disarm and the supervisor can then always stop the
        # correct process even if later initialization hangs.
        if (-not (Write-GuardIdentityState -ProcessStartTicks $processStartTicks)) {
            throw 'The guard could not create its immutable process identity.'
        }
        $PID | Set-Content -LiteralPath $Script:PidPath -Encoding ASCII

        # Every armed Run is fail-closed. FailClosedStart remains accepted for
        # compatibility with existing launchers, but safety must not depend on
        # a caller remembering the switch.
        $blockedNow = $nativeMethods::StartInputBlocker(
            $Script:InputHookHelper)
        if ($blockedNow) {
            $inputBlocked = $true
        }
        else {
            $blockFailure = (('Native input helper failed during fail-closed ' +
                    'startup while {0}; error {1}.') -f
                $nativeMethods::GetBlockerStage(),
                $nativeMethods::GetBlockerError())
            Write-GuardLog $blockFailure
            $null = $nativeMethods::StopInputBlocker()
            throw ($blockFailure + ' Refusing to report the guard ready.')
        }
        $lastBlockAssert = [long]$clock.ElapsedMilliseconds
        if ($inputBlocked) {
            Show-GuardBanner -Banner $banner
        }
        $null = $nativeMethods::SetKeepAwake($true)

        if (-not (Write-GuardReadyState -ProcessStartTicks $processStartTicks `
                -WatcherStatus $watcherStatus `
                -WatcherRestartCount $watcherRestartCount `
                -WatcherRestartReason $lastWatcherRestartReason `
                -Initialized $false)) {
            throw 'The guard could not create its initialization heartbeat.'
        }

        Initialize-BleWatcherBridge
        $config = Get-GuardConfig
        $guid = ConvertTo-TargetGuid -Value ([string]$config.service_uuid)
        $bridge = New-BleWatcherBridge -TargetUuid $guid
        $banner = New-GuardBanner -Text ([string]$config.banner_text)
        $presence = New-PresenceState
        $presence.Near = $false
        $presence.Reason = 'fail-closed startup'
        $initialAC = $nativeMethods::GetACLineStatus()
        $powerState = @{
            StableAC       = $initialAC
            CandidateAC    = $initialAC
            CandidateSince = [long]0
            SawDisconnect  = $false
            ReconnectTimes = @()
        }

        Write-GuardLog ('BLE guard {0} started. UUID={1}; lock={2}; unlock={3}; absence={4}s.' -f
            $Script:GuardVersion, $config.service_uuid, $config.lock_rssi_dbm,
            $config.unlock_rssi_dbm, $config.absence_seconds)

        try {
            $bridge.Start()
            $watcherStatus = [string]$bridge.Status
        }
        catch {
            # A radio/WinRT startup failure is a recoverable FAR state. Keep
            # this process alive so charger rescue remains available while the
            # normal watcher-restart loop repairs Bluetooth.
            $watcherStatus = 'Error'
            $pendingWatcherRecoveryReason = 'initial watcher start error: ' +
                $_.Exception.Message
            $lastWatcherRestartReason = $pendingWatcherRecoveryReason
            $watcherRecoveryEpisodeActive = $true
            $presence.Near = $false
            $presence.Reason = 'BLE watcher recovering'
            $presence.RecentRssi.Clear()
            if (-not $inputBlocked) {
                $blockedNow = $nativeMethods::StartInputBlocker(
                    $Script:InputHookHelper)
                if ($blockedNow) {
                    $inputBlocked = $true
                }
                else {
                    $blockFailure = (('Native input helper failed after BLE startup ' +
                            'error while {0}; error {1}.') -f
                        $nativeMethods::GetBlockerStage(),
                        $nativeMethods::GetBlockerError())
                    Write-GuardLog $blockFailure
                    $null = $nativeMethods::StopInputBlocker()
                    throw ($blockFailure + ' Restarting the supervised guard.')
                }
                $lastBlockAssert = [long]$clock.ElapsedMilliseconds
            }
            if ($inputBlocked) {
                Show-GuardBanner -Banner $banner
            }
            $null = $nativeMethods::SetKeepAwake($true)
            Write-GuardLog $pendingWatcherRecoveryReason
        }
        if (-not (Write-GuardReadyState -ProcessStartTicks $processStartTicks `
                -WatcherStatus $watcherStatus `
                -WatcherRestartCount $watcherRestartCount `
                -WatcherRestartReason $lastWatcherRestartReason)) {
            throw 'The guard could not create its readiness heartbeat.'
        }
        while ((Test-Path -LiteralPath $Script:ArmedPath) -and
            -not (Test-Path -LiteralPath $Script:StopPath)) {
            $now = [long]$clock.ElapsedMilliseconds
            $loopUtc = [DateTime]::UtcNow
            $loopMonotonicMilliseconds = [long]$nativeMethods::GetMonotonicMilliseconds()
            $utcLoopGapMilliseconds = [long][Math]::Max(
                0,
                ($loopUtc - $lastLoopUtc).TotalMilliseconds)
            $monotonicLoopGapMilliseconds = [long][Math]::Max(
                0,
                ($loopMonotonicMilliseconds - $lastLoopMonotonicMilliseconds))
            $loopGapMilliseconds = [long][Math]::Max(
                $utcLoopGapMilliseconds,
                $monotonicLoopGapMilliseconds)
            $lastLoopUtc = $loopUtc
            $lastLoopMonotonicMilliseconds = $loopMonotonicMilliseconds

            # WinRT automatically stops BLE advertisement watchers when an app
            # is suspended.  Recreate the watcher after a long execution gap
            # even if an adapter incorrectly continues to report Started.
            $watcherRecoveryReason = $null
            $resumeGapDetected = $false
            if ($loopGapMilliseconds -ge 5000) {
                $resumeGapDetected = $true
                $watcherRecoveryReason = ('execution gap of {0:N1} seconds' -f
                    ($loopGapMilliseconds / 1000.0))
            }

            if (($null -eq $watcherRecoveryReason) -and
                ($now -ge $nextWatcherHealthCheck)) {
                try {
                    $watcherStatus = [string]$bridge.Status
                    if (-not [string]::Equals(
                            $watcherStatus,
                            'Started',
                            [StringComparison]::OrdinalIgnoreCase)) {
                        $watcherRecoveryReason = 'watcher status ' + $watcherStatus
                    }
                }
                catch {
                    $watcherStatus = 'Error'
                    $watcherRecoveryReason = 'watcher status error: ' +
                        $_.Exception.Message
                }
                $nextWatcherHealthCheck = $now + 1000
            }

            $recoveryJustStarted = $false
            if ($null -ne $watcherRecoveryReason) {
                # Every suspend/resume gap is a new trust boundary even if a
                # previous watcher-recovery attempt was already pending.
                $recoveryJustStarted = (($null -eq $pendingWatcherRecoveryReason) -or
                    $resumeGapDetected)
                $pendingWatcherRecoveryReason = $watcherRecoveryReason
            }

            if ($null -ne $pendingWatcherRecoveryReason) {
                # Until a fresh strong advertisement arrives, an interrupted
                # scanner must not leave the previous NEAR decision trusted.
                $presence.Near = $false
                $presence.Reason = 'BLE watcher recovering'
                $presence.RecentRssi.Clear()
            }

            if ($recoveryJustStarted) {
                if (-not $watcherRecoveryEpisodeActive) {
                    # Discard charger edges from before suspend once, but keep
                    # all new edges across slow or repeated BLE restart attempts.
                    Reset-PowerRescueState -State $powerState -NowMilliseconds $now
                    $watcherRecoveryEpisodeActive = $true
                }

                # Stale pre-suspend network state cannot be used as an
                # exclusion. Assert the blocker before any WinRT restart or
                # Wi-Fi query can stall; a fresh strong advertisement or a
                # freshly detected exclusion Wi-Fi will release it below.
                $activeWifi = @()
                $excludedWifi = $null
                $nextWifiPoll = [long]0
                if (-not $rescueActive) {
                    # Revalidate the already job-contained helper
                    # unconditionally. If it exited during suspend, this call
                    # starts a replacement and confirms it remains running.
                    $blockedNow = $nativeMethods::StartInputBlocker(
                        $Script:InputHookHelper)
                    if ($blockedNow) {
                        $inputBlocked = $true
                    }
                    else {
                        $blockFailure = (('Native input helper failed during BLE ' +
                                'recovery while {0}; error {1}.') -f
                            $nativeMethods::GetBlockerStage(),
                            $nativeMethods::GetBlockerError())
                        if (($now - $lastBlockFailureLog) -ge 5000) {
                            Write-GuardLog $blockFailure
                            $lastBlockFailureLog = $now
                        }
                        $null = $nativeMethods::StopInputBlocker()
                        throw ($blockFailure + ' Restarting the supervised guard.')
                    }
                    $lastBlockAssert = $now
                    if ($inputBlocked) {
                        Show-GuardBanner -Banner $banner
                    }
                    $null = $nativeMethods::SetKeepAwake($true)
                }

                # Publish fail-closed progress before any WinRT restart or
                # network probe. A pre-sleep heartbeat may already be stale;
                # without this write the supervisor could kill a healthy
                # recovery iteration and briefly release the helper job.
                $watcherStatus = 'Recovering'
                [void](Write-GuardReadyState `
                    -ProcessStartTicks $processStartTicks `
                    -WatcherStatus $watcherStatus `
                    -WatcherRestartCount $watcherRestartCount `
                    -WatcherRestartReason $pendingWatcherRecoveryReason)
            }

            if (($null -ne $pendingWatcherRecoveryReason) -and
                ($now -ge $nextWatcherRestartAttempt)) {
                $restartReason = [string]$pendingWatcherRecoveryReason
                try {
                    $bridge.Restart()
                    $watcherStatus = [string]$bridge.Status
                    $watcherRestartCount++
                    $lastWatcherRestartReason = $restartReason
                    Write-GuardLog ('BLE watcher recovery {0}: {1}; status={2}.' -f
                        $watcherRestartCount,
                        $restartReason,
                        $watcherStatus)
                    $nextWatcherRestartAttempt = $now + 5000
                    $pendingWatcherRecoveryReason = $null
                }
                catch {
                    $watcherStatus = 'Error'
                    $lastWatcherRestartReason = $restartReason
                    Write-GuardLog ('BLE watcher recovery failed: {0}' -f
                        $_.Exception.Message)
                    $nextWatcherRestartAttempt = $now + 5000
                }
            }

            $drainedSamples = @($bridge.Drain())
            if ($null -eq $pendingWatcherRecoveryReason) {
                foreach ($sample in $drainedSamples) {
                    Add-PresenceSample -State $presence -Config $config `
                        -Rssi ([int]$sample.Rssi) -NowMilliseconds $now
                }
            }
            Update-PresenceTimeout -State $presence -Config $config -NowMilliseconds $now

            if ($now -ge $nextWifiPoll) {
                $activeWifi = @(Get-ActiveWifiNames)
                $excludedWifi = Get-ExcludedWifiMatch -Config $config -ActiveNames $activeWifi
                $nextWifiPoll = $now + [long]$config.wifi_poll_milliseconds
            }

            if ($watcherRecoveryEpisodeActive -and
                ((($null -ne $presence.Near) -and [bool]$presence.Near) -or
                    ($null -ne $excludedWifi))) {
                $watcherRecoveryEpisodeActive = $false
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
                    $blockedNow = $nativeMethods::StartInputBlocker(
                        $Script:InputHookHelper)
                    if ($blockedNow) {
                        $inputBlocked = $true
                    }
                    else {
                        if (($now - $lastBlockFailureLog) -ge 5000) {
                            Write-GuardLog ('Native input helper failed while {0}; error {1}.' -f
                                $nativeMethods::GetBlockerStage(),
                                $nativeMethods::GetBlockerError())
                            $lastBlockFailureLog = $now
                        }
                        # A failed start can occur after the helper process was created.
                        # Stop it immediately so an unconfirmed helper never runs silently.
                        $failedStartReleased = [bool]$nativeMethods::StopInputBlocker()
                        # Conservatively treat an unconfirmed helper as blocking.
                        # This keeps the banner visible and retries release.
                        $inputBlocked = -not $failedStartReleased
                    }
                    $lastBlockAssert = $now
                }
                if ($inputBlocked) {
                    Show-GuardBanner -Banner $banner
                }
                else {
                    Hide-GuardBanner -Banner $banner
                }
                $null = $nativeMethods::SetKeepAwake($true)
            }
            else {
                if ($inputBlocked) {
                    $releaseConfirmed = [bool]$nativeMethods::StopInputBlocker()
                    if ($releaseConfirmed) {
                        $inputBlocked = $false
                    }
                    elseif (($now - $lastReleaseFailureLog) -ge 5000) {
                        Write-GuardLog ('Input release remains pending while {0}; error {1}.' -f
                            $nativeMethods::GetBlockerStage(),
                            $nativeMethods::GetBlockerError())
                        $lastReleaseFailureLog = $now
                    }
                }

                if ($inputBlocked) {
                    Show-GuardBanner -Banner $banner
                    $null = $nativeMethods::SetKeepAwake($true)
                }
                else {
                    Hide-GuardBanner -Banner $banner
                    $null = $nativeMethods::SetKeepAwake($false)
                }
            }

            $effectiveBlock = [bool]$shouldBlock -or [bool]$inputBlocked
            if (($null -eq $lastEffectiveBlock) -or
                ([bool]$effectiveBlock -ne [bool]$lastEffectiveBlock)) {
                if ($effectiveBlock) {
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
                $lastEffectiveBlock = $effectiveBlock
            }

            if ($now -ge $nextStateWrite) {
                Write-GuardState -Config $config -Presence $presence -NowMilliseconds $now `
                    -ExcludedWifi $excludedWifi -InputBlocked $inputBlocked `
                    -RescueActive $rescueActive -WatcherStatus $watcherStatus `
                    -WatcherRestartCount $watcherRestartCount `
                    -WatcherRestartReason $lastWatcherRestartReason
                [void](Write-GuardReadyState `
                    -ProcessStartTicks $processStartTicks `
                    -WatcherStatus $watcherStatus `
                    -WatcherRestartCount $watcherRestartCount `
                    -WatcherRestartReason $lastWatcherRestartReason)
                $nextStateWrite = $now + 1000
            }

            if ($null -ne $banner) {
                try {
                    [System.Windows.Forms.Application]::DoEvents()
                }
                catch {
                    Write-GuardLog ('Lock banner event pump was disabled: ' +
                        $_.Exception.Message)
                    Close-GuardBanner -Banner $banner
                    $banner = $null
                }
            }
            [Threading.Thread]::Sleep([int]$config.poll_milliseconds)
        }
    }
    catch {
        Write-GuardLog ('Guard stopped by error: ' + $_.Exception.ToString())
        throw
    }
    finally {
        $releaseConfirmed = [bool]$nativeMethods::StopInputBlocker()
        $null = $nativeMethods::SetKeepAwake($false)
        Close-GuardBanner -Banner $banner
        if ($null -ne $bridge) {
            $bridge.Dispose()
        }
        try {
            if ((Test-Path -LiteralPath $Script:PidPath) -and
                ([int](Get-Content -LiteralPath $Script:PidPath -Raw) -eq $PID)) {
                Remove-Item -LiteralPath $Script:PidPath -Force
            }
            if (Test-Path -LiteralPath $Script:IdentityPath) {
                $ownedIdentity = Get-Content -LiteralPath $Script:IdentityPath -Raw |
                    ConvertFrom-Json
                if ([int]$ownedIdentity.pid -eq $PID) {
                    Remove-Item -LiteralPath $Script:IdentityPath -Force
                }
            }
        }
        catch {
        }
        Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($Script:IdentityPath + '.tmp') -Force -ErrorAction SilentlyContinue
        if ($guardMutexOwned) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
        if ($releaseConfirmed) {
            Write-GuardLog 'Guard stopped; input release confirmed.'
        }
        else {
            Write-GuardLog (('Guard stopped; helper release was not confirmed while {0}; error {1}. ' +
                'Process exit will close the safety job.') -f
                $nativeMethods::GetBlockerStage(),
                $nativeMethods::GetBlockerError())
        }
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
    $sourceHelperPath = Join-Path (Split-Path -Parent $sourcePath) 'windows-input-hook-helper.exe'
    Assert-InputHookHelper -Path $sourceHelperPath
    if (-not [string]::Equals($sourcePath, $destinationPath, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $sourcePath -Destination $destinationPath -Force
    }
    $helperDestinationPath = [IO.Path]::GetFullPath($Script:InputHookHelper)
    if (-not [string]::Equals(
            ([IO.Path]::GetFullPath($sourceHelperPath)),
            $helperDestinationPath,
            [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $sourceHelperPath -Destination $helperDestinationPath -Force
    }
    Unblock-File -LiteralPath $destinationPath -ErrorAction SilentlyContinue
    Unblock-File -LiteralPath $helperDestinationPath -ErrorAction SilentlyContinue
    Assert-InputHookHelper -Path $helperDestinationPath
    $config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Script:ConfigPath -Encoding UTF8

    $startupInstall = Install-StartupLaunchers

    Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue

    Write-Host 'Installed for the current user without administrator access.' -ForegroundColor Green
    Write-Host ('Installed script: ' + $Script:InstalledScript)
    Write-Host ('Native input helper: ' + $Script:InputHookHelper)
    if ([bool]$startupInstall.RunUsable) {
        Write-Host 'HKCU Run startup fallback: installed and enabled.'
    }
    else {
        Write-Warning ('HKCU Run startup fallback was unavailable. ' +
            [string]$startupInstall.RunError + ' ' +
            [string]$startupInstall.ApprovalError)
    }
    if ([bool]$startupInstall.TaskInstalled) {
        Write-Host 'Per-user scheduled startup task: installed (limited, interactive token).'
    }
    else {
        Write-Warning ('Scheduled startup task was unavailable. ' +
            [string]$startupInstall.TaskError)
    }
    Write-Host 'The startup entry is installed, but the guard is deliberately DISARMED.' -ForegroundColor Yellow
    Write-Host 'Run Observe, then SelfTest, and finally Arm.'
}

function Repair-GuardStartup {
    Assert-Windows
    [void](Get-GuardConfig)
    $startupInstall = Install-StartupLaunchers
    if ([bool]$startupInstall.RunUsable) {
        Write-Host 'The current-user HKCU Run fallback was repaired.' -ForegroundColor Green
    }
    else {
        Write-Warning ('HKCU Run fallback was unavailable. ' +
            [string]$startupInstall.RunError + ' ' +
            [string]$startupInstall.ApprovalError)
    }
    if ([bool]$startupInstall.TaskInstalled) {
        Write-Host 'The limited per-user scheduled startup task was installed.' -ForegroundColor Green
    }
    else {
        Write-Warning ('Scheduled startup task was unavailable. ' +
            [string]$startupInstall.TaskError)
    }
}

function Invoke-SelfTest {
    Assert-Windows
    Initialize-NativeMethods
    Assert-InputHookHelper -Path $Script:InputHookHelper
    $nativeMethods = $Script:NativeMethodsType
    $blocked = $false
    $testError = $null
    try {
        $blocked = $nativeMethods::StartInputBlocker(
            $Script:InputHookHelper)
        if (-not $blocked) {
            throw ('Native input helper failed while {0}; error {1}.' -f
                $nativeMethods::GetBlockerStage(),
                $nativeMethods::GetBlockerError())
        }
        Start-Sleep -Milliseconds 250
    }
    catch {
        $testError = $_
    }

    $releaseConfirmed = $nativeMethods::StopInputBlocker()
    if (-not $releaseConfirmed) {
        throw (('Native input helper release could not be confirmed while {0}; error {1}. ' +
            'The helper remains tracked so release can be retried.') -f
            $nativeMethods::GetBlockerStage(),
            $nativeMethods::GetBlockerError())
    }
    if ($null -ne $testError) {
        throw $testError
    }
    Write-Host 'Native non-admin input-hook self-test passed; input was released.' -ForegroundColor Green
}

function Arm-Guard {
    Assert-Windows
    Initialize-NativeMethods
    $config = Get-GuardConfig
    $null = Install-StartupLaunchers

    if ((Test-Path -LiteralPath $Script:ArmedPath) -and (Test-GuardReady)) {
        if (Test-StartupSupervisorMutexAvailable) {
            $null = Start-StartupSupervisorProcess
            $supervisorWaitClock = [Diagnostics.Stopwatch]::StartNew()
            while ((Test-StartupSupervisorMutexAvailable) -and
                ($supervisorWaitClock.ElapsedMilliseconds -lt 10000)) {
                Start-Sleep -Milliseconds 200
            }
            if (Test-StartupSupervisorMutexAvailable) {
                throw ('The guard is ready, but its startup supervisor could not be ' +
                    'restored. Run RepairStartup, then retry Arm.')
            }
        }
        Write-Host 'BLE Phone Input Guard is already armed and ready.' -ForegroundColor Green
        return
    }

    # A failed or interrupted previous run can leave the armed marker behind.
    # Clear it before preflight so a failed Arm never reports Armed=True while
    # no process exists, and so any old supervisor exits before replacement.
    Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue

    # Do not race a stale or partially initialized hidden process. Stop it
    # before performing a fresh preflight and startup handshake.
    if (Test-GuardProcess) {
        New-Item -ItemType File -Path $Script:StopPath -Force | Out-Null
        $oldProcessWaitClock = [Diagnostics.Stopwatch]::StartNew()
        while ((Test-GuardProcess) -and
            ($oldProcessWaitClock.ElapsedMilliseconds -lt 6000)) {
            Start-Sleep -Milliseconds 200
        }
        if (Test-GuardProcess) {
            if (-not (Stop-OwnedGuardProcess)) {
                throw ('An earlier owned guard process could not be stopped safely. ' +
                    'The guard remains disarmed; retry Disarm.')
            }
        }
        Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
    }

    if (-not (Wait-StartupLaunchersExit -Seconds 45)) {
        throw ('An earlier startup supervisor is still stopping. The guard remains ' +
            'disarmed; wait a few seconds, then retry Arm.')
    }
    if (-not (Test-GuardProcess)) {
        Remove-Item -LiteralPath $Script:PidPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:IdentityPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($Script:IdentityPath + '.tmp') -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue
    }

    # Sample exclusions only after all old processes have stopped. A network
    # seen before that wait may no longer be connected when the new guard starts.
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

    Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
    New-Item -ItemType File -Path $Script:ArmedPath -Force | Out-Null

    $startedProcess = $null
    try {
        # Arm the long-lived supervisor immediately instead of starting one
        # unsupervised guard child.  Recovery therefore works now, not only
        # after the next sign-in.
        $startedProcess = Start-StartupSupervisorProcess
    }
    catch {
        Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
        throw
    }

    $ready = $false
    $readyWaitClock = [Diagnostics.Stopwatch]::StartNew()
    while ($readyWaitClock.ElapsedMilliseconds -lt 45000) {
        if (Test-GuardReady) {
            # Require the ready signal and process to remain valid briefly.
            Start-Sleep -Milliseconds 400
            if (Test-GuardReady) {
                $ready = $true
                break
            }
        }
        if ($null -ne $startedProcess) {
            try {
                $startedProcess.Refresh()
                if ($startedProcess.HasExited) {
                    break
                }
            }
            catch {
                break
            }
        }
        Start-Sleep -Milliseconds 200
    }

    if (-not $ready) {
        # Roll back the armed flag first.  A process still compiling the
        # bridges will then return before it can enter the monitoring loop.
        Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
        New-Item -ItemType File -Path $Script:StopPath -Force | Out-Null
        $stopWaitClock = [Diagnostics.Stopwatch]::StartNew()
        while ((Test-GuardProcess) -and
            ($stopWaitClock.ElapsedMilliseconds -lt 6000)) {
            Start-Sleep -Milliseconds 200
        }
        $stillRunning = Test-GuardProcess
        if ($stillRunning -and (Stop-OwnedGuardProcess)) {
            $stillRunning = $false
        }
        if (-not $stillRunning) {
            Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Script:PidPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Script:IdentityPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath ($Script:IdentityPath + '.tmp') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue
        }
        if ($stillRunning) {
            throw ('The guard did not become ready within 45 seconds. It is disarmed and a stop ' +
                'was requested; check windows-ble-guard.log before retrying.')
        }
        throw 'The guard did not become ready within 45 seconds and was stopped. Check windows-ble-guard.log.'
    }
    Write-Host ('BLE Phone Input Guard is armed, supervised, and will recover ' +
        'automatically after sign-in, unlock, or system resume.') -ForegroundColor Green
}

function Disarm-Guard {
    Assert-Windows
    Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Script:InstallRoot)) {
        Write-Host 'The guard is not installed.'
        return
    }
    New-Item -ItemType File -Path $Script:StopPath -Force | Out-Null
    $stopWaitClock = [Diagnostics.Stopwatch]::StartNew()
    while ((Test-GuardProcess) -and
        ($stopWaitClock.ElapsedMilliseconds -lt 6000)) {
        Start-Sleep -Milliseconds 200
    }
    if (Test-GuardProcess) {
        if (Stop-OwnedGuardProcess) {
            Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Script:PidPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Script:IdentityPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath ($Script:IdentityPath + '.tmp') -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue
            Write-Host 'BLE Phone Input Guard was force-stopped safely; input is released.' -ForegroundColor Green
        }
        else {
            Write-Warning ('The owned guard process could not be stopped safely. ' +
                'Use the charger rescue if input remains blocked.')
        }
    }
    else {
        Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:PidPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:IdentityPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($Script:IdentityPath + '.tmp') -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue
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
    $expectedStartupValue = Get-StartupRunCommand
    $runEntryStatus = if ($null -eq $startupValue) {
        'Missing'
    }
    elseif ([string]::Equals(
            [string]$startupValue,
            $expectedStartupValue,
            [StringComparison]::Ordinal)) {
        'Installed'
    }
    else {
        'Outdated or changed'
    }
    $startupTask = Get-StartupTaskInfo
    $startupState = $null
    if (Test-Path -LiteralPath $Script:StartupStatePath) {
        try {
            $startupState = Get-Content -LiteralPath $Script:StartupStatePath -Raw |
                ConvertFrom-Json
        }
        catch {
        }
    }

    $config = if ($installed) { Get-GuardConfig } else { $null }
    $activeWifi = @(Get-ActiveWifiNames)
    $excludedWifi = if ($installed) {
        Get-ExcludedWifiMatch -Config $config -ActiveNames $activeWifi
    }
    else {
        $null
    }
    $heartbeatAge = Get-GuardHeartbeatAgeSeconds

    [pscustomobject][ordered]@{
        Version             = $Script:GuardVersion
        Installed           = $installed
        Armed               = Test-Path -LiteralPath $Script:ArmedPath
        ProcessRunning      = Test-GuardProcess
        ProcessReady        = Test-GuardReady
        StartupEntry        = $runEntryStatus
        StartupRunApproval  = Get-RunStartupApproval
        StartupTask         = if ([bool]$startupTask.Registered) {
            if (-not [bool]$startupTask.ActionMatches) { 'Outdated action' }
            elseif (-not [bool]$startupTask.TriggersMatch) { 'Outdated recovery triggers' }
            elseif ([bool]$startupTask.Enabled) { [string]$startupTask.State }
            else { 'Disabled' }
        }
        else { 'Unavailable or missing' }
        StartupTriggers     = [string]$startupTask.TriggerSummary
        StartupTaskResult   = [string]$startupTask.LastResult
        StartupTaskError    = [string]$startupTask.Error
        StartupLastStatus   = if ($null -ne $startupState) {
            '{0} at {1}' -f [string]$startupState.status, [string]$startupState.updated_utc
        }
        else { 'No startup attempt recorded yet' }
        StartupLastMessage  = if ($null -ne $startupState) {
            [string]$startupState.message
        }
        else { $null }
        ServiceUuid         = if ($installed) { [string]$config.service_uuid } else { 'Not configured' }
        LockRssi            = if ($installed) { [int]$config.lock_rssi_dbm } else { $null }
        UnlockRssi          = if ($installed) { [int]$config.unlock_rssi_dbm } else { $null }
        MissingTimeout      = if ($installed) { ([string]$config.absence_seconds + ' seconds') } else { $null }
        HeartbeatAge        = if ($null -ne $heartbeatAge) {
            ([string]$heartbeatAge + ' seconds')
        }
        else { 'Unavailable' }
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

    if (Test-Path -LiteralPath $Script:LogPath) {
        Write-Host 'Recent guard log:'
        Get-Content -LiteralPath $Script:LogPath -Tail 12 | Out-Host
    }
}

function Uninstall-Guard {
    Assert-Windows
    Disarm-Guard
    if (Test-GuardProcess) {
        throw 'Refusing to uninstall while the guard process is still running.'
    }

    Remove-StartupLaunchers

    if (-not (Wait-StartupLaunchersExit -Seconds 45)) {
        throw ('Refusing to remove the installation while its native startup ' +
            'launcher is still stopping. Wait a few seconds and run Uninstall again.')
    }

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
        'Startup'     { Invoke-StartupSupervisor }
        'RepairStartup' { Repair-GuardStartup }
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
            $nativeMethods = $Script:NativeMethodsType
            $acStatus = $nativeMethods::GetACLineStatus()
            Write-Host ('BLE guard bridges compiled successfully; native bridge AC status={0}.' -f
                $acStatus) -ForegroundColor Green
        }
    }
}
catch {
    Write-GuardLog ('Command {0} failed: {1}' -f
        $Command, $_.Exception.ToString())
    Write-Error $_
    exit 1
}
