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

$Script:GuardVersion = '2.1.3'
$Script:NativeMethodsType = $null
$Script:BleWatcherBridgeType = $null
$Script:InstallRoot = Join-Path $env:LOCALAPPDATA 'KIDZ'
$Script:InstalledScript = Join-Path $Script:InstallRoot 'phone-input-guard-windows-ble.ps1'
$Script:InputHookHelper = Join-Path $Script:InstallRoot 'windows-input-hook-helper.exe'
$Script:InputHookHelperSha256 = '0adc71ca80b19003db434b2bff0bf3dc63bb686d180095e67f6478c77d8c2d66'
$Script:ConfigPath = Join-Path $Script:InstallRoot 'windows-ble-config.json'
$Script:LogPath = Join-Path $Script:InstallRoot 'windows-ble-guard.log'
$Script:StatePath = Join-Path $Script:InstallRoot 'windows-ble-state.json'
$Script:PidPath = Join-Path $Script:InstallRoot 'windows-ble-guard.pid'
$Script:ReadyPath = Join-Path $Script:InstallRoot 'windows-ble-ready.json'
$Script:ArmedPath = Join-Path $Script:InstallRoot 'windows-ble-armed.flag'
$Script:StopPath = Join-Path $Script:InstallRoot 'windows-ble-stop.flag'
$Script:RunKeyPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Script:RunValueName = 'KIDZ Phone Input Guard'

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
        return ($null -ne (Get-Process -Id $guardPid -ErrorAction Stop))
    }
    catch {
        return $false
    }
}

function Start-GuardProcess {
    if (Test-GuardProcess) {
        return $null
    }
    if (-not (Test-Path -LiteralPath $Script:InstalledScript)) {
        throw 'Installed guard script is missing. Run Install again.'
    }
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Sta -File "{0}" Run' -f
        $Script:InstalledScript
    return (Start-Process -FilePath $windowsPowerShell -ArgumentList $arguments `
        -WindowStyle Hidden -PassThru)
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
    Initialize-BleWatcherBridge
    Assert-InputHookHelper -Path $Script:InputHookHelper
    $nativeMethods = $Script:NativeMethodsType

    if (-not (Test-Path -LiteralPath $Script:ArmedPath)) {
        return
    }

    $createdNew = $false
    $mutex = New-Object Threading.Mutex($true, 'Local\XX-Phone-Input-Guard-BLE-V2', [ref]$createdNew)
    if (-not $createdNew) {
        $mutex.Dispose()
        return
    }

    # A ready file belongs only to the process that currently owns the mutex.
    Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue

    $config = Get-GuardConfig
    $guid = ConvertTo-TargetGuid -Value ([string]$config.service_uuid)
    $bridge = New-BleWatcherBridge -TargetUuid $guid
    $banner = New-GuardBanner -Text ([string]$config.banner_text)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $presence = New-PresenceState
    $initialAC = $nativeMethods::GetACLineStatus()
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
    $lastBlockFailureLog = [long]-10000
    $lastReleaseFailureLog = [long]-10000
    $inputBlocked = $false
    $rescueActive = $false
    $lastEffectiveBlock = $null
    $PID | Set-Content -LiteralPath $Script:PidPath -Encoding ASCII
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue

    Write-GuardLog ('BLE guard {0} started. UUID={1}; lock={2}; unlock={3}; absence={4}s.' -f
        $Script:GuardVersion, $config.service_uuid, $config.lock_rssi_dbm,
        $config.unlock_rssi_dbm, $config.absence_seconds)

    try {
        $bridge.Start()
        $readyState = [pscustomobject][ordered]@{
            pid       = $PID
            ready_utc = [DateTime]::UtcNow.ToString('o')
            version   = $Script:GuardVersion
        }
        $temporaryReadyPath = $Script:ReadyPath + '.tmp'
        $readyState | ConvertTo-Json -Depth 2 |
            Set-Content -LiteralPath $temporaryReadyPath -Encoding UTF8
        Move-Item -LiteralPath $temporaryReadyPath `
            -Destination $Script:ReadyPath -Force
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
                if ($inputBlocked -and -not $banner.Visible) {
                    $banner.Show()
                    $banner.BringToFront()
                    $banner.Refresh()
                }
                elseif ((-not $inputBlocked) -and $banner.Visible) {
                    $banner.Hide()
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
                    if (-not $banner.Visible) {
                        $banner.Show()
                        $banner.BringToFront()
                        $banner.Refresh()
                    }
                    $null = $nativeMethods::SetKeepAwake($true)
                }
                else {
                    if ($banner.Visible) {
                        $banner.Hide()
                    }
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
        $releaseConfirmed = [bool]$nativeMethods::StopInputBlocker()
        $null = $nativeMethods::SetKeepAwake($false)
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
        Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue
        $mutex.ReleaseMutex()
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

    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $runCommand = '"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Sta -File "{1}" Run' -f
        $windowsPowerShell, $Script:InstalledScript
    New-Item -Path $Script:RunKeyPath -Force | Out-Null
    New-ItemProperty -Path $Script:RunKeyPath -Name $Script:RunValueName `
        -Value $runCommand -PropertyType String -Force | Out-Null

    Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($Script:ReadyPath + '.tmp') -Force -ErrorAction SilentlyContinue

    Write-Host 'Installed for the current user without administrator access.' -ForegroundColor Green
    Write-Host ('Installed script: ' + $Script:InstalledScript)
    Write-Host ('Native input helper: ' + $Script:InputHookHelper)
    Write-Host 'The startup entry is installed, but the guard is deliberately DISARMED.' -ForegroundColor Yellow
    Write-Host 'Run Observe, then SelfTest, and finally Arm.'
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
    $activeWifi = @(Get-ActiveWifiNames)
    $excludedWifi = Get-ExcludedWifiMatch -Config $config -ActiveNames $activeWifi

    if ((Test-Path -LiteralPath $Script:ArmedPath) -and (Test-GuardReady)) {
        Write-Host 'BLE Phone Input Guard is already armed and ready.' -ForegroundColor Green
        return
    }

    # Do not race a stale or partially initialized hidden process.  Stop it
    # before performing a fresh preflight and startup handshake.
    if (Test-GuardProcess) {
        Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
        New-Item -ItemType File -Path $Script:StopPath -Force | Out-Null
        $oldProcessDeadline = [DateTime]::UtcNow.AddSeconds(6)
        while ((Test-GuardProcess) -and [DateTime]::UtcNow -lt $oldProcessDeadline) {
            Start-Sleep -Milliseconds 200
        }
        if (Test-GuardProcess) {
            throw 'An earlier guard process is still stopping. Run Disarm before retrying Arm.'
        }
        Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
    }

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
        $startedProcess = Start-GuardProcess
    }
    catch {
        Remove-Item -LiteralPath $Script:ArmedPath -Force -ErrorAction SilentlyContinue
        throw
    }

    $ready = $false
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
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
        $stopDeadline = [DateTime]::UtcNow.AddSeconds(6)
        while ((Test-GuardProcess) -and [DateTime]::UtcNow -lt $stopDeadline) {
            Start-Sleep -Milliseconds 200
        }
        $stillRunning = Test-GuardProcess
        if (-not $stillRunning) {
            Remove-Item -LiteralPath $Script:StopPath -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $Script:ReadyPath -Force -ErrorAction SilentlyContinue
        }
        if ($stillRunning) {
            throw ('The guard did not become ready within 20 seconds. It is disarmed and a stop ' +
                'was requested; check windows-ble-guard.log before retrying.')
        }
        throw 'The guard did not become ready within 20 seconds and was stopped. Check windows-ble-guard.log.'
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
        ProcessReady        = Test-GuardReady
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
            $nativeMethods = $Script:NativeMethodsType
            $acStatus = $nativeMethods::GetACLineStatus()
            Write-Host ('BLE guard bridges compiled successfully; native bridge AC status={0}.' -f
                $acStatus) -ForegroundColor Green
        }
    }
}
catch {
    Write-Error $_
    exit 1
}
