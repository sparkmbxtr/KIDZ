# KIDZ Phone Input Guard

KIDZ keeps the desktop visible but freezes local keyboard and mouse input when a Bluetooth phone is no longer nearby. It includes separate implementations for Linux and Microsoft Windows 10/11.

This is a convenience guard for brief absences, not a replacement for the operating system lock screen. Test the emergency release before relying on it.

## Shared behavior

- Starts automatically after sign-in on Windows or at boot on Linux.
- Does **not** pause when the laptop switches to battery power.
- Releases input when an exact configured Wi-Fi name is active.
- Keeps the display and system awake while input is frozen.
- Shows a small top-edge marker only while input is frozen.
- Emergency release: complete three charger unplug/replug cycles within 60 seconds. Each unplugged and reconnected state must remain stable for at least one second.

All personal values in this public repository are represented by `XX` placeholders. Replace them with your own values during setup.

## Linux

Linux 1.6.0 supports two proximity modes: the existing BlueZ BR/EDR connection/RSSI detector (the default), and optional BLE advertisement detection using the same phone advertiser as the Windows BLE guard. Both use physical `EVIOCGRAB` input suppression, systemd, the GNOME Shell marker, Wi-Fi exclusions, display/idle inhibition, and charger-cycle emergency release.

Requirements include Python 3, systemd, BlueZ/`bluetoothctl`, and NetworkManager/`nmcli`. Pair and trust the phone before installation.

```bash
chmod +x phone-input-guard.py
sudo ./phone-input-guard.py install --reconfigure-wifi
```

The installer displays paired phones and asks which numbered phone to use. It then lets you choose the Wi-Fi exclusions. Useful commands:

```bash
sudo /usr/local/sbin/phone-input-guard check
sudo /usr/local/sbin/phone-input-guard disarm
sudo /usr/local/sbin/phone-input-guard arm
sudo /usr/local/sbin/phone-input-guard uninstall
```

To change the public placeholder marker, edit `PANEL_MARKER_TEXT = "XX"` before installing.

### Optional Linux BLE mode

On Ubuntu 24.04/26.04, install the optional D-Bus binding alongside BlueZ:

```bash
sudo apt install bluez python3-dbus-fast
```

BR/EDR does not require `dbus-fast`; existing configurations without a `proximity_mode` field continue to use BR/EDR. The optional BLE scanner uses BlueZ D-Bus directly and does not pair, connect to GATT, change the controller's power state, or depend on a phone MAC address. The phone may rotate its BLE address. Each discovery session has its own bus connection and releases only that client's discovery session on shutdown.

Start the phone advertiser with the **same full 128-bit service UUID used on Windows**, included in the advertised service UUID list. A legacy, non-connectable advertisement around 250 ms is suitable. Enter the UUID locally; do not put it or personal network names in a commit or issue:

```bash
read -r -p 'Phone advertiser UUID: ' KIDZ_UUID
sudo python3 ./phone-input-guard.py install \
  --mode ble --service-uuid "$KIDZ_UUID" \
  --lock-rssi -84 --unlock-rssi -80 --absence-seconds 11 \
  --reconfigure-wifi
unset KIDZ_UUID
```

BLE installation, including a reinstall, **stops/disables the service and leaves it disarmed**. It validates settings and the optional dependency before replacing installed files. Local configuration is stored at `/etc/phone-input-guard.json` with mode `0600`. Reinstalling without new options preserves the mode, UUID and thresholds. `--mode bredr` selects the original detector again; `--phone` selects a paired phone for that mode. `--adapter hci0` optionally selects a BLE controller instead of the first powered adapter.

Validate before arming:

```bash
sudo /usr/local/sbin/phone-input-guard observe --seconds 90
sudo /usr/local/sbin/phone-input-guard self-test --seconds 3
sudo /usr/local/sbin/phone-input-guard arm
sudo /usr/local/sbin/phone-input-guard check
```

`observe` reports near/far state, accepted RSSI updates and RSSI without grabbing input, connecting to the phone, changing configuration or arming the service. It exits successfully if a near state was seen. `self-test` briefly grabs physical input and automatically releases it; its duration is limited to 1–5 seconds. Run it while disarmed. A separate parent kills a stalled test process after the requested duration plus five seconds; closing the child's evdev descriptors releases its grabs. No input devices means failure, not a successful test. Confirm physical input suppression and return yourself during this bounded test.

`arm` performs a scan lasting up to ten seconds and refuses to enable the service unless it sees a fresh strong advertisement or an active excluded Wi-Fi. BLE does not support the BR/EDR `--force`/`--force-start` bypasses. A new daemon starts far until fresh evidence arrives; it does not reuse the preflight's signal sample or apply the BR/EDR startup Wi-Fi waiting period.

| BLE setting | Default | Meaning |
| --- | --- | --- |
| `ble_service_uuid` / `--service-uuid` | No usable default | Exact full service UUID; case insensitive. Public zero placeholders are rejected. |
| `ble_lock_rssi_dbm` / `--lock-rssi` | −84 dBm | A matching observation at or below this threshold sets far. |
| `ble_unlock_rssi_dbm` / `--unlock-rssi` | −80 dBm | A matching observation at or above this threshold sets near. |
| `ble_absence_seconds` / `--absence-seconds` | 11 s | No fresh matching RSSI update for this duration sets far. |
| `ble_adapter` / `--adapter` | Automatic | Optional controller name such as `hci0`. |

For example, −82 dBm retains the previous near/far state. After startup, signal loss, or a scanner interruption, −82 dBm cannot release input; a new observation of at least −80 dBm is needed. These are absolute BLE dBm values, independent of BR/EDR's controller-relative threshold of zero. This Linux mode uses one qualifying weak/strong observation for each transition; it does not duplicate Windows' additional weak-sample voting rule. Tune thresholds from observation on the actual laptop.

Only live BlueZ signals containing RSSI refresh proximity. Cached `GetManagedObjects` RSSI, device name/connection changes, unrelated UUIDs, unknown RSSI values, and callbacks from an earlier scan do not. The counter reports **accepted BlueZ RSSI updates**, not all over-the-air packets. BlueZ/controller combinations may coalesce identical data, so the 90-second stationary-phone observation must confirm continuing updates and no false loss timeouts before arming.

Adapter power/discovery loss, Bluetooth service loss, a stalled scanner, or suspend/resume invalidates cached near state and restarts scanning with bounded retries. The loss clock uses Linux `CLOCK_BOOTTIME`, including suspend. Wi-Fi exclusions also expire when their cached probe becomes stale or crosses suspend. While armed, a radio failure means far; input remains frozen until fresh near evidence, a fresh Wi-Fi exclusion, or the charger rescue. Fatal process exit releases evdev grabs; systemd may then restart the armed service. Cleanup releases input before indicator/backend shutdown and still runs if another cleanup fails. An exclusive lock prevents the new daemon and input self-test from grabbing simultaneously.

The UUID is broadcast in cleartext and can be replayed. As on Windows, this convenience guard is not authentication or a replacement for the OS lock screen.

### Linux validation

Run the hardware-free suite with:

```bash
python3 -m py_compile phone-input-guard.py
python3 -m unittest discover -s tests -v
```

CI runs simulations on Python 3.10, 3.12 and 3.14. A separate job tests the Ubuntu 24.04 and 26.04 D-Bus binding baselines plus the latest binding against an isolated simulated BlueZ service. That job requires a private test bus; it never uses the runner's real system bus, Bluetooth adapter or input devices. The Windows checks remain in place.

See [the Ubuntu laptop verification procedure](docs/linux-ble-validation.md) for radio calibration, actual input/marker behavior, suspend/resume, Bluetooth interruption and emergency release checks that CI cannot establish.

## Microsoft Windows 10/11: BLE guard without administrator access

`phone-input-guard-windows-ble.ps1` is the recommended Windows implementation. It listens for a private 128-bit BLE service UUID advertised by the phone, classifies near/far state from RSSI plus missing advertisements, and uses a verified native helper to suppress keyboard and mouse input in the current desktop session. It installs entirely within the current user's profile and does not require administrator access.

Configure a phone BLE advertiser with a new, unique 128-bit service UUID. A legacy, non-connectable advertisement at roughly 250 ms works well. The UUID is broadcast in cleartext: uniqueness prevents accidental matches, but it is not authentication and a nearby transmitter could replay it. The public repository deliberately contains only a zero UUID placeholder.

Keep `phone-input-guard-windows-ble.ps1` and `windows-input-hook-helper.exe` in the same folder. Open ordinary **Windows PowerShell 5.1** in that folder and run:

```powershell
Unblock-File -LiteralPath '.\phone-input-guard-windows-ble.ps1', '.\windows-input-hook-helper.exe'

.\phone-input-guard-windows-ble.ps1 Install `
  -ServiceUuid '00000000-0000-4000-8000-000000000000' `
  -LockRssi -84 `
  -UnlockRssi -80 `
  -AbsenceSeconds 8 `
  -ExcludedWifiNames @('XX1','XX2','XX3') `
  -BannerText "XX"
```

Replace the zero UUID and each `XX` value. `LockRssi` is the weak-signal threshold, `UnlockRssi` is the stronger return threshold, and `AbsenceSeconds` is the time without a matching packet that counts as far. The gap between the two RSSI thresholds is hysteresis, which reduces rapid toggling near the boundary.

Installation creates two non-admin, per-user startup paths: a limited scheduled
task that starts after sign-in, workstation unlock, or a sleep/Modern Standby
resume event, and an HKCU Run fallback. The
fallback waits briefly so both launchers cannot create competing supervisors.
Both paths use a locally generated Windows GUI-subsystem launcher. The launcher
has no console and creates Windows PowerShell with `CREATE_NO_WINDOW`, so the
default terminal cannot open a PowerShell window at sign-in.
The startup supervisor retries transient Bluetooth/WinRT failures while the
guard remains armed. Supervised starts fail closed until a fresh phone packet or
fresh exclusion-Wi-Fi result is seen. The guard recreates its BLE watcher after
a lid-close, suspend/resume gap, or a `Stopped`/`Aborted` watcher state. A fresh
heartbeat prevents a live but stalled process from being reported as ready. An empty
active-Wi-Fi list is valid and means that no Wi-Fi exclusion applies.
Installation deliberately leaves the guard disarmed.
Validate it in this order:

```powershell
.\phone-input-guard-windows-ble.ps1 Observe -ObserveSeconds 90
.\phone-input-guard-windows-ble.ps1 SelfTest
.\phone-input-guard-windows-ble.ps1 Arm
.\phone-input-guard-windows-ble.ps1 Check
```

Useful control commands:

```powershell
.\phone-input-guard-windows-ble.ps1 Disarm
.\phone-input-guard-windows-ble.ps1 RepairStartup
.\phone-input-guard-windows-ble.ps1 Uninstall
```

`RepairStartup` recreates both current-user launchers without changing the BLE
configuration or armed state. It never requests elevation. On a managed PC
that forbids users from creating scheduled tasks, the command reports that
restriction and retains the HKCU Run fallback.

`Check` reports the exact HKCU Run command status, Windows startup approval,
scheduled-task state/result, the last startup-supervisor status, and the last
12 guard log lines. This makes a failed sign-in start diagnosable without an
Administrator PowerShell.  After repairing startup, sign out and sign back in
(or restart Windows), wait about 30 seconds, and run `Check`; `Armed`,
`ProcessRunning`, and `ProcessReady` should all be `True`.

`Arm` performs a ten-second BLE preflight and refuses to start unless the phone is near or an exclusion Wi-Fi is active. The native helper is assigned to a kill-on-close Windows job, and the PowerShell parent confirms helper exit before reporting that input was released.

Windows reserves `Ctrl+Alt+Delete` for its secure-attention screen, so a user-mode input hook cannot suppress it. This is one reason KIDZ is a brief-absence convenience guard rather than a substitute for locking Windows.

### Legacy Windows connected-device guard

`phone-input-guard-windows.ps1` is retained for systems where a continuously connected classic-Bluetooth device is reliable. It uses `BlockInput`, requires an elevated Administrator PowerShell, and does not measure Bluetooth RSSI. The BLE implementation above is preferable when the phone can advertise a private service UUID.

## Safe test

1. Save open work and keep the charger within reach.
2. Make sure no configured exclusion Wi-Fi is active.
3. Start the phone advertisement and run `Observe`; verify that matching packets appear and the state becomes `NEAR`.
4. Run `SelfTest`; it must explicitly report that the test passed and input was released.
5. Run `Arm`, then `Check`; `Armed`, `ProcessRunning`, and `ProcessReady` must all be `True`.
6. Stop the phone advertisement. Confirm that input freezes and the marker appears after the configured timeout.
7. Restart the advertisement and confirm release. Separately test the emergency release by completing three charger unplug/replug cycles within 60 seconds, keeping every state stable for at least one second.

Do not first test this while unsaved work is open.
