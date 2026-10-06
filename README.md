# KIDZ Phone Input Guard

KIDZ keeps the desktop visible but freezes local keyboard and mouse input when a paired Bluetooth phone is no longer nearby. It includes separate implementations for Linux and Microsoft Windows 10/11.

This is a convenience guard for brief absences, not a replacement for the operating system lock screen. Test the emergency release before relying on it.

## Shared behavior

- Starts automatically after sign-in or boot.
- Does **not** pause when the laptop switches to battery power.
- Releases input when an exact configured Wi-Fi name is active.
- Keeps the display and system awake while input is frozen.
- Shows a small top-edge marker only while input is frozen.
- Emergency release: complete three charger unplug/replug cycles within 60 seconds. Each unplugged and reconnected state must remain stable for at least one second.

All personal values in this public repository are represented by `XX` placeholders. Replace them with your own values during setup.

## Linux

The Linux implementation uses BlueZ connection/RSSI data, grabs physical input devices through `EVIOCGRAB`, installs a systemd service, and installs a GNOME Shell marker.

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

Installation creates the per-user startup entry but deliberately leaves the guard disarmed. Validate it in this order:

```powershell
.\phone-input-guard-windows-ble.ps1 Observe -ObserveSeconds 90
.\phone-input-guard-windows-ble.ps1 SelfTest
.\phone-input-guard-windows-ble.ps1 Arm
.\phone-input-guard-windows-ble.ps1 Check
```

Useful control commands:

```powershell
.\phone-input-guard-windows-ble.ps1 Disarm
.\phone-input-guard-windows-ble.ps1 Uninstall
```

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
