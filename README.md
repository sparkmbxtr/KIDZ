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

## Microsoft Windows 10/11

The Windows implementation uses the supported Win32 Bluetooth connected flag and `BlockInput`, and installs an interactive Scheduled Task for the current user. Unlike the Linux implementation, the classic Windows Bluetooth API used here does not expose link RSSI; Windows freezes input when it declares the phone disconnected.

Pair the phone first. Then open **Windows PowerShell as Administrator** in the repository folder and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phone-input-guard-windows.ps1 Install `
  -PhoneAddress "XX:XX:XX:XX:XX:XX" `
  -PhoneName "XX" `
  -ExcludedWifiNames "XX1","XX2","XX3" `
  -BannerText "XX"
```

Replace every `XX` value in that command. The installer refuses to arm immediately if it cannot see either the connected phone or an excluded Wi-Fi profile.

Useful commands, also from an Administrator PowerShell:

```powershell
.\phone-input-guard-windows.ps1 Check
.\phone-input-guard-windows.ps1 Arm
.\phone-input-guard-windows.ps1 Disarm
.\phone-input-guard-windows.ps1 Uninstall
```

Windows deliberately releases `BlockInput` when `Ctrl+Alt+Delete` is pressed. The guard reasserts the block after returning to the desktop, but it cannot suppress the Windows secure-attention screen. Preventing that would require an unsafe kernel input-filter driver and is intentionally outside this project.

## Safe test

1. Connect the charger and confirm the phone is connected.
2. Run `check` and verify that it reports the phone as present/connected and that input would not currently freeze.
3. Keep the charger within reach.
4. Turn off Bluetooth on the phone.
5. Confirm that input freezes and the marker appears.
6. Turn phone Bluetooth back on, or exercise the three-cycle charger rescue.

Do not first test this while unsaved work is open.
