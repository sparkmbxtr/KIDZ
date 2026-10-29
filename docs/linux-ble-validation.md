# Linux BLE laptop verification

These checks need the actual Ubuntu laptop, phone advertiser, physical input,
GNOME session and charger. Passing CI verifies simulated behavior; it does not
establish radio calibration or successful input suppression on that laptop.
Record results locally, without committing UUIDs, addresses, network names,
hostnames, configuration files or unredacted journal output.

## Before arming

1. Save work. Keep the charger accessible. Use `disarm` if a guard is already
   running. Check the installed version is 1.6.0.
2. Install BLE mode as described in the README. Confirm installation reports
   disarmed and `systemctl is-active phone-input-guard` reports inactive.
   Complete the GNOME log-out/log-in step if installing the marker for the
   first time. Reinstalling BLE mode intentionally disarms an existing guard.
3. Start the existing Windows-compatible advertiser: the same private service
   UUID in its advertised service UUID list, preferably legacy/non-connectable
   advertising around 250 ms. No BLE pairing or connection is needed.
4. Run `sudo /usr/local/sbin/phone-input-guard observe --seconds 90`.
   Keep the phone at the normal working position. Confirm `NEAR`, plausible
   negative dBm values and an increasing update count throughout multiple
   absence intervals. There must be no false timeouts with a stationary phone.
   BlueZ exposes RSSI updates rather than a guaranteed raw-packet feed; do not
   arm if this controller suppresses those updates for the timeout duration.
5. While still observing, stop advertising, move the phone away, return it,
   and restart advertising. Check far after the configured loss timeout and
   near after a strong fresh update. A different advertised UUID must not count
   as a match. Test a rotating phone BLE address if the advertiser supports it.
6. Use the observed RSSI range to select lock/unlock thresholds. Require the
   lock threshold to be lower (more negative) than the unlock threshold.
   The middle band must retain state. These thresholds need not be identical
   across the Windows and Ubuntu adapters.
7. Run `self-test --seconds 3` while disarmed. Physical keyboard, mouse and
   touchpad input should stop briefly and return automatically. A pass message
   and process exit confirm cleanup; manually confirm actual input return.
   This bounded test does not prove GNOME indication or charger rescue.
8. Run `check`. Confirm the expected physical devices and an external-power
   sensor are detected. If no charger sensor is found, the charger rescue is
   unavailable; resolve that before testing sustained suppression.

## Armed checks

1. Ensure no excluded Wi-Fi is active. Bring the phone near and run `arm`,
   then `check`. Confirm `systemctl is-active phone-input-guard` reports active.
2. Stop advertising. Input should freeze after the configured absence timeout
   plus the polling interval. The GNOME marker should appear and the visible
   desktop should remain awake. Restart advertising: a strong fresh observation
   should release keyboard/pointer input and hide the marker.
3. Move through the weak/strong boundaries and confirm no rapid toggling in
   the hysteresis band. Attach/detach a USB input device while frozen and check
   that a new physical device is also suppressed on a subsequent poll.
4. Activate an exact excluded Wi-Fi: input should release. Leave it: BLE policy
   should resume. No Wi-Fi or a failed NetworkManager query must not remain an
   indefinite exclusion. Confirm an unrelated similar Wi-Fi name does not match.
5. Freeze input, then complete three full unplug/replug charger cycles within
   60 seconds, holding every state for at least one second. Input must release
   and stay released while the phone remains far. Bring the phone near once;
   the next departure must freeze input again.

## Bluetooth and suspend recovery

Arrange interruptions before input freezes, or use a separate recovery session
and keep the charger rescue ready. Observe first, then repeat while armed.
The guard does not power on an adapter or override rfkill itself.

| Scenario | Required result |
| --- | --- |
| Toggle Bluetooth off and on | Far on interruption; retries recover; only a new strong update releases input. |
| Restart `bluetooth.service` | Cached near state is invalidated; no stale callback releases input; scanning recovers. |
| Remove/reinsert a USB BLE adapter, if used | Adapter loss sets far; reconnect recovers discovery without restarting the guard manually. |
| Suspend/resume with phone near | Old signal and Wi-Fi state cannot authorize release; fresh near evidence recovers. |
| Suspend/resume after stopping advertiser | Input stays frozen after resume until rescue, a fresh Wi-Fi exclusion, or the phone returns. |
| Suspend for less than the advertisement timeout | Suspend detection still invalidates the old near state. |
| Resume on a different/non-excluded network | Pre-suspend Wi-Fi exclusion must not remain cached. |
| Stop the service while frozen from a recovery session | Physical input is released and the GNOME marker disappears. |
| Kill the guard process while frozen | Kernel closes evdev handles; an enabled systemd service may restart and freeze again until fresh evidence/rescue. |

Do not post personal configuration or unredacted logs in the public PR. A useful
review record contains the Ubuntu/BlueZ/GNOME versions, adapter model, test names,
pass/fail results and any timing discrepancies, with identifiers omitted.

## What CI establishes

- UUID matching, threshold boundaries, hysteresis and exact loss-timeout expiry.
- Unknown/malformed RSSI and unrelated UUIDs do not refresh proximity.
- Cached RSSI and non-RSSI BlueZ property changes cannot count as fresh evidence.
- Device/adapter/service interruption, failed starts, silent scans, old callbacks,
  stalled workers and simulated suspend invalidate/retry correctly.
- Near/far, Wi-Fi, rescue, dry-run and exception paths through the shared guard loop.
- Descriptor closure on ungrab errors and exclusive input-session ownership.
- BLE installation remains disarmed; invalid settings do not mutate installation;
  arming requires fresh evidence; BR/EDR configuration and behavior remain supported.
- An isolated simulated BlueZ service exercises actual D-Bus messages and discovery
  lifecycle with the optional binding. No physical hardware is touched.
