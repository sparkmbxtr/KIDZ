#!/usr/bin/env python3
"""Freeze local Linux keyboard and pointer input when a Bluetooth phone is distant.

The visible desktop stays on and an idle/sleep inhibitor is held while input is
frozen.  On GNOME, XX appears at the top-left of the Shell
panel.  This program uses Linux EVIOCGRAB on physical evdev devices, so it works
below X11/Wayland.

Quick installation:

    chmod +x phone-input-guard.py
    sudo ./phone-input-guard.py install

The installer lists paired Bluetooth devices, lets you select the phone, and
starts the systemd service only after it confirms that the phone is connected.

Important: for the selected phone's BR/EDR link, "nearby" means that BlueZ
reports both an active connection and an RSSI value in or above the controller's
Golden Receive Power Range.  The measured calibration for this installation is
nearby at RSSI >= 0 and distant at RSSI < 0.  A disconnection is always distant.

Emergency rescue: while the phone is absent, complete three full charger
unplug -> reconnect cycles within 60 seconds.  Each power state must remain
stable for one second.  Input is then released until the phone returns nearby.
"""

from __future__ import annotations

import argparse
import ast
import ctypes
import ctypes.util
import errno
import fcntl
import json
import logging
import os
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional


APP_NAME = "phone-input-guard"
VERSION = "1.5.0"
INSTALL_PATH = Path("/usr/local/sbin/phone-input-guard")
CONFIG_PATH = Path("/etc/phone-input-guard.json")
SERVICE_PATH = Path("/etc/systemd/system/phone-input-guard.service")
PANEL_MARKER_TEXT = "XX"
PANEL_RUNTIME_DIR = Path("/run/phone-input-guard")
PANEL_STATE_PATH = PANEL_RUNTIME_DIR / "locked"
GNOME_EXTENSION_UUID = "phone-input-guard@xx.local"
GNOME_EXTENSION_PATH = (
    Path("/usr/share/gnome-shell/extensions") / GNOME_EXTENSION_UUID
)

LOG = logging.getLogger(APP_NAME)


# Linux input-event constants from include/uapi/linux/input-event-codes.h.
EV_SYN = 0x00
EV_KEY = 0x01
EV_REL = 0x02
EV_ABS = 0x03
REL_X = 0x00
REL_Y = 0x01
ABS_X = 0x00
ABS_Y = 0x01
BTN_TOOL_FINGER = 0x145
BTN_TOUCH = 0x14A
KEY_MAX = 0x2FF
REL_MAX = 0x0F
ABS_MAX = 0x3F

# Generic Linux ioctl encoding.  These values are ABI constants, not magic
# values tied to one desktop environment.
_IOC_NRBITS = 8
_IOC_TYPEBITS = 8
_IOC_SIZEBITS = 14
_IOC_NRSHIFT = 0
_IOC_TYPESHIFT = _IOC_NRSHIFT + _IOC_NRBITS
_IOC_SIZESHIFT = _IOC_TYPESHIFT + _IOC_TYPEBITS
_IOC_DIRSHIFT = _IOC_SIZESHIFT + _IOC_SIZEBITS
_IOC_WRITE = 1
_IOC_READ = 2


def _ioc(direction: int, ioctl_type: int, number: int, size: int) -> int:
    return (
        (direction << _IOC_DIRSHIFT)
        | (ioctl_type << _IOC_TYPESHIFT)
        | (number << _IOC_NRSHIFT)
        | (size << _IOC_SIZESHIFT)
    )


def _eviocgbit(event_type: int, length: int) -> int:
    return _ioc(_IOC_READ, ord("E"), 0x20 + event_type, length)


def _eviocgname(length: int) -> int:
    return _ioc(_IOC_READ, ord("E"), 0x06, length)


EVIOCGRAB = _ioc(_IOC_WRITE, ord("E"), 0x90, struct.calcsize("i"))

WIFI_POLICY_REVISION = 1
PROXIMITY_POLICY_REVISION = 1
DEFAULT_WIFI_EXCLUSIONS = ["XX1", "XX2", "XX3"]


DEFAULT_CONFIG: dict[str, Any] = {
    "phone_address": "",
    # This is a polling interval, not an absence grace period.  The first
    # disconnected or distant result freezes input immediately.
    "poll_seconds": 0.35,
    "automatic_reconnect": True,
    "reconnect_every_seconds": 2.0,
    # BR/EDR HCI RSSI is relative to the controller's Golden Receive Power
    # Range, not absolute dBm.  The measured trace was 0 or positive nearby
    # and negative only when departing.  There is deliberately no timer or
    # consecutive-sample requirement: the first negative sample freezes input.
    "bredr_rssi_proximity": True,
    "bredr_rssi_lock_below": 0,
    "proximity_policy_revision": PROXIMITY_POLICY_REVISION,
    "rescue_power_cycles": 3,
    "rescue_window_seconds": 60.0,
    "power_state_debounce_seconds": 1.0,
    # Match active NetworkManager connection-profile names (normally the SSID).
    # When either home Wi-Fi or the phone hotspot is active, the guard is inert.
    "excluded_wifi_connections": list(DEFAULT_WIFI_EXCLUSIONS),
    "wifi_policy_revision": WIFI_POLICY_REVISION,
    "wifi_poll_seconds": 0.75,
    # At boot only, allow NetworkManager time to report an auto-connected home
    # network before applying the normal rule.  After this, no Wi-Fi is not an
    # exclusion; only an explicit name above pauses the guard.
    "wifi_startup_settle_seconds": 15.0,
    "locked_banner_template": PANEL_MARKER_TEXT,
    "exclude_device_name_regex": [
        "Power Button",
        "Sleep Button",
        "Lid Switch",
        "Video Bus",
    ],
}


SYSTEMD_SERVICE = f"""[Unit]
Description=Freeze keyboard and pointer input when the paired phone is distant
Documentation=https://www.kernel.org/doc/html/latest/input/input.html
Wants=bluetooth.service
After=bluetooth.service NetworkManager.service systemd-udevd.service

[Service]
Type=simple
ExecStart={INSTALL_PATH} run --config {CONFIG_PATH}
Restart=on-failure
RestartSec=1
TimeoutStopSec=5
User=root
UMask=0077
Environment=PYTHONUNBUFFERED=1
Environment=LC_ALL=C
RuntimeDirectory=phone-input-guard
RuntimeDirectoryMode=0755

# Hardening that still permits access to the real /dev/input event devices.
NoNewPrivileges=yes
# The display socket and, on some X11 systems, a user Xauthority file must
# remain readable by the unprivileged on-screen indicator process.
ProtectHome=read-only
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
"""


# GNOME 45 and newer use ES modules for Shell extensions.  This extension adds
# a text-only item at the panel's top-left and watches the root service's state
# file.
GNOME_EXTENSION_MODERN_JS = r"""import Clutter from 'gi://Clutter';
import GLib from 'gi://GLib';
import St from 'gi://St';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PanelMenu from 'resource:///org/gnome/shell/ui/panelMenu.js';

const STATE_FILE = '/run/phone-input-guard/locked';
const LABEL_TEXT = 'XX';

export default class PhoneInputGuardExtension extends Extension {
    enable() {
        this._indicator = new PanelMenu.Button(0.0, LABEL_TEXT, true);
        this._indicator.reactive = false;
        this._indicator.can_focus = false;
        this._indicator.visible = false;
        this._label = new St.Label({
            text: LABEL_TEXT,
            y_align: Clutter.ActorAlign.CENTER,
            style_class: 'xx-input-guard-label',
        });
        this._indicator.add_child(this._label);

        Main.panel.addToStatusArea(this.uuid, this._indicator, 0, 'left');
        this._syncVisibility();
        this._timeoutId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 250, () => {
            this._syncVisibility();
            return GLib.SOURCE_CONTINUE;
        });
    }

    _syncVisibility() {
        if (this._indicator)
            this._indicator.visible = GLib.file_test(STATE_FILE, GLib.FileTest.EXISTS);
    }

    disable() {
        if (this._timeoutId) {
            GLib.Source.remove(this._timeoutId);
            this._timeoutId = null;
        }
        this._indicator?.destroy();
        this._indicator = null;
        this._label = null;
    }
}
"""


# GNOME 40-44 use the earlier imports-based extension format.  Keeping this
# variant costs little and lets the same installer work on Ubuntu 22.04 too.
GNOME_EXTENSION_LEGACY_JS = r"""const {Clutter, GLib, St} = imports.gi;
const Main = imports.ui.main;
const PanelMenu = imports.ui.panelMenu;

const STATE_FILE = '/run/phone-input-guard/locked';
const LABEL_TEXT = 'XX';

let indicator = null;
let timeoutId = 0;

function syncVisibility() {
    if (indicator)
        indicator.visible = GLib.file_test(STATE_FILE, GLib.FileTest.EXISTS);
}

function init() {
}

function enable() {
    indicator = new PanelMenu.Button(0.0, LABEL_TEXT, true);
    indicator.reactive = false;
    indicator.can_focus = false;
    indicator.visible = false;
    indicator.add_child(new St.Label({
        text: LABEL_TEXT,
        y_align: Clutter.ActorAlign.CENTER,
        style_class: 'xx-input-guard-label',
    }));
    Main.panel.addToStatusArea('phone-input-guard', indicator, 0, 'left');
    syncVisibility();
    timeoutId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 250, () => {
        syncVisibility();
        return true;
    });
}

function disable() {
    if (timeoutId) {
        GLib.source_remove(timeoutId);
        timeoutId = 0;
    }
    if (indicator) {
        indicator.destroy();
        indicator = null;
    }
}
"""


GNOME_EXTENSION_STYLESHEET = """.xx-input-guard-label {
    font-weight: bold;
    padding-left: 10px;
    padding-right: 10px;
}
"""


def command_environment() -> dict[str, str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    return env


def run_command(
    command: list[str], timeout: float = 8.0, check: bool = False
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=check,
        env=command_environment(),
    )


def normalize_address(value: str) -> str:
    address = value.strip().upper().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", address):
        raise ValueError(f"Invalid Bluetooth address: {value!r}")
    return address


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def require_root(action: str) -> None:
    if os.geteuid() != 0:
        raise SystemExit(f"{action} must be run with sudo/root privileges.")


def paired_devices() -> list[tuple[str, str]]:
    if shutil.which("bluetoothctl") is None:
        raise SystemExit("bluetoothctl was not found. Install the BlueZ package first.")

    outputs: list[str] = []
    for command in (
        ["bluetoothctl", "devices", "Paired"],
        ["bluetoothctl", "paired-devices"],
    ):
        try:
            result = run_command(command, timeout=5.0)
        except (OSError, subprocess.TimeoutExpired):
            continue
        outputs.append(result.stdout)
        if result.returncode == 0 and "Device " in result.stdout:
            break

    found: dict[str, str] = {}
    pattern = re.compile(
        r"^Device\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?:\s+(.*))?$"
    )
    for output in outputs:
        for line in output.splitlines():
            match = pattern.match(line.strip())
            if match:
                found[normalize_address(match.group(1))] = (
                    match.group(2) or "Unnamed device"
                ).strip()
    return list(found.items())


def choose_phone(explicit_address: Optional[str]) -> str:
    if explicit_address:
        return normalize_address(explicit_address)
    if not sys.stdin.isatty():
        raise SystemExit("Use --phone AA:BB:CC:DD:EE:FF in non-interactive mode.")

    devices = paired_devices()
    if not devices:
        raise SystemExit(
            "No paired Bluetooth devices were found. Pair and trust the phone first."
        )

    print("Paired Bluetooth devices:")
    for index, (address, name) in enumerate(devices, start=1):
        print(f"  {index}. {name}  [{address}]")
    while True:
        raw = input("Select the phone number: ").strip()
        try:
            selected = int(raw)
        except ValueError:
            selected = 0
        if 1 <= selected <= len(devices):
            return devices[selected - 1][0]
        print("Enter one of the listed numbers.")


def _parse_nmcli_terse_line(line: str) -> list[str]:
    """Split nmcli's colon format while respecting backslash escapes."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line.rstrip("\n"):
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def _deduplicate_names(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = str(value).strip()
        key = cleaned.casefold()
        if cleaned and key not in seen:
            result.append(cleaned)
            seen.add(key)
    return result


def saved_wifi_connections() -> list[tuple[str, Optional[str]]]:
    """Return saved NetworkManager Wi-Fi profile names and configured SSIDs."""
    if shutil.which("nmcli") is None:
        return []
    try:
        result = run_command(
            [
                "nmcli",
                "--terse",
                "--escape",
                "yes",
                "--fields",
                "NAME,TYPE",
                "connection",
                "show",
            ],
            timeout=6.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []

    profiles: list[tuple[str, Optional[str]]] = []
    seen: set[str] = set()
    for line in result.stdout.splitlines():
        fields = _parse_nmcli_terse_line(line)
        if len(fields) < 2 or fields[1] not in {"802-11-wireless", "wifi"}:
            continue
        profile = fields[0].strip()
        if not profile or profile.casefold() in seen:
            continue
        seen.add(profile.casefold())
        ssid: Optional[str] = None
        try:
            ssid_result = run_command(
                [
                    "nmcli",
                    "--escape",
                    "no",
                    "--get-values",
                    "802-11-wireless.ssid",
                    "connection",
                    "show",
                    profile,
                ],
                timeout=3.0,
            )
            if ssid_result.returncode == 0:
                candidate = ssid_result.stdout.splitlines()[0].strip()
                ssid = candidate or None
        except (OSError, subprocess.TimeoutExpired, IndexError):
            pass
        profiles.append((profile, ssid))
    return profiles


def choose_wifi_exclusions(
    explicit: Optional[list[str]],
    existing: list[str],
    prompt_for_values: bool,
) -> list[str]:
    if explicit is not None:
        return _deduplicate_names(explicit)
    if not prompt_for_values or not sys.stdin.isatty():
        return _deduplicate_names(existing)

    profiles = saved_wifi_connections()
    print("\nSaved Wi-Fi connections:")
    if profiles:
        for index, (profile, ssid) in enumerate(profiles, start=1):
            suffix = f"  [SSID: {ssid}]" if ssid and ssid != profile else ""
            print(f"  {index}. {profile}{suffix}")
    else:
        print("  NetworkManager profiles were not available; enter exact names manually.")

    def ask(label: str) -> list[str]:
        raw = input(f"{label} Wi-Fi number or exact profile/SSID (blank to skip): ").strip()
        if not raw:
            return []
        if raw.isdigit() and 1 <= int(raw) <= len(profiles):
            profile, ssid = profiles[int(raw) - 1]
            return [profile] + ([ssid] if ssid and ssid != profile else [])
        return [raw]

    selected: list[str] = []
    selected.extend(ask("Home"))
    selected.extend(ask("Phone hotspot"))
    return _deduplicate_names(selected)


def active_wifi_names() -> Optional[set[str]]:
    """Return active Wi-Fi profile names and SSIDs, or None if unavailable."""
    names: set[str] = set()
    successful_query = False

    if shutil.which("nmcli"):
        try:
            result = run_command(
                [
                    "nmcli",
                    "--terse",
                    "--escape",
                    "yes",
                    "--fields",
                    "NAME,TYPE",
                    "connection",
                    "show",
                    "--active",
                ],
                timeout=3.0,
            )
            if result.returncode == 0:
                successful_query = True
                for line in result.stdout.splitlines():
                    fields = _parse_nmcli_terse_line(line)
                    if (
                        len(fields) >= 2
                        and fields[1] in {"802-11-wireless", "wifi"}
                        and fields[0].strip()
                    ):
                        names.add(fields[0].strip())
        except (OSError, subprocess.TimeoutExpired):
            pass

        # Profile and SSID are usually identical, but include both so a renamed
        # NetworkManager profile cannot defeat an SSID exclusion.
        try:
            result = run_command(
                [
                    "nmcli",
                    "--terse",
                    "--escape",
                    "yes",
                    "--fields",
                    "IN-USE,SSID",
                    "device",
                    "wifi",
                    "list",
                    "--rescan",
                    "no",
                ],
                timeout=3.0,
            )
            if result.returncode == 0:
                successful_query = True
                for line in result.stdout.splitlines():
                    fields = _parse_nmcli_terse_line(line)
                    if len(fields) >= 2 and fields[0] in {"*", "yes"}:
                        if fields[1].strip():
                            names.add(fields[1].strip())
        except (OSError, subprocess.TimeoutExpired):
            pass

    if not successful_query and shutil.which("iwgetid"):
        try:
            result = run_command(["iwgetid", "--raw"], timeout=2.0)
            if result.returncode == 0:
                successful_query = True
                if result.stdout.strip():
                    names.add(result.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            pass

    return names if successful_query else None


@dataclass(frozen=True)
class WifiPolicyDecision:
    paused: bool
    reason: str
    active_names: tuple[str, ...]


class WifiExclusionMonitor:
    """Poll Wi-Fi outside the fast Bluetooth loop and expose a cached policy."""

    def __init__(
        self,
        excluded_names: Iterable[str],
        poll_seconds: float,
        startup_settle_seconds: float,
    ) -> None:
        self.excluded_names = _deduplicate_names(excluded_names)
        self._excluded_lookup = {name.casefold(): name for name in self.excluded_names}
        self.poll_seconds = poll_seconds
        self.startup_settle_seconds = startup_settle_seconds
        self._started_at = time.monotonic()
        self._active_names: Optional[set[str]] = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._worker, name="wifi-exclusion-monitor", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _worker(self) -> None:
        while not self._stop.is_set():
            current = active_wifi_names()
            with self._lock:
                self._active_names = current
            self._stop.wait(self.poll_seconds)

    def decision(self) -> WifiPolicyDecision:
        if not self.excluded_names:
            return WifiPolicyDecision(False, "no Wi-Fi exclusions configured", ())
        with self._lock:
            current = None if self._active_names is None else set(self._active_names)
        names = tuple(sorted(current or set(), key=str.casefold))
        if current:
            for name in names:
                configured = self._excluded_lookup.get(name.casefold())
                if configured is not None:
                    return WifiPolicyDecision(
                        True, f"excluded Wi-Fi active: {configured}", names
                    )
            return WifiPolicyDecision(False, "non-excluded Wi-Fi active", names)
        if time.monotonic() - self._started_at < self.startup_settle_seconds:
            return WifiPolicyDecision(True, "waiting for startup Wi-Fi state", names)
        # No Wi-Fi is deliberately not a continuing exclusion.  This ensures
        # a lab Wi-Fi outage cannot disable the guard.
        return WifiPolicyDecision(False, "no excluded Wi-Fi active", names)


def bit_is_set(bitmap: int, bit: int) -> bool:
    return bool(bitmap & (1 << bit))


def get_capability_bits(file_descriptor: int, event_type: int, maximum: int) -> int:
    length = (maximum // 8) + 1
    buffer = bytearray(length)
    fcntl.ioctl(file_descriptor, _eviocgbit(event_type, length), buffer, True)
    return int.from_bytes(buffer, byteorder=sys.byteorder, signed=False)


def get_device_name(file_descriptor: int) -> str:
    buffer = bytearray(256)
    try:
        fcntl.ioctl(file_descriptor, _eviocgname(len(buffer)), buffer, True)
    except OSError:
        return "Unknown input device"
    return bytes(buffer).split(b"\0", 1)[0].decode("utf-8", errors="replace")


@dataclass
class GrabbedDevice:
    path: Path
    file_descriptor: int
    name: str
    kind: str


class InputGrabber:
    """Own exclusive evdev grabs and discard input until released."""

    def __init__(self, excluded_name_patterns: Iterable[str]) -> None:
        self._devices: dict[Path, GrabbedDevice] = {}
        self._excluded = [
            re.compile(pattern, re.IGNORECASE) for pattern in excluded_name_patterns
        ]

    @staticmethod
    def _classify(file_descriptor: int, name: str) -> Optional[str]:
        event_types = get_capability_bits(file_descriptor, 0, 0x1F)
        key_bits = (
            get_capability_bits(file_descriptor, EV_KEY, KEY_MAX)
            if bit_is_set(event_types, EV_KEY)
            else 0
        )
        rel_bits = (
            get_capability_bits(file_descriptor, EV_REL, REL_MAX)
            if bit_is_set(event_types, EV_REL)
            else 0
        )
        abs_bits = (
            get_capability_bits(file_descriptor, EV_ABS, ABS_MAX)
            if bit_is_set(event_types, EV_ABS)
            else 0
        )

        # A real keyboard normally exposes many keys in the standard 0..127
        # range; this avoids grabbing one-key power/lid devices.
        keyboard_like = (key_bits & ((1 << 128) - 1)).bit_count() >= 8
        relative_pointer = bit_is_set(rel_bits, REL_X) and bit_is_set(rel_bits, REL_Y)
        name_suggests_absolute_pointer = bool(
            re.search(r"touchpad|touchscreen|tablet|pointer", name, re.IGNORECASE)
        )
        absolute_pointer = (
            bit_is_set(abs_bits, ABS_X)
            and bit_is_set(abs_bits, ABS_Y)
            and (
                bit_is_set(key_bits, BTN_TOUCH)
                or bit_is_set(key_bits, BTN_TOOL_FINGER)
                or name_suggests_absolute_pointer
            )
        )

        if keyboard_like and (relative_pointer or absolute_pointer):
            return "keyboard+pointer"
        if keyboard_like:
            return "keyboard"
        if relative_pointer or absolute_pointer:
            return "pointer"
        return None

    def candidate_devices(self) -> list[tuple[Path, str, str]]:
        candidates: list[tuple[Path, str, str]] = []
        for path in sorted(Path("/dev/input").glob("event*")):
            try:
                descriptor = os.open(
                    path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
                )
            except OSError:
                continue
            try:
                name = get_device_name(descriptor)
                if any(pattern.search(name) for pattern in self._excluded):
                    continue
                kind = self._classify(descriptor, name)
                if kind:
                    candidates.append((path, name, kind))
            except OSError:
                continue
            finally:
                os.close(descriptor)
        return candidates

    def grab_all(self) -> None:
        live_paths = set(Path("/dev/input").glob("event*"))
        for path in list(self._devices):
            if path not in live_paths:
                self._close_one(path)

        for path in sorted(live_paths):
            if path in self._devices:
                continue
            try:
                descriptor = os.open(
                    path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
                )
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.ENOENT, errno.ENODEV):
                    LOG.warning("Cannot open %s: %s", path, error)
                continue

            keep_open = False
            try:
                name = get_device_name(descriptor)
                if any(pattern.search(name) for pattern in self._excluded):
                    continue
                kind = self._classify(descriptor, name)
                if not kind:
                    continue
                fcntl.ioctl(descriptor, EVIOCGRAB, struct.pack("i", 1))
                self._devices[path] = GrabbedDevice(path, descriptor, name, kind)
                keep_open = True
                LOG.info("Frozen %s: %s (%s)", kind, name, path)
            except OSError as error:
                LOG.warning("Cannot freeze %s: %s", path, error)
            finally:
                if not keep_open:
                    os.close(descriptor)

    def _close_one(self, path: Path) -> None:
        device = self._devices.pop(path, None)
        if not device:
            return
        try:
            fcntl.ioctl(device.file_descriptor, EVIOCGRAB, struct.pack("i", 0))
        except OSError:
            pass
        try:
            os.close(device.file_descriptor)
        except OSError:
            pass
        LOG.info("Released %s: %s (%s)", device.kind, device.name, device.path)

    def release_all(self) -> None:
        for path in list(self._devices):
            self._close_one(path)

    @property
    def is_grabbed(self) -> bool:
        return bool(self._devices)

    def discard_input(self) -> None:
        """Drain and discard events so grabbed-device queues cannot accumulate."""
        for path, device in list(self._devices.items()):
            while True:
                try:
                    data = os.read(device.file_descriptor, 4096)
                except BlockingIOError:
                    break
                except OSError as error:
                    if error.errno in (errno.ENODEV, errno.EIO, errno.EBADF):
                        self._close_one(path)
                    break
                if not data:
                    break


class PowerCycleRescue:
    """Detect deliberate full external-power cycles through Linux power_supply."""

    ACCEPTED_TYPES = {
        "Mains",
        "USB",
        "USB_DCP",
        "USB_CDP",
        "USB_ACA",
        "USB_C",
        "USB_PD",
        "USB_PD_DRP",
        "Wireless",
    }

    def __init__(
        self, required_cycles: int, window_seconds: float, debounce_seconds: float
    ) -> None:
        self.required_cycles = required_cycles
        self.window_seconds = window_seconds
        self.debounce_seconds = debounce_seconds
        self.supplies = self._discover_supplies()
        self._stable_state: Optional[bool] = None
        self._raw_state: Optional[bool] = None
        self._raw_changed_at = time.monotonic()
        self._window_started: Optional[float] = None
        self._saw_disconnect = False
        self._completed_cycles = 0
        self.reset()

    @classmethod
    def _discover_supplies(cls) -> list[Path]:
        supplies: list[Path] = []
        for directory in sorted(Path("/sys/class/power_supply").glob("*")):
            online = directory / "online"
            supply_type = directory / "type"
            if not online.is_file() or not supply_type.is_file():
                continue
            try:
                kind = supply_type.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if kind in cls.ACCEPTED_TYPES:
                supplies.append(online)
        return supplies

    def external_power_online(self) -> Optional[bool]:
        if not self.supplies:
            self.supplies = self._discover_supplies()
        if not self.supplies:
            return None
        readable = 0
        online = False
        for path in self.supplies:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            readable += 1
            online = online or value == "1"
        return online if readable else None

    def reset(self) -> None:
        now = time.monotonic()
        current = self.external_power_online()
        self._stable_state = current
        self._raw_state = current
        self._raw_changed_at = now
        self._window_started = None
        self._saw_disconnect = False
        self._completed_cycles = 0

    @property
    def supply_names(self) -> list[str]:
        return [path.parent.name for path in self.supplies]

    def update(self) -> bool:
        """Return True once three debounced unplug/reconnect cycles complete."""
        now = time.monotonic()
        current = self.external_power_online()
        if current is None:
            return False

        if current != self._raw_state:
            self._raw_state = current
            self._raw_changed_at = now
            return False

        if current == self._stable_state:
            if (
                self._window_started is not None
                and now - self._window_started > self.window_seconds
            ):
                LOG.info("Power rescue sequence expired; counter reset")
                self._window_started = None
                self._saw_disconnect = False
                self._completed_cycles = 0
            return False

        if now - self._raw_changed_at < self.debounce_seconds:
            return False

        previous = self._stable_state
        self._stable_state = current

        # Begin a rescue window only on a real online -> offline transition.
        if previous is True and current is False:
            if (
                self._window_started is None
                or now - self._window_started > self.window_seconds
            ):
                self._window_started = now
                self._completed_cycles = 0
            self._saw_disconnect = True
            LOG.info(
                "Power rescue: charger disconnected (%d/%d cycles complete)",
                self._completed_cycles,
                self.required_cycles,
            )
            return False

        # Count only a full, ordered offline -> online completion inside the
        # active window.  Random duplicate state reports cannot increment it.
        if previous is False and current is True and self._saw_disconnect:
            if (
                self._window_started is None
                or now - self._window_started > self.window_seconds
            ):
                self.reset()
                return False
            self._completed_cycles += 1
            self._saw_disconnect = False
            LOG.warning(
                "Power rescue: charger reconnected (%d/%d cycles complete)",
                self._completed_cycles,
                self.required_cycles,
            )
            if self._completed_cycles >= self.required_cycles:
                self.reset()
                return True
        return False


@dataclass
class GraphicalSession:
    session_id: str
    uid: int
    gid: int
    username: str
    environment: dict[str, str]


def _read_process_environment(process_id: int) -> dict[str, str]:
    try:
        raw = Path(f"/proc/{process_id}/environ").read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return {}
    environment: dict[str, str] = {}
    for item in raw.split(b"\0"):
        if b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        environment[key.decode(errors="ignore")] = value.decode(errors="ignore")
    return environment


def _session_properties(session_id: str) -> dict[str, str]:
    try:
        result = run_command(
            [
                "loginctl",
                "show-session",
                session_id,
                "--no-pager",
                "-p",
                "Active",
                "-p",
                "Remote",
                "-p",
                "Type",
                "-p",
                "Class",
                "-p",
                "User",
                "-p",
                "Name",
                "-p",
                "Leader",
                "-p",
                "Display",
            ],
            timeout=3.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key] = value
    return properties


def _find_display_environment(
    uid: int, session_id: str, leader: int
) -> dict[str, str]:
    leader_environment: dict[str, str] = {}
    if leader > 0:
        leader_environment = _read_process_environment(leader)

    # Session leaders do not always retain DISPLAY/XAUTHORITY.  Prefer a
    # process explicitly belonging to this login session, then any graphical
    # process owned by the same active user.
    exact: Optional[dict[str, str]] = None
    fallback: Optional[dict[str, str]] = None
    for process_directory in Path("/proc").glob("[0-9]*"):
        try:
            if process_directory.stat().st_uid != uid:
                continue
            environment = _read_process_environment(int(process_directory.name))
        except (ValueError, FileNotFoundError, PermissionError, OSError):
            continue
        if not environment.get("DISPLAY") and not environment.get("WAYLAND_DISPLAY"):
            continue
        if environment.get("XDG_SESSION_ID") == session_id:
            exact = environment
            if environment.get("DISPLAY"):
                break
        elif fallback is None:
            fallback = environment

    merged: dict[str, str] = {}
    useful_keys = {
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "XDG_SESSION_TYPE",
    }
    # Merge least-specific to most-specific so the exact session wins.
    for environment in (fallback or {}, leader_environment, exact or {}):
        for key in useful_keys:
            if environment.get(key):
                merged[key] = environment[key]
    return merged


def active_graphical_session() -> Optional[GraphicalSession]:
    if shutil.which("loginctl") is None:
        return None
    try:
        listed = run_command(
            ["loginctl", "list-sessions", "--no-legend", "--no-pager"],
            timeout=3.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    for line in listed.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        session_id = fields[0]
        properties = _session_properties(session_id)
        if properties.get("Active") != "yes" or properties.get("Remote") == "yes":
            continue
        if properties.get("Type") not in {"x11", "wayland"}:
            continue
        if properties.get("Class") not in {"user", "user-early", "background"}:
            continue
        try:
            uid = int(properties["User"])
            account = pwd.getpwuid(uid)
            leader = int(properties.get("Leader", "0") or "0")
        except (KeyError, ValueError):
            continue
        environment = _find_display_environment(uid, session_id, leader)
        if properties.get("Display") and not environment.get("DISPLAY"):
            environment["DISPLAY"] = properties["Display"]
        environment.setdefault("XDG_RUNTIME_DIR", f"/run/user/{uid}")
        environment.setdefault(
            "DBUS_SESSION_BUS_ADDRESS", f"unix:path=/run/user/{uid}/bus"
        )
        return GraphicalSession(
            session_id=session_id,
            uid=uid,
            gid=account.pw_gid,
            username=account.pw_name,
            environment=environment,
        )
    return None


def _graphical_session_environment(session: GraphicalSession) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(session.environment)
    environment.update(
        {
            "HOME": pwd.getpwuid(session.uid).pw_dir,
            "USER": session.username,
            "LOGNAME": session.username,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _run_in_graphical_session(
    session: GraphicalSession, command: list[str], timeout: float = 8.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        env=_graphical_session_environment(session),
        user=session.uid,
        group=session.gid,
        extra_groups=os.getgrouplist(session.username, session.gid),
    )


def _gnome_shell_major_version() -> Optional[int]:
    executable = shutil.which("gnome-shell")
    if not executable:
        return None
    try:
        result = run_command([executable, "--version"], timeout=3.0)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"(?:GNOME\s+Shell\s+)?(\d+)(?:\.\d+)?", result.stdout)
    return int(match.group(1)) if match else None


def _set_gnome_extension_enabled(
    session: Optional[GraphicalSession], enabled: bool
) -> bool:
    if session is None:
        return False
    gsettings = shutil.which("gsettings")
    if not gsettings:
        return False
    try:
        current_result = _run_in_graphical_session(
            session,
            [gsettings, "get", "org.gnome.shell", "enabled-extensions"],
            timeout=5.0,
        )
        if current_result.returncode != 0:
            return False
        raw_value = current_result.stdout.strip()
        if raw_value.startswith("@as "):
            raw_value = raw_value[4:]
        current = ast.literal_eval(raw_value)
        if not isinstance(current, list) or not all(
            isinstance(value, str) for value in current
        ):
            return False
        if enabled and GNOME_EXTENSION_UUID not in current:
            current.append(GNOME_EXTENSION_UUID)
        elif not enabled:
            current = [
                value for value in current if value != GNOME_EXTENSION_UUID
            ]
        serialized = "[" + ", ".join(_gvariant_string(value) for value in current) + "]"
        set_result = _run_in_graphical_session(
            session,
            [
                gsettings,
                "set",
                "org.gnome.shell",
                "enabled-extensions",
                serialized,
            ],
            timeout=5.0,
        )
        if set_result.returncode != 0:
            return False

        # If Shell has already noticed the new directory this activates it in
        # the current session.  Otherwise the gsettings entry activates it at
        # the next login, when Shell performs its normal extension scan.
        extensions_tool = shutil.which("gnome-extensions")
        if extensions_tool:
            _run_in_graphical_session(
                session,
                [
                    extensions_tool,
                    "enable" if enabled else "disable",
                    GNOME_EXTENSION_UUID,
                ],
                timeout=5.0,
            )
        return True
    except (OSError, ValueError, SyntaxError, subprocess.TimeoutExpired):
        return False


def install_gnome_panel_extension() -> tuple[bool, bool, Optional[int], Optional[str]]:
    """Install and pre-enable the GNOME top-bar marker for the active user."""
    major_version = _gnome_shell_major_version()
    if major_version is None or major_version < 40:
        return False, False, major_version, None

    source = (
        GNOME_EXTENSION_MODERN_JS
        if major_version >= 45
        else GNOME_EXTENSION_LEGACY_JS
    )
    metadata = {
        "uuid": GNOME_EXTENSION_UUID,
        "name": "XX Input Guard Marker",
        "description": "Shows XX at the top-left while input is frozen.",
        "shell-version": [str(major_version)],
        "version": 2,
    }
    try:
        GNOME_EXTENSION_PATH.mkdir(parents=True, exist_ok=True)
        os.chmod(GNOME_EXTENSION_PATH, 0o755)
        atomic_write(
            GNOME_EXTENSION_PATH / "metadata.json",
            (json.dumps(metadata, indent=2) + "\n").encode("utf-8"),
            0o644,
        )
        atomic_write(
            GNOME_EXTENSION_PATH / "extension.js",
            source.encode("utf-8"),
            0o644,
        )
        atomic_write(
            GNOME_EXTENSION_PATH / "stylesheet.css",
            GNOME_EXTENSION_STYLESHEET.encode("utf-8"),
            0o644,
        )
    except OSError as error:
        LOG.warning("Could not install GNOME top-bar extension: %s", error)
        return False, False, major_version, None

    session = active_graphical_session()
    enabled = _set_gnome_extension_enabled(session, True)
    return True, enabled, major_version, session.username if session else None


def remove_gnome_panel_extension() -> list[Path]:
    """Remove only files owned by this installer and disable their UUID."""
    _set_gnome_extension_enabled(active_graphical_session(), False)
    removed: list[Path] = []
    for path in (
        GNOME_EXTENSION_PATH / "stylesheet.css",
        GNOME_EXTENSION_PATH / "extension.js",
        GNOME_EXTENSION_PATH / "metadata.json",
    ):
        try:
            path.unlink()
            removed.append(path)
        except FileNotFoundError:
            pass
    try:
        GNOME_EXTENSION_PATH.rmdir()
        removed.append(GNOME_EXTENSION_PATH)
    except (FileNotFoundError, OSError):
        pass
    try:
        PANEL_STATE_PATH.unlink()
        removed.append(PANEL_STATE_PATH)
    except FileNotFoundError:
        pass
    return removed


def _publish_panel_marker() -> bool:
    try:
        PANEL_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(PANEL_RUNTIME_DIR, 0o755)
        atomic_write(PANEL_STATE_PATH, (PANEL_MARKER_TEXT + "\n").encode(), 0o644)
        return True
    except OSError as error:
        LOG.warning("Could not publish GNOME top-bar marker state: %s", error)
        return False


def _remove_panel_marker() -> None:
    try:
        PANEL_STATE_PATH.unlink()
    except FileNotFoundError:
        pass
    except OSError as error:
        LOG.warning("Could not remove GNOME top-bar marker state: %s", error)


def _session_uses_gnome_panel(session: Optional[GraphicalSession]) -> bool:
    if session is None or not GNOME_EXTENSION_PATH.is_dir():
        return False
    desktop = ":".join(
        [
            session.environment.get("XDG_CURRENT_DESKTOP", ""),
            session.environment.get("XDG_SESSION_DESKTOP", ""),
        ]
    ).upper()
    return "GNOME" in desktop or "UBUNTU" in desktop


class OverlayManager:
    """Publish the GNOME marker state, with a floating desktop fallback."""

    def __init__(self, text_template: str) -> None:
        self.text_template = text_template
        self._process: Optional[subprocess.Popen[bytes]] = None
        self._last_attempt = float("-inf")
        self._backend: Optional[str] = None
        self._panel_state_visible = False

    def show(self) -> None:
        if not self._panel_state_visible:
            self._panel_state_visible = _publish_panel_marker()

        if self._backend is None:
            session = active_graphical_session()
            if _session_uses_gnome_panel(session):
                self._backend = "gnome-panel"
                LOG.info(
                    "GNOME top-bar marker state published for %s",
                    session.username if session else "graphical session",
                )
            else:
                self._backend = "floating"

        if self._backend == "gnome-panel":
            return

        if self._process is not None:
            if self._process.poll() is None:
                return
            LOG.warning("Top-edge indicator exited with code %s", self._process.returncode)
            self._process = None
        now = time.monotonic()
        if now - self._last_attempt < 2.0:
            return
        self._last_attempt = now

        session = active_graphical_session()
        if session is None:
            LOG.warning("No active graphical session found for floating marker fallback")
            return

        environment = _graphical_session_environment(session)
        try:
            supplementary_groups = os.getgrouplist(session.username, session.gid)
            self._process = subprocess.Popen(
                [
                    str(Path(__file__).resolve()),
                    "overlay",
                    "--text-template",
                    self.text_template,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                user=session.uid,
                group=session.gid,
                extra_groups=supplementary_groups,
                start_new_session=True,
            )
            LOG.info(
                "Top-edge input-lock indicator started for %s", session.username
            )
        except (OSError, PermissionError) as error:
            LOG.warning("Could not start floating marker fallback: %s", error)
            self._process = None

    def hide(self) -> None:
        if self._panel_state_visible or PANEL_STATE_PATH.exists():
            _remove_panel_marker()
        self._panel_state_visible = False
        self._backend = None
        process = self._process
        self._process = None
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1.0)
        LOG.info("Top-edge input-lock indicator removed")


class DisplayAwakeManager:
    """Hold a system idle/sleep inhibitor only while input is frozen."""

    def __init__(self) -> None:
        self._process: Optional[subprocess.Popen[bytes]] = None
        self._last_attempt = float("-inf")

    def hold(self) -> None:
        if self._process is not None and self._process.poll() is None:
            return
        self._process = None
        now = time.monotonic()
        if now - self._last_attempt < 5.0:
            return
        self._last_attempt = now
        executable = shutil.which("systemd-inhibit")
        sleep_executable = shutil.which("sleep")
        if not executable or not sleep_executable:
            return
        try:
            self._process = subprocess.Popen(
                [
                    executable,
                    "--what=idle:sleep",
                    "--who=Phone Input Guard",
                    "--why=Keep the visible desktop on while local input is frozen",
                    "--mode=block",
                    sleep_executable,
                    "infinity",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            LOG.info("Display/system idle and sleep inhibitor active")
        except OSError as error:
            LOG.warning("Could not create idle/sleep inhibitor: %s", error)

    def release(self) -> None:
        process = self._process
        self._process = None
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()
        try:
            process.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            process.wait(timeout=1.0)
        LOG.info("Display/system idle and sleep inhibitor released")


class XColor(ctypes.Structure):
    _fields_ = [
        ("pixel", ctypes.c_ulong),
        ("red", ctypes.c_ushort),
        ("green", ctypes.c_ushort),
        ("blue", ctypes.c_ushort),
        ("flags", ctypes.c_byte),
        ("pad", ctypes.c_byte),
    ]


class XCharStruct(ctypes.Structure):
    _fields_ = [
        ("lbearing", ctypes.c_short),
        ("rbearing", ctypes.c_short),
        ("width", ctypes.c_short),
        ("ascent", ctypes.c_short),
        ("descent", ctypes.c_short),
        ("attributes", ctypes.c_ushort),
    ]


class XFontProp(ctypes.Structure):
    _fields_ = [("name", ctypes.c_ulong), ("card32", ctypes.c_ulong)]


class XFontStruct(ctypes.Structure):
    pass


XFontStruct._fields_ = [
    ("ext_data", ctypes.c_void_p),
    ("fid", ctypes.c_ulong),
    ("direction", ctypes.c_uint),
    ("min_char_or_byte2", ctypes.c_uint),
    ("max_char_or_byte2", ctypes.c_uint),
    ("min_byte1", ctypes.c_uint),
    ("max_byte1", ctypes.c_uint),
    ("all_chars_exist", ctypes.c_int),
    ("default_char", ctypes.c_uint),
    ("n_properties", ctypes.c_int),
    ("properties", ctypes.POINTER(XFontProp)),
    ("min_bounds", XCharStruct),
    ("max_bounds", XCharStruct),
    ("per_char", ctypes.POINTER(XCharStruct)),
    ("ascent", ctypes.c_int),
    ("descent", ctypes.c_int),
]


class XSetWindowAttributes(ctypes.Structure):
    _fields_ = [
        ("background_pixmap", ctypes.c_ulong),
        ("background_pixel", ctypes.c_ulong),
        ("border_pixmap", ctypes.c_ulong),
        ("border_pixel", ctypes.c_ulong),
        ("bit_gravity", ctypes.c_int),
        ("win_gravity", ctypes.c_int),
        ("backing_store", ctypes.c_int),
        ("backing_planes", ctypes.c_ulong),
        ("backing_pixel", ctypes.c_ulong),
        ("save_under", ctypes.c_int),
        ("event_mask", ctypes.c_long),
        ("do_not_propagate_mask", ctypes.c_long),
        ("override_redirect", ctypes.c_int),
        ("colormap", ctypes.c_ulong),
        ("cursor", ctypes.c_ulong),
    ]


def _primary_monitor_geometry(
    default_width: int, default_height: int
) -> tuple[int, int, int, int]:
    if shutil.which("xrandr") is None:
        return 0, 0, default_width, default_height
    try:
        result = run_command(["xrandr", "--listactivemonitors"], timeout=2.0)
    except (OSError, subprocess.TimeoutExpired):
        return 0, 0, default_width, default_height
    primary_pattern = re.compile(
        r"^\s*\d+:\s+\+\*\S+\s+(\d+)(?:/\d+)?x(\d+)(?:/\d+)?([+-]\d+)([+-]\d+)"
    )
    any_pattern = re.compile(
        r"^\s*\d+:\s+\+\*?\S+\s+(\d+)(?:/\d+)?x(\d+)(?:/\d+)?([+-]\d+)([+-]\d+)"
    )
    lines = result.stdout.splitlines()
    for pattern in (primary_pattern, any_pattern):
        for line in lines:
            match = pattern.match(line)
            if match:
                width, height, x_position, y_position = map(int, match.groups())
                return x_position, y_position, width, height
    return 0, 0, default_width, default_height


def _configure_xlib(library: Any) -> None:
    display_pointer = ctypes.c_void_p
    library.XOpenDisplay.argtypes = [ctypes.c_char_p]
    library.XOpenDisplay.restype = display_pointer
    library.XDefaultScreen.argtypes = [display_pointer]
    library.XDefaultScreen.restype = ctypes.c_int
    library.XRootWindow.argtypes = [display_pointer, ctypes.c_int]
    library.XRootWindow.restype = ctypes.c_ulong
    library.XDisplayWidth.argtypes = [display_pointer, ctypes.c_int]
    library.XDisplayWidth.restype = ctypes.c_int
    library.XDisplayHeight.argtypes = [display_pointer, ctypes.c_int]
    library.XDisplayHeight.restype = ctypes.c_int
    library.XWhitePixel.argtypes = [display_pointer, ctypes.c_int]
    library.XWhitePixel.restype = ctypes.c_ulong
    library.XBlackPixel.argtypes = [display_pointer, ctypes.c_int]
    library.XBlackPixel.restype = ctypes.c_ulong
    library.XDefaultColormap.argtypes = [display_pointer, ctypes.c_int]
    library.XDefaultColormap.restype = ctypes.c_ulong
    library.XAllocNamedColor.argtypes = [
        display_pointer,
        ctypes.c_ulong,
        ctypes.c_char_p,
        ctypes.POINTER(XColor),
        ctypes.POINTER(XColor),
    ]
    library.XAllocNamedColor.restype = ctypes.c_int
    library.XCreateSimpleWindow.argtypes = [
        display_pointer,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    library.XCreateSimpleWindow.restype = ctypes.c_ulong
    library.XChangeWindowAttributes.argtypes = [
        display_pointer,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.POINTER(XSetWindowAttributes),
    ]
    library.XChangeWindowAttributes.restype = ctypes.c_int
    library.XInternAtom.argtypes = [display_pointer, ctypes.c_char_p, ctypes.c_int]
    library.XInternAtom.restype = ctypes.c_ulong
    library.XChangeProperty.argtypes = [
        display_pointer,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_int,
    ]
    library.XChangeProperty.restype = ctypes.c_int
    library.XStoreName.argtypes = [display_pointer, ctypes.c_ulong, ctypes.c_char_p]
    library.XStoreName.restype = ctypes.c_int
    library.XLoadQueryFont.argtypes = [display_pointer, ctypes.c_char_p]
    library.XLoadQueryFont.restype = ctypes.POINTER(XFontStruct)
    library.XCreateGC.argtypes = [
        display_pointer,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    library.XCreateGC.restype = ctypes.c_void_p
    library.XSetFont.argtypes = [display_pointer, ctypes.c_void_p, ctypes.c_ulong]
    library.XSetForeground.argtypes = [display_pointer, ctypes.c_void_p, ctypes.c_ulong]
    library.XTextWidth.argtypes = [ctypes.POINTER(XFontStruct), ctypes.c_char_p, ctypes.c_int]
    library.XTextWidth.restype = ctypes.c_int
    library.XDrawString.argtypes = [
        display_pointer,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    library.XClearWindow.argtypes = [display_pointer, ctypes.c_ulong]
    library.XMapRaised.argtypes = [display_pointer, ctypes.c_ulong]
    library.XRaiseWindow.argtypes = [display_pointer, ctypes.c_ulong]
    library.XFlush.argtypes = [display_pointer]
    library.XFreeGC.argtypes = [display_pointer, ctypes.c_void_p]
    library.XFreeFont.argtypes = [display_pointer, ctypes.POINTER(XFontStruct)]
    library.XDestroyWindow.argtypes = [display_pointer, ctypes.c_ulong]
    library.XCloseDisplay.argtypes = [display_pointer]


def _set_x_atom_list(
    library: Any, display: Any, window: int, property_name: str, atom_names: list[str]
) -> None:
    property_atom = library.XInternAtom(display, property_name.encode("ascii"), 0)
    atoms = (ctypes.c_ulong * len(atom_names))(
        *(library.XInternAtom(display, name.encode("ascii"), 0) for name in atom_names)
    )
    library.XChangeProperty(
        display,
        window,
        property_atom,
        4,  # XA_ATOM
        32,
        0,  # PropModeReplace
        ctypes.cast(atoms, ctypes.POINTER(ctypes.c_ubyte)),
        len(atom_names),
    )


def _gvariant_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def _run_notification_fallback(text_template: str) -> int:
    """Wayland fallback when no X11/XWayland display is available."""
    stop_event = threading.Event()

    def stop_handler(_signal_number: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    notification_id: Optional[int] = None
    close_notification: Optional[Any] = None
    title = text_template.replace("{date}", datetime.now().strftime("%m%d%y"))
    try:
        try:
            import dbus  # type: ignore[import-not-found]

            bus = dbus.SessionBus()
            proxy = bus.get_object(
                "org.freedesktop.Notifications", "/org/freedesktop/Notifications"
            )
            interface = dbus.Interface(proxy, "org.freedesktop.Notifications")
            notification_id = int(
                interface.Notify(
                    "XX",
                    0,
                    "",
                    title,
                    "",
                    [],
                    {"urgency": dbus.Byte(1)},
                    0,
                )
            )
            close_notification = lambda: interface.CloseNotification(notification_id)
        except Exception as dbus_error:
            if shutil.which("gdbus"):
                result = run_command(
                    [
                        "gdbus",
                        "call",
                        "--session",
                        "--dest",
                        "org.freedesktop.Notifications",
                        "--object-path",
                        "/org/freedesktop/Notifications",
                        "--method",
                        "org.freedesktop.Notifications.Notify",
                        _gvariant_string("XX"),
                        "0",
                        _gvariant_string(""),
                        _gvariant_string(title),
                        _gvariant_string(""),
                        "[]",
                        "{'urgency': <byte 1>}",
                        "0",
                    ],
                    timeout=4.0,
                )
                match = re.search(r"uint32\s+(\d+)", result.stdout)
                if result.returncode != 0 or not match:
                    raise RuntimeError(result.stdout.strip() or str(dbus_error))
                notification_id = int(match.group(1))

                def close_with_gdbus() -> None:
                    run_command(
                        [
                            "gdbus",
                            "call",
                            "--session",
                            "--dest",
                            "org.freedesktop.Notifications",
                            "--object-path",
                            "/org/freedesktop/Notifications",
                            "--method",
                            "org.freedesktop.Notifications.CloseNotification",
                            str(notification_id),
                        ],
                        timeout=2.0,
                    )

                close_notification = close_with_gdbus
            elif shutil.which("notify-send"):
                result = run_command(
                    [
                        "notify-send",
                        "--print-id",
                        "--app-name=XX",
                        "--urgency=normal",
                        "--expire-time=0",
                        title,
                    ],
                    timeout=4.0,
                )
                match = re.search(r"(\d+)", result.stdout)
                if result.returncode != 0 or not match:
                    raise RuntimeError(result.stdout.strip() or str(dbus_error))
                notification_id = int(match.group(1))

                def close_with_notify_send() -> None:
                    run_command(
                        [
                            "notify-send",
                            "--replace-id",
                            str(notification_id),
                            "--expire-time=1",
                            " ",
                        ],
                        timeout=2.0,
                    )

                close_notification = close_with_notify_send
            else:
                raise RuntimeError(str(dbus_error))

        while not stop_event.wait(0.5):
            pass
        return 0
    except Exception as error:
        LOG.error("Cannot display X11 badge or Wayland notification: %s", error)
        while not stop_event.wait(0.5):
            pass
        return 3
    finally:
        if close_notification is not None and notification_id is not None:
            try:
                close_notification()
            except Exception:
                pass


def run_overlay(text_template: str) -> int:
    """Draw a top-center badge on the primary display until terminated."""
    display_name = os.environ.get("DISPLAY")
    library_name = ctypes.util.find_library("X11")
    if not display_name or not library_name:
        return _run_notification_fallback(text_template)

    library = ctypes.CDLL(library_name)
    _configure_xlib(library)
    display = library.XOpenDisplay(display_name.encode("utf-8"))
    if not display:
        return _run_notification_fallback(text_template)

    stop_event = threading.Event()

    def stop_handler(_signal_number: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    screen = library.XDefaultScreen(display)
    root = library.XRootWindow(display, screen)
    screen_width = library.XDisplayWidth(display, screen)
    screen_height = library.XDisplayHeight(display, screen)
    monitor_x, monitor_y, monitor_width, _ = _primary_monitor_geometry(
        screen_width, screen_height
    )
    foreground = library.XWhitePixel(display, screen)
    background = library.XBlackPixel(display, screen)
    colormap = library.XDefaultColormap(display, screen)
    allocated = XColor()
    exact = XColor()
    if library.XAllocNamedColor(
        display, colormap, b"#20242B", ctypes.byref(allocated), ctypes.byref(exact)
    ):
        background = allocated.pixel

    font: Optional[ctypes.POINTER(XFontStruct)] = None
    for font_name in (
        b"-misc-fixed-bold-r-normal--20-*-*-*-*-*-iso10646-1",
        b"10x20",
        b"9x15bold",
        b"fixed",
    ):
        candidate = library.XLoadQueryFont(display, font_name)
        if candidate:
            font = candidate
            break
    if font is None:
        library.XCloseDisplay(display)
        return _run_notification_fallback(text_template)

    text = text_template.replace("{date}", datetime.now().strftime("%m%d%y"))
    encoded = text.encode("ascii", errors="replace")
    text_width = library.XTextWidth(font, encoded, len(encoded))
    badge_width = min(monitor_width, max(260, text_width + 34))
    badge_height = max(28, font.contents.ascent + font.contents.descent + 12)
    x_position = monitor_x + max(0, (monitor_width - badge_width) // 2)
    y_position = monitor_y

    window = library.XCreateSimpleWindow(
        display,
        root,
        x_position,
        y_position,
        badge_width,
        badge_height,
        1,
        foreground,
        background,
    )
    attributes = XSetWindowAttributes()
    attributes.override_redirect = 1
    library.XChangeWindowAttributes(
        display, window, 1 << 9, ctypes.byref(attributes)  # CWOverrideRedirect
    )
    library.XStoreName(display, window, encoded)
    _set_x_atom_list(
        library,
        display,
        window,
        "_NET_WM_WINDOW_TYPE",
        ["_NET_WM_WINDOW_TYPE_DOCK"],
    )
    _set_x_atom_list(
        library,
        display,
        window,
        "_NET_WM_STATE",
        ["_NET_WM_STATE_ABOVE", "_NET_WM_STATE_STICKY"],
    )
    graphics_context = library.XCreateGC(display, window, 0, None)
    library.XSetFont(display, graphics_context, font.contents.fid)
    library.XSetForeground(display, graphics_context, foreground)
    library.XMapRaised(display, window)
    library.XFlush(display)

    screensaver_suspended = False
    xdg_screensaver = shutil.which("xdg-screensaver")
    if xdg_screensaver:
        try:
            result = run_command(
                [xdg_screensaver, "suspend", hex(window)], timeout=3.0
            )
            screensaver_suspended = result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            pass

    def draw_badge() -> None:
        current_text = text_template.replace(
            "{date}", datetime.now().strftime("%m%d%y")
        )
        current_encoded = current_text.encode("ascii", errors="replace")
        current_width = library.XTextWidth(font, current_encoded, len(current_encoded))
        text_x = max(8, (badge_width - current_width) // 2)
        baseline = max(font.contents.ascent + 5, badge_height - 7)
        library.XClearWindow(display, window)
        library.XDrawString(
            display,
            window,
            graphics_context,
            text_x,
            baseline,
            current_encoded,
            len(current_encoded),
        )
        library.XRaiseWindow(display, window)
        library.XFlush(display)

    draw_badge()

    try:
        while not stop_event.wait(0.35):
            draw_badge()
    finally:
        if screensaver_suspended and xdg_screensaver:
            try:
                run_command(
                    [xdg_screensaver, "resume", hex(window)], timeout=3.0
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        library.XFreeGC(display, graphics_context)
        library.XFreeFont(display, font)
        library.XDestroyWindow(display, window)
        library.XCloseDisplay(display)
    return 0


@dataclass(frozen=True)
class BluetoothConnectionInfo:
    """One result from BlueZ's management Get Connection Information command."""

    transport: Optional[str]
    rssi: Optional[int]
    explicitly_not_connected: bool = False


@dataclass(frozen=True)
class BluetoothPresenceSample:
    """Distinguish a live radio link from a phone that is actually nearby."""

    connected: bool
    present: bool
    transport: Optional[str]
    rssi: Optional[int]
    reason: str


class BluezPresence:
    """Read connection state and, for BR/EDR, controller-relative RSSI."""

    _MGMT_OP_GET_CONN_INFO = 0x0031
    _MGMT_EV_CMD_COMPLETE = 0x0001
    _MGMT_EV_CMD_STATUS = 0x0002
    _MGMT_STATUS_SUCCESS = 0x00
    _MGMT_STATUS_NOT_CONNECTED = 0x02
    _MGMT_INDEX_NONE = 0xFFFF
    _HCI_CHANNEL_CONTROL = 3

    def __init__(
        self,
        address: str,
        reconnect_every_seconds: float,
        bredr_rssi_proximity: bool = False,
        bredr_rssi_lock_below: int = 0,
    ) -> None:
        self.address = normalize_address(address)
        self.reconnect_every_seconds = reconnect_every_seconds
        self.bredr_rssi_proximity = bredr_rssi_proximity
        self.bredr_rssi_lock_below = bredr_rssi_lock_below
        self._last_reconnect = 0.0
        self._reconnect_process: Optional[subprocess.Popen[bytes]] = None
        # Once a disconnection or weak RSSI has frozen input, a transient RSSI
        # query failure must not release it.  Only a valid nearby sample clears
        # this latch.  At initial startup, an unavailable RSSI safely falls back
        # to the established Connected property for hardware compatibility.
        self._proximity_absent_latched = False
        self._dbus: Any = None
        self._dbus_properties: Any = None
        self._dbus_path: Optional[str] = None
        self._adapter_index = 0
        self._mgmt_socket: Optional[socket.socket] = None
        self._last_fallback_info_at = float("-inf")
        self._last_fallback_info = BluetoothConnectionInfo(None, None)
        self.backend = "bluetoothctl"
        self._initialize_dbus()
        if self.bredr_rssi_proximity:
            if self._initialize_management_socket():
                self.backend += " + native BR/EDR management RSSI"
            else:
                self.backend += " + bluetoothctl BR/EDR management RSSI"

    def _initialize_dbus(self) -> None:
        try:
            import dbus  # type: ignore[import-not-found]

            self._dbus = dbus
            system_bus = dbus.SystemBus()
            manager_object = system_bus.get_object("org.bluez", "/")
            manager = dbus.Interface(
                manager_object, "org.freedesktop.DBus.ObjectManager"
            )
            managed_objects = manager.GetManagedObjects()
            for object_path, interfaces in managed_objects.items():
                device = interfaces.get("org.bluez.Device1")
                if device and str(device.get("Address", "")).upper() == self.address:
                    self._dbus_path = str(object_path)
                    adapter_match = re.search(r"/hci(\d+)/", self._dbus_path)
                    if adapter_match:
                        self._adapter_index = int(adapter_match.group(1))
                    device_object = system_bus.get_object("org.bluez", object_path)
                    self._dbus_properties = dbus.Interface(
                        device_object, "org.freedesktop.DBus.Properties"
                    )
                    self.backend = "BlueZ D-Bus"
                    return
        except Exception as error:  # dbus is optional; bluetoothctl is the fallback.
            LOG.debug("D-Bus backend unavailable: %s", error)

    def _initialize_management_socket(self) -> bool:
        """Open one persistent kernel management socket for inexpensive polling."""
        try:
            bluetooth_family = getattr(socket, "AF_BLUETOOTH")
            hci_protocol = getattr(socket, "BTPROTO_HCI", 1)
            socket_flags = socket.SOCK_RAW | getattr(socket, "SOCK_CLOEXEC", 0)
            management_socket = socket.socket(
                bluetooth_family, socket_flags, hci_protocol
            )
            management_socket.settimeout(0.75)
            management_socket.bind(
                (self._MGMT_INDEX_NONE, self._HCI_CHANNEL_CONTROL)
            )
            self._mgmt_socket = management_socket
            return True
        except (AttributeError, OSError, TypeError) as error:
            LOG.debug("Native Bluetooth management socket unavailable: %s", error)
            self._mgmt_socket = None
            return False

    def _close_management_socket(self) -> None:
        management_socket = self._mgmt_socket
        self._mgmt_socket = None
        if management_socket is not None:
            try:
                management_socket.close()
            except OSError:
                pass

    @staticmethod
    def _bluetooth_address_bytes(address: str) -> bytes:
        # bdaddr_t stores the human-readable address in reverse octet order.
        return bytes(reversed(bytes.fromhex(address.replace(":", ""))))

    @staticmethod
    def _transport_name(address_type: int) -> Optional[str]:
        return {0: "BR/EDR", 1: "LE Public", 2: "LE Random"}.get(address_type)

    def _native_connection_info(self) -> Optional[BluetoothConnectionInfo]:
        management_socket = self._mgmt_socket
        if management_socket is None:
            return None

        parameters = self._bluetooth_address_bytes(self.address) + b"\x00"
        request = struct.pack(
            "<HHH",
            self._MGMT_OP_GET_CONN_INFO,
            self._adapter_index,
            len(parameters),
        ) + parameters
        try:
            management_socket.sendall(request)
            deadline = time.monotonic() + 0.75
            while time.monotonic() < deadline:
                packet = management_socket.recv(4096)
                if len(packet) < 6:
                    continue
                event_code, controller_index, parameter_length = struct.unpack_from(
                    "<HHH", packet
                )
                if controller_index != self._adapter_index:
                    continue
                event_data = packet[6 : 6 + parameter_length]
                if len(event_data) < 3:
                    continue
                if event_code not in (
                    self._MGMT_EV_CMD_COMPLETE,
                    self._MGMT_EV_CMD_STATUS,
                ):
                    continue
                command_opcode, status = struct.unpack_from("<HB", event_data)
                if command_opcode != self._MGMT_OP_GET_CONN_INFO:
                    continue
                if status == self._MGMT_STATUS_NOT_CONNECTED:
                    return BluetoothConnectionInfo(
                        "BR/EDR", None, explicitly_not_connected=True
                    )
                if status != self._MGMT_STATUS_SUCCESS:
                    LOG.debug(
                        "Native Bluetooth connection-info status: 0x%02x", status
                    )
                    return None
                if event_code != self._MGMT_EV_CMD_COMPLETE or len(event_data) < 13:
                    return None
                return_parameters = event_data[3:]
                address_type = return_parameters[6]
                rssi = struct.unpack_from("<b", return_parameters, 7)[0]
                if rssi == 127:
                    rssi = None
                return BluetoothConnectionInfo(
                    self._transport_name(address_type), rssi
                )
        except (OSError, socket.timeout, struct.error) as error:
            LOG.debug("Native Bluetooth management query failed: %s", error)
            self._close_management_socket()
        return None

    def connected(self) -> bool:
        if self._dbus_properties is not None:
            try:
                value = self._dbus_properties.Get("org.bluez.Device1", "Connected")
                return bool(value)
            except Exception as error:
                LOG.debug("D-Bus query failed; using bluetoothctl: %s", error)
                self._dbus_properties = None

        if shutil.which("bluetoothctl") is None:
            LOG.error("bluetoothctl is unavailable; treating phone as absent")
            return False
        try:
            result = run_command(
                ["bluetoothctl", "info", self.address], timeout=1.5
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            LOG.warning("Bluetooth query failed; treating phone as absent: %s", error)
            return False
        return bool(re.search(r"(?mi)^\s*Connected:\s*yes\s*$", result.stdout))

    def connection_info(self) -> BluetoothConnectionInfo:
        """Read the live controller RSSI without confusing BR/EDR with dBm."""
        native_result = self._native_connection_info()
        if native_result is not None:
            return native_result
        now = time.monotonic()
        if now - self._last_fallback_info_at < 0.75:
            return self._last_fallback_info
        if shutil.which("bluetoothctl") is None:
            return BluetoothConnectionInfo(None, None)
        try:
            result = run_command(
                ["bluetoothctl", "mgmt.conn-info", self.address], timeout=1.5
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            LOG.debug("Bluetooth connection-info query unavailable: %s", error)
            info = BluetoothConnectionInfo(None, None)
            self._last_fallback_info_at = time.monotonic()
            self._last_fallback_info = info
            return info

        output = "\n".join(part for part in (result.stdout, result.stderr) if part)
        transport_match = re.search(
            r"(?mi)^(?:Connection Information|Get Conn Info)\s+for\s+"
            + re.escape(self.address)
            + r"\s+\(([^)]+)\)",
            output,
        )
        transport = transport_match.group(1).strip() if transport_match else None
        if re.search(r"(?i)status\s+0x02\s+\(Not Connected\)", output):
            info = BluetoothConnectionInfo(
                transport, None, explicitly_not_connected=True
            )
            self._last_fallback_info_at = time.monotonic()
            self._last_fallback_info = info
            return info

        rssi_match = re.search(r"(?mi)^\s*RSSI\s+(-?\d+)\b", output)
        if not rssi_match:
            info = BluetoothConnectionInfo(transport, None)
            self._last_fallback_info_at = time.monotonic()
            self._last_fallback_info = info
            return info
        rssi = int(rssi_match.group(1))
        # The management API reserves 127 for unavailable/unknown RSSI.
        if rssi == 127:
            rssi = None
        info = BluetoothConnectionInfo(transport, rssi)
        self._last_fallback_info_at = time.monotonic()
        self._last_fallback_info = info
        return info

    def sample(self) -> BluetoothPresenceSample:
        """Return nearby/absent state with no time-based absence grace."""
        connected = self.connected()
        if not connected:
            self._proximity_absent_latched = True
            return BluetoothPresenceSample(
                connected=False,
                present=False,
                transport=None,
                rssi=None,
                reason="Bluetooth disconnected",
            )

        if not self.bredr_rssi_proximity:
            self._proximity_absent_latched = False
            return BluetoothPresenceSample(
                connected=True,
                present=True,
                transport=None,
                rssi=None,
                reason="Bluetooth connected",
            )

        info = self.connection_info()
        if info.explicitly_not_connected:
            self._proximity_absent_latched = True
            return BluetoothPresenceSample(
                connected=False,
                present=False,
                transport=info.transport,
                rssi=None,
                reason="Bluetooth management interface reports disconnected",
            )

        if info.transport == "BR/EDR" and info.rssi is not None:
            if info.rssi < self.bredr_rssi_lock_below:
                self._proximity_absent_latched = True
                return BluetoothPresenceSample(
                    connected=True,
                    present=False,
                    transport=info.transport,
                    rssi=info.rssi,
                    reason=(
                        f"connected but distant: BR/EDR RSSI {info.rssi} < "
                        f"{self.bredr_rssi_lock_below}"
                    ),
                )
            self._proximity_absent_latched = False
            return BluetoothPresenceSample(
                connected=True,
                present=True,
                transport=info.transport,
                rssi=info.rssi,
                reason=(
                    f"nearby: BR/EDR RSSI {info.rssi} >= "
                    f"{self.bredr_rssi_lock_below}"
                ),
            )

        if self._proximity_absent_latched:
            return BluetoothPresenceSample(
                connected=True,
                present=False,
                transport=info.transport,
                rssi=info.rssi,
                reason="connected; waiting for a valid nearby BR/EDR RSSI",
            )
        return BluetoothPresenceSample(
            connected=True,
            present=True,
            transport=info.transport,
            rssi=info.rssi,
            reason="connected; BR/EDR RSSI unavailable, using connection fallback",
        )

    def maybe_reconnect(self) -> None:
        if shutil.which("bluetoothctl") is None:
            return
        if self._reconnect_process is not None:
            if self._reconnect_process.poll() is None:
                return
            self._reconnect_process = None
        now = time.monotonic()
        if now - self._last_reconnect < self.reconnect_every_seconds:
            return
        self._last_reconnect = now
        try:
            self._reconnect_process = subprocess.Popen(
                ["bluetoothctl", "--timeout", "3", "connect", self.address],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=command_environment(),
            )
        except OSError as error:
            LOG.warning("Could not start Bluetooth reconnect attempt: %s", error)

    def stop(self) -> None:
        self._close_management_socket()
        process = self._reconnect_process
        if process is not None and process.poll() is None:
            process.terminate()


def load_config(path: Path) -> dict[str, Any]:
    try:
        supplied = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SystemExit(f"Configuration does not exist: {path}") from error
    except json.JSONDecodeError as error:
        raise SystemExit(f"Invalid JSON in {path}: {error}") from error
    if not isinstance(supplied, dict):
        raise SystemExit(f"Configuration root must be an object: {path}")
    config = DEFAULT_CONFIG.copy()
    config.update(supplied)
    try:
        config["phone_address"] = normalize_address(str(config["phone_address"]))
        config["poll_seconds"] = max(0.10, float(config["poll_seconds"]))
        config["reconnect_every_seconds"] = max(
            0.5, float(config["reconnect_every_seconds"])
        )
        if not isinstance(config["bredr_rssi_proximity"], bool):
            raise ValueError("bredr_rssi_proximity must be true or false")
        config["bredr_rssi_lock_below"] = int(
            config["bredr_rssi_lock_below"]
        )
        if not -127 <= config["bredr_rssi_lock_below"] <= 126:
            raise ValueError("bredr_rssi_lock_below must be between -127 and 126")
        config["rescue_power_cycles"] = max(
            3, int(config["rescue_power_cycles"])
        )
        config["rescue_window_seconds"] = max(
            10.0, float(config["rescue_window_seconds"])
        )
        config["power_state_debounce_seconds"] = max(
            0.5, float(config["power_state_debounce_seconds"])
        )
        if not isinstance(config["excluded_wifi_connections"], list):
            raise ValueError("excluded_wifi_connections must be a list")
        config["excluded_wifi_connections"] = _deduplicate_names(
            config["excluded_wifi_connections"]
        )
        config["wifi_poll_seconds"] = max(
            0.5, float(config["wifi_poll_seconds"])
        )
        config["wifi_startup_settle_seconds"] = max(
            0.0, float(config["wifi_startup_settle_seconds"])
        )
        config["locked_banner_template"] = str(config["locked_banner_template"])
        if not config["locked_banner_template"].strip():
            raise ValueError("locked_banner_template cannot be empty")
        if not isinstance(config["exclude_device_name_regex"], list):
            raise ValueError("exclude_device_name_regex must be a list")
        for pattern in config["exclude_device_name_regex"]:
            re.compile(str(pattern))
    except (TypeError, ValueError, re.error) as error:
        raise SystemExit(f"Invalid setting in {path}: {error}") from error
    return config


def run_guard(config_path: Path, dry_run: bool = False) -> int:
    if not dry_run:
        require_root("The input guard")
    config = load_config(config_path)
    stop_event = threading.Event()

    def stop_handler(_signal_number: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)

    presence = BluezPresence(
        config["phone_address"],
        config["reconnect_every_seconds"],
        config["bredr_rssi_proximity"],
        config["bredr_rssi_lock_below"],
    )
    grabber = InputGrabber(config["exclude_device_name_regex"])
    power_rescue = PowerCycleRescue(
        config["rescue_power_cycles"],
        config["rescue_window_seconds"],
        config["power_state_debounce_seconds"],
    )
    overlay = OverlayManager(config["locked_banner_template"])
    display_awake = DisplayAwakeManager()
    wifi_monitor = WifiExclusionMonitor(
        config["excluded_wifi_connections"],
        config["wifi_poll_seconds"],
        config["wifi_startup_settle_seconds"],
    )
    wifi_monitor.start()
    rescue_active = False
    previous_present: Optional[bool] = None
    previous_link_connected: Optional[bool] = None
    previous_wifi_decision: Optional[WifiPolicyDecision] = None

    LOG.info(
        "Watching %s via %s; absence grace is 0 seconds",
        config["phone_address"],
        presence.backend,
    )
    if config["bredr_rssi_proximity"]:
        LOG.info(
            "BR/EDR proximity rule: freeze on first RSSI below %d; "
            "release at %d or above",
            config["bredr_rssi_lock_below"],
            config["bredr_rssi_lock_below"],
        )
    LOG.info("The desktop stays visible; only the discreet XX panel marker is added")
    if power_rescue.supply_names:
        LOG.info(
            "Emergency rescue watches external power: %s",
            ", ".join(power_rescue.supply_names),
        )
    else:
        LOG.warning(
            "No external power_supply online sensor found; power-cycle rescue is unavailable"
        )
    if config["excluded_wifi_connections"]:
        LOG.info(
            "Wi-Fi exclusions: %s",
            ", ".join(config["excluded_wifi_connections"]),
        )
    else:
        LOG.warning("No Wi-Fi exclusions configured; guard is active on every network")

    try:
        while not stop_event.is_set():
            wifi_decision = wifi_monitor.decision()
            if wifi_decision != previous_wifi_decision:
                LOG.info(
                    "Guard policy: %s (%s)%s",
                    "PAUSED" if wifi_decision.paused else "ACTIVE",
                    wifi_decision.reason,
                    (
                        "; active Wi-Fi: " + ", ".join(wifi_decision.active_names)
                        if wifi_decision.active_names
                        else ""
                    ),
                )
                if wifi_decision.paused:
                    rescue_active = False
                    power_rescue.reset()
                previous_wifi_decision = wifi_decision

            if wifi_decision.paused:
                overlay.hide()
                display_awake.release()
                if grabber.is_grabbed:
                    grabber.release_all()
                stop_event.wait(config["poll_seconds"])
                continue

            sample = presence.sample()
            present = sample.present

            if (
                present != previous_present
                or sample.connected != previous_link_connected
            ):
                LOG.info(
                    "Phone state: %s (%s)",
                    "NEARBY" if present else "ABSENT",
                    sample.reason,
                )
                previous_present = present
                previous_link_connected = sample.connected

            if dry_run:
                if not sample.connected and bool(config["automatic_reconnect"]):
                    presence.maybe_reconnect()
                stop_event.wait(config["poll_seconds"])
                continue

            if present:
                if rescue_active:
                    LOG.info("Phone returned nearby; normal instant-freeze rule re-armed")
                rescue_active = False
                power_rescue.reset()

            elif not rescue_active and power_rescue.update():
                rescue_active = True
                LOG.warning(
                    "Emergency power-cycle rescue accepted; input released until phone returns nearby"
                )

            if not sample.connected and bool(config["automatic_reconnect"]):
                presence.maybe_reconnect()

            if present or rescue_active:
                overlay.hide()
                display_awake.release()
                if grabber.is_grabbed:
                    grabber.release_all()
            else:
                # No counter and no timer: the first disconnected or negative
                # BR/EDR RSSI result reaches this branch immediately.
                grabber.grab_all()
                grabber.discard_input()
                display_awake.hold()
                overlay.show()

            stop_event.wait(config["poll_seconds"])
    finally:
        overlay.hide()
        display_awake.release()
        grabber.release_all()
        presence.stop()
        wifi_monitor.stop()
        LOG.info("Stopped; all input grabs released")
    return 0


def bluetooth_connected(address: str) -> bool:
    return BluezPresence(address, reconnect_every_seconds=2.0).connected()


def configured_bluetooth_presence(config: dict[str, Any]) -> BluetoothPresenceSample:
    presence = BluezPresence(
        config["phone_address"],
        config["reconnect_every_seconds"],
        config["bredr_rssi_proximity"],
        config["bredr_rssi_lock_below"],
    )
    try:
        return presence.sample()
    finally:
        presence.stop()


def _raw_config(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}
    return value if isinstance(value, dict) else {}


def write_config(path: Path, config: dict[str, Any]) -> None:
    atomic_write(
        path,
        (json.dumps(config, indent=2) + "\n").encode("utf-8"),
        0o600,
    )


def matching_wifi_exclusions(
    excluded_names: Iterable[str], current_names: Optional[Iterable[str]]
) -> list[str]:
    if current_names is None:
        return []
    excluded = {name.casefold(): name for name in _deduplicate_names(excluded_names)}
    matches: list[str] = []
    for current in current_names:
        configured = excluded.get(current.casefold())
        if configured and configured not in matches:
            matches.append(configured)
    return matches


def install(args: argparse.Namespace) -> int:
    require_root("Installation")
    if shutil.which("systemctl") is None:
        raise SystemExit("systemctl was not found; this installer requires systemd.")
    if shutil.which("bluetoothctl") is None:
        raise SystemExit("bluetoothctl was not found. Install BlueZ first.")

    existing_config = _raw_config(CONFIG_PATH)
    existing_phone = existing_config.get("phone_address")
    address = choose_phone(args.phone or (str(existing_phone) if existing_phone else None))

    existing_wifi = existing_config.get("excluded_wifi_connections", [])
    if not isinstance(existing_wifi, list):
        existing_wifi = []
    existing_policy_revision = existing_config.get("wifi_policy_revision")
    existing_proximity_revision = existing_config.get(
        "proximity_policy_revision"
    )
    if args.clear_wifi_exclusions:
        wifi_exclusions = []
    elif args.exclude_wifi is not None:
        wifi_exclusions = _deduplicate_names(args.exclude_wifi)
    elif args.reconfigure_wifi:
        wifi_exclusions = choose_wifi_exclusions(
            None,
            [str(value) for value in existing_wifi],
            prompt_for_values=True,
        )
    elif existing_policy_revision == WIFI_POLICY_REVISION:
        wifi_exclusions = _deduplicate_names(str(value) for value in existing_wifi)
    else:
        # Apply this revision's requested home/hotspot policy exactly once when
        # upgrading an older installation, then preserve later user changes.
        wifi_exclusions = list(DEFAULT_WIFI_EXCLUSIONS)

    source = Path(__file__).resolve()
    atomic_write(INSTALL_PATH, source.read_bytes(), 0o755)
    config = DEFAULT_CONFIG.copy()
    config.update(existing_config)
    config["phone_address"] = address
    config["excluded_wifi_connections"] = wifi_exclusions
    config["wifi_policy_revision"] = WIFI_POLICY_REVISION
    config["locked_banner_template"] = PANEL_MARKER_TEXT
    if existing_proximity_revision != PROXIMITY_POLICY_REVISION:
        # Upgrade the old connection-only detector to the threshold established
        # by the user's measured outbound/return trace.  Once this policy has
        # been installed, preserve any later manual threshold adjustment.
        config["bredr_rssi_proximity"] = True
        config["bredr_rssi_lock_below"] = 0
    config["proximity_policy_revision"] = PROXIMITY_POLICY_REVISION
    # This is an intentional policy update, so upgrade an existing 30-second
    # installation instead of allowing config.update() to retain the old value.
    config["rescue_window_seconds"] = 60.0
    write_config(CONFIG_PATH, config)
    config = load_config(CONFIG_PATH)
    atomic_write(SERVICE_PATH, SYSTEMD_SERVICE.encode("utf-8"), 0o644)
    panel_installed, panel_enabled, panel_version, panel_user = (
        install_gnome_panel_extension()
    )
    run_command(["systemctl", "daemon-reload"], check=True)

    print(f"Installed {INSTALL_PATH}")
    print(f"Configured phone {address}")
    if wifi_exclusions:
        print("Wi-Fi exclusions: " + ", ".join(wifi_exclusions))
    else:
        print("Wi-Fi exclusions: NONE (guard remains active on every network)")
    print("Battery power is not an activation or pause criterion.")
    if config["bredr_rssi_proximity"]:
        print(
            "BR/EDR proximity: freeze immediately below RSSI "
            f"{config['bredr_rssi_lock_below']}; release at or above it."
        )
    if panel_installed:
        print(
            "GNOME top-bar marker installed"
            + (f" for Shell {panel_version}" if panel_version is not None else "")
            + "."
        )
        if panel_enabled and panel_user:
            print(f"GNOME marker enabled for {panel_user}.")
        else:
            print(
                "After logging in, enable it once with: "
                f"gnome-extensions enable {GNOME_EXTENSION_UUID}"
            )
        print("REQUIRED ONCE: fully log out and back in so GNOME Shell loads the marker.")
    else:
        print("GNOME Shell was not detected; the floating marker fallback remains active.")

    phone_sample = configured_bluetooth_presence(config)
    current_wifi = active_wifi_names()
    wifi_matches = matching_wifi_exclusions(wifi_exclusions, current_wifi)
    if not phone_sample.connected:
        try:
            run_command(
                ["bluetoothctl", "--timeout", "8", "connect", address],
                timeout=10.0,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        phone_sample = configured_bluetooth_presence(config)

    if args.no_start:
        print("Not started (--no-start). Arm later with:")
        print(f"  sudo {INSTALL_PATH} arm")
        return 0

    if not phone_sample.present and not wifi_matches and not args.force_start:
        print(f"\nSafety stop: the selected phone is not nearby ({phone_sample.reason}).")
        print("The service was installed but NOT enabled or started, so input remains usable.")
        print("Bring/connect the phone, then run:")
        print(f"  sudo {INSTALL_PATH} arm")
        return 2

    if not phone_sample.present:
        if wifi_matches:
            print("Phone is absent, but the active excluded Wi-Fi keeps input released.")
        else:
            print("WARNING: --force-start selected while the phone is absent; input will freeze.")
    # A reinstall replaces the executable while an older daemon may still be
    # running, so explicitly restart instead of relying on enable --now.
    run_command(["systemctl", "enable", APP_NAME], check=True)
    run_command(["systemctl", "restart", APP_NAME], check=True)
    print(
        "Service enabled and started. Input will freeze on the first "
        "disconnection or distant-RSSI result."
    )
    print(f"Top-left GNOME panel marker: {PANEL_MARKER_TEXT}")
    print("The visible desktop is kept on; applications continue running.")
    print("At startup, home/hotspot exclusions pause the guard automatically.")
    print(
        "Emergency recovery: unplug and reconnect charger 3 times within "
        f"{config['rescue_window_seconds']:.0f} seconds."
    )
    print("Each power state must remain stable for at least 1 second.")
    return 0


def arm(args: argparse.Namespace) -> int:
    require_root("Arming")
    config = load_config(CONFIG_PATH)
    phone_sample = configured_bluetooth_presence(config)
    wifi_matches = matching_wifi_exclusions(
        config["excluded_wifi_connections"], active_wifi_names()
    )
    if not phone_sample.present and not wifi_matches and not args.force:
        raise SystemExit(
            "Phone is not nearby; service not started. Bring/connect it or use --force. "
            f"Detector: {phone_sample.reason}."
        )
    run_command(["systemctl", "enable", "--now", APP_NAME], check=True)
    print("Phone Input Guard is enabled and running.")
    if wifi_matches:
        print("It is currently paused by Wi-Fi exclusion: " + ", ".join(wifi_matches))
    return 0


def configure_wifi(args: argparse.Namespace) -> int:
    require_root("Wi-Fi configuration")
    config = load_config(CONFIG_PATH)
    if args.clear:
        explicit: Optional[list[str]] = []
    else:
        explicit = args.exclude_wifi
    selected = choose_wifi_exclusions(
        explicit,
        config["excluded_wifi_connections"],
        prompt_for_values=explicit is None,
    )
    config["excluded_wifi_connections"] = selected
    config["wifi_policy_revision"] = WIFI_POLICY_REVISION
    write_config(CONFIG_PATH, config)
    run_command(["systemctl", "try-restart", APP_NAME], check=False)
    if selected:
        print("Wi-Fi exclusions: " + ", ".join(selected))
    else:
        print("Wi-Fi exclusions cleared; guard is active on every network.")
    print("Battery power remains irrelevant to activation.")
    return 0


def disarm(_args: argparse.Namespace) -> int:
    require_root("Disarming")
    run_command(["systemctl", "disable", "--now", APP_NAME], check=False)
    _remove_panel_marker()
    print("Phone Input Guard is stopped and disabled; input is released.")
    return 0


def uninstall(_args: argparse.Namespace) -> int:
    require_root("Uninstallation")
    run_command(["systemctl", "disable", "--now", APP_NAME], check=False)
    removed: list[Path] = []
    for path in (SERVICE_PATH, CONFIG_PATH, INSTALL_PATH):
        try:
            path.unlink()
            removed.append(path)
        except FileNotFoundError:
            pass
    removed.extend(remove_gnome_panel_extension())
    run_command(["systemctl", "daemon-reload"], check=False)
    print("Removed:")
    for path in removed:
        print(f"  {path}")
    print("The removed files are not recoverable unless you retained this installer.")
    return 0


def check_setup(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    config = load_config(config_path)
    presence = BluezPresence(
        config["phone_address"],
        config["reconnect_every_seconds"],
        config["bredr_rssi_proximity"],
        config["bredr_rssi_lock_below"],
    )
    phone_sample = presence.sample()
    presence.stop()
    current_wifi = active_wifi_names()
    wifi_matches = matching_wifi_exclusions(
        config["excluded_wifi_connections"], current_wifi
    )
    wifi_paused = bool(wifi_matches)
    print(f"Phone:   {config['phone_address']}")
    print(f"Backend: {presence.backend}")
    if wifi_paused:
        state = "PAUSED BY WI-FI / INPUT RELEASED"
    elif phone_sample.present:
        state = "ACTIVE / PHONE NEARBY / INPUT RELEASED"
    elif phone_sample.connected:
        state = "ACTIVE / PHONE CONNECTED BUT DISTANT / INPUT WOULD FREEZE"
    else:
        state = "ACTIVE / PHONE ABSENT / INPUT WOULD FREEZE"
    print(f"State:   {state}")
    print(f"Detector: {phone_sample.reason}")
    if phone_sample.transport is not None:
        print(f"Transport: {phone_sample.transport}")
    if phone_sample.rssi is not None:
        print(f"Connection RSSI: {phone_sample.rssi}")
    if config["bredr_rssi_proximity"]:
        print(
            "BR/EDR threshold: distant below "
            f"{config['bredr_rssi_lock_below']}; nearby at or above it"
        )
    if current_wifi is None:
        print("Active Wi-Fi: unavailable")
    elif current_wifi:
        print("Active Wi-Fi: " + ", ".join(sorted(current_wifi, key=str.casefold)))
    else:
        print("Active Wi-Fi: none")
    if config["excluded_wifi_connections"]:
        print("Wi-Fi exclusions: " + ", ".join(config["excluded_wifi_connections"]))
    else:
        print("Wi-Fi exclusions: none")
    print("Battery activation criterion: NONE")
    print("Absence grace: 0 seconds")
    print("Display: kept on while frozen; no screen lock, logout, or app pause")
    print(f"On-screen marker: {PANEL_MARKER_TEXT} (GNOME panel, top-left)")
    power_rescue = PowerCycleRescue(
        config["rescue_power_cycles"],
        config["rescue_window_seconds"],
        config["power_state_debounce_seconds"],
    )
    print(
        "Emergency rescue: "
        f"{config['rescue_power_cycles']} full charger cycles within "
        f"{config['rescue_window_seconds']:.0f} seconds"
    )
    if power_rescue.supply_names:
        print(f"Power sensor(s): {', '.join(power_rescue.supply_names)}")
    else:
        print("Power sensor(s): NONE DETECTED — rescue unavailable on this machine")
    grabber = InputGrabber(config["exclude_device_name_regex"])
    candidates = grabber.candidate_devices()
    print("Input devices that will be frozen:")
    if not candidates:
        print("  None detected (root may be required to inspect /dev/input).")
    for path, name, kind in candidates:
        print(f"  {path}: {name} [{kind}]")
    return 0 if phone_sample.present or wifi_paused else 1


def list_phones(_args: argparse.Namespace) -> int:
    devices = paired_devices()
    if not devices:
        print("No paired Bluetooth devices found.")
        return 1
    for address, name in devices:
        state = "connected" if bluetooth_connected(address) else "disconnected"
        print(f"{address}  {state:12}  {name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Instantly freeze Linux keyboard/mouse input when a paired Bluetooth "
            "phone disconnects or its BR/EDR connection RSSI becomes distant, "
            "without touching the display or desktop session."
        )
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="install the systemd service")
    install_parser.add_argument(
        "--phone", metavar="MAC", help="paired phone Bluetooth address"
    )
    install_parser.add_argument(
        "--no-start", action="store_true", help="install without starting the service"
    )
    install_parser.add_argument(
        "--force-start",
        action="store_true",
        help="start even if the phone is currently absent/distant (input will freeze)",
    )
    install_wifi_group = install_parser.add_mutually_exclusive_group()
    install_wifi_group.add_argument(
        "--exclude-wifi",
        metavar="NAME",
        action="append",
        help="Wi-Fi profile or SSID that pauses the guard; repeat for home and hotspot",
    )
    install_wifi_group.add_argument(
        "--reconfigure-wifi",
        action="store_true",
        help="interactively choose home and phone-hotspot exclusions",
    )
    install_wifi_group.add_argument(
        "--clear-wifi-exclusions",
        action="store_true",
        help="remove all Wi-Fi exclusions",
    )
    install_parser.set_defaults(function=install)

    arm_parser = subparsers.add_parser("arm", help="enable and start the service")
    arm_parser.add_argument(
        "--force", action="store_true", help="start while the phone is absent/distant"
    )
    arm_parser.set_defaults(function=arm)

    wifi_parser = subparsers.add_parser(
        "configure-wifi", help="set home and phone-hotspot exclusion networks"
    )
    wifi_group = wifi_parser.add_mutually_exclusive_group()
    wifi_group.add_argument(
        "--exclude-wifi",
        metavar="NAME",
        action="append",
        help="exact Wi-Fi profile or SSID; repeat to set both exclusions",
    )
    wifi_group.add_argument(
        "--clear", action="store_true", help="remove all Wi-Fi exclusions"
    )
    wifi_parser.set_defaults(function=configure_wifi)

    disarm_parser = subparsers.add_parser("disarm", help="stop and disable the service")
    disarm_parser.set_defaults(function=disarm)

    run_parser = subparsers.add_parser("run", help="run the guard (normally via systemd)")
    run_parser.add_argument("--config", default=str(CONFIG_PATH))
    run_parser.add_argument(
        "--dry-run", action="store_true", help="report presence without grabbing input"
    )
    run_parser.set_defaults(
        function=lambda values: run_guard(Path(values.config), values.dry_run)
    )

    overlay_parser = subparsers.add_parser(
        "overlay", help="run the floating marker fallback (normally internal)"
    )
    overlay_parser.add_argument(
        "--text-template", default=DEFAULT_CONFIG["locked_banner_template"]
    )
    overlay_parser.set_defaults(
        function=lambda values: run_overlay(values.text_template)
    )

    check_parser = subparsers.add_parser("check", help="check phone state and input devices")
    check_parser.add_argument("--config", default=str(CONFIG_PATH))
    check_parser.set_defaults(function=check_setup)

    list_parser = subparsers.add_parser("list-phones", help="list paired Bluetooth devices")
    list_parser.set_defaults(function=list_phones)

    uninstall_parser = subparsers.add_parser("uninstall", help="remove the service and config")
    uninstall_parser.set_defaults(function=uninstall)
    return parser


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.function(args))
    except subprocess.CalledProcessError as error:
        output = (error.stdout or "").strip()
        if output:
            LOG.error("Command failed: %s", output)
        else:
            LOG.error("Command failed with exit status %s", error.returncode)
        return error.returncode or 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
