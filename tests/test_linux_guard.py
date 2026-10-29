"""Simulated radio, power and evdev tests. Never touches Bluetooth or real input."""

import argparse
import asyncio
import contextlib
import errno
import importlib.util
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "phone-input-guard.py"
SPEC = importlib.util.spec_from_file_location("linux_guard", SOURCE)
guard = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = guard
SPEC.loader.exec_module(guard)

# Synthetic fixtures only; never copy an actual phone UUID, MAC or SSID here.
UUID = "11111111-1111-4111-8111-111111111111"
OTHER_UUID = "22222222-2222-4222-8222-222222222222"
MAC = "00:00:00:00:00:01"


def ble_config(**overrides):
    return guard.validate_config({"proximity_mode": "ble", "ble_service_uuid": UUID,
                                  "excluded_wifi_connections": [], **overrides})


def packet(rssi=-70, uuids=None):
    return SimpleNamespace(rssi=rssi, service_uuids=[UUID] if uuids is None else uuids)


def sample(near):
    return guard.BluetoothPresenceSample(near, near, "BLE advertisement", -70 if near else None, "simulated")


class ProximityTests(unittest.TestCase):
    def setUp(self):
        self.state = guard.BleProximityState(UUID, -84, -80, 11)

    def add(self, rssi, now=0, uuids=None):
        return self.state.advertisement([UUID] if uuids is None else uuids, rssi, now)

    def test_startup_and_hysteresis_band_require_strong_packet(self):
        self.assertFalse(self.state.sample(0).present)
        self.add(-82)
        self.assertFalse(self.state.sample(0).present)
        self.add(-80, 1)
        self.assertTrue(self.state.sample(1).present)
        self.add(-82, 2)
        self.assertTrue(self.state.sample(2).present)
        self.add(-84, 3)
        self.assertFalse(self.state.sample(3).present)
        self.add(-82, 4)
        self.assertFalse(self.state.sample(4).present)

    def test_matching_is_case_insensitive_and_independent_of_device_address(self):
        state = guard.BleProximityState("ABCDEFAB-1234-4567-8123-123456789ABC", -84, -80, 11)
        self.assertTrue(state.advertisement(["abcdefab-1234-4567-8123-123456789abc"], -70, 0))
        self.assertTrue(state.sample(0).present)

    def test_unrelated_uuid_and_invalid_rssi_do_not_refresh_timeout(self):
        self.add(-70)
        for value in (127, None, -128, 21, True, "-70", float("nan")):
            self.assertFalse(self.add(value, 10))
        self.assertFalse(self.add(-70, 10, [OTHER_UUID]))
        self.assertFalse(self.add(-70, 10, []))
        self.assertEqual(self.state.packet_count, 1)
        self.assertFalse(self.state.sample(11).present)

    def test_loss_timeout_includes_exact_boundary(self):
        self.add(-70)
        self.assertTrue(self.state.sample(10.999).present)
        self.assertFalse(self.state.sample(11).present)
        self.assertFalse(self.state.sample(11).connected)

    def test_identical_packets_refresh_loss_timer(self):
        self.add(-70, 0)
        self.add(-70, 10)
        self.assertTrue(self.state.sample(20).present)
        self.assertFalse(self.state.sample(21).present)

    def test_first_packet_after_expiry_cannot_reuse_old_hysteresis_state(self):
        self.add(-70, 0)
        self.add(-82, 20)  # No intervening poll, e.g. Wi-Fi exclusion.
        self.assertFalse(self.state.sample(20).present)
        self.add(-70, 21)
        self.assertTrue(self.state.sample(21).present)

    def test_interruption_discards_near_state_and_rssi(self):
        self.add(-70)
        self.state.invalidate("adapter off")
        self.assertIsNone(self.state.sample(1).rssi)
        self.add(-82, 2)
        self.assertFalse(self.state.sample(2).present)
        self.add(-70, 3)
        self.assertTrue(self.state.sample(3).present)


class ConfigTests(unittest.TestCase):
    def test_old_configuration_remains_bredr_without_optional_dbus_package(self):
        with mock.patch.dict(sys.modules, {"dbus_fast": None}):
            config = guard.validate_config({"phone_address": MAC})
            self.assertEqual(config["proximity_mode"], "bredr")
            with mock.patch.object(guard, "BluezPresence") as classic:
                guard.create_presence(config)
            classic.assert_called_once_with(MAC, 2.0, True, 0)

    def test_ble_needs_no_mac_or_pairing(self):
        self.assertEqual(ble_config()["phone_address"], "")

    def test_invalid_ble_configuration_is_rejected(self):
        invalid = [
            {"ble_service_uuid": ""}, {"ble_service_uuid": "180d"},
            {"ble_service_uuid": "00000000-0000-0000-0000-000000000000"},
            {"ble_service_uuid": "00000000-0000-4000-8000-000000000000"},
            {"ble_service_uuid": None}, {"proximity_mode": "unknown"},
            {"ble_lock_rssi_dbm": -80}, {"ble_lock_rssi_dbm": -79},
            {"ble_lock_rssi_dbm": -128}, {"ble_unlock_rssi_dbm": 127},
            {"ble_unlock_rssi_dbm": True}, {"ble_lock_rssi_dbm": -84.5},
            {"ble_absence_seconds": 0}, {"ble_absence_seconds": 301},
            {"ble_absence_seconds": float("nan")}, {"ble_absence_seconds": float("inf")},
            {"ble_adapter": "hci0; command"}, {"ble_adapter": None},
            {"poll_seconds": float("nan")}, {"reconnect_every_seconds": float("inf")},
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(SystemExit):
                ble_config(**value)

    def test_missing_optional_dependency_has_actionable_error(self):
        with mock.patch.dict(sys.modules, {"dbus_fast": None}), self.assertRaisesRegex(SystemExit, "python3-dbus-fast"):
            guard.BleAdvertisementPresence(ble_config())

    def test_invalid_cli_durations(self):
        for command, seconds in (("self-test", "6"), ("self-test", "0"),
                                 ("self-test", "nan"), ("observe", "inf"), ("observe", "-1")):
            with self.subTest(command=command, seconds=seconds), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                guard.build_parser().parse_args([command, "--seconds", seconds])


class ScannerTests(unittest.TestCase):
    def make_presence(self):
        return guard.BleAdvertisementPresence(ble_config(), scanner_factory=mock.Mock())

    def test_old_callbacks_and_post_stop_callbacks_are_ignored(self):
        presence = self.make_presence()
        token = presence._generation
        presence._callback(token, object(), packet())
        self.assertTrue(presence.sample().present)
        with presence._lock:
            presence._invalidate("adapter lost")
        presence._callback(token, object(), packet())
        self.assertFalse(presence.sample().present)
        presence.stop()
        presence._callback(presence._generation, object(), packet())
        self.assertFalse(presence.sample().present)

    def test_suspend_shorter_than_absence_timeout_invalidates_cached_near(self):
        boot, mono = [100.0], [100.0]
        with mock.patch.object(guard, "elapsed_seconds", side_effect=lambda: boot[0]), mock.patch.object(guard.time, "monotonic", side_effect=lambda: mono[0]):
            presence = self.make_presence()
            token = presence._generation
            presence._callback(token, None, packet())
            self.assertTrue(presence.sample().present)
            boot[0] += 2  # CLOCK_BOOTTIME includes the 2s suspend; monotonic doesn't.
            self.assertFalse(presence.sample().present)
            self.assertTrue(presence._restart.is_set())
            presence._callback(token, None, packet())
            self.assertFalse(presence.sample().present)

    def test_stalled_worker_does_not_keep_input_released(self):
        boot, mono = [100.0], [100.0]
        with mock.patch.object(guard, "elapsed_seconds", side_effect=lambda: boot[0]), mock.patch.object(guard.time, "monotonic", side_effect=lambda: mono[0]):
            presence = self.make_presence()
            presence._callback(0, None, packet())
            self.assertTrue(presence.sample().present)
            for _ in range(6):
                boot[0] += 1
                mono[0] += 1
                last = presence.sample()
            self.assertFalse(last.present)
            self.assertTrue(presence._restart.is_set())

    def test_scan_cache_replay_is_ignored_but_live_callback_is_accepted(self):
        presence = self.make_presence()
        factory = presence._scanner_factory
        callback = [None]

        async def start():
            callback[0](None, packet())  # Simulates cached data during start().

        def create(**kwargs):
            callback[0] = kwargs["detection_callback"]
            return SimpleNamespace(start=start, stop=mock.AsyncMock(), interrupted=False)

        factory.side_effect = create
        outcomes = []

        async def tick(_delay):
            outcomes.append(presence._state.sample(guard.elapsed_seconds()).present)
            callback[0](None, packet())
            outcomes.append(presence._state.sample(guard.elapsed_seconds()).present)
            presence._stop.set()

        with mock.patch.object(guard.asyncio, "sleep", side_effect=tick):
            asyncio.run(presence._scan_once())
        self.assertEqual(outcomes, [False, True])
        self.assertFalse(presence.sample().present)
        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs["service_uuids"], [UUID])
        self.assertTrue(kwargs["bluez"]["filters"]["DuplicateData"])

    def test_start_failure_invalidates_and_attempts_scanner_cleanup(self):
        presence = self.make_presence()
        scanner = SimpleNamespace(start=mock.AsyncMock(side_effect=OSError("simulated bus failure")), stop=mock.AsyncMock(), interrupted=False)
        presence._scanner_factory.return_value = scanner
        with self.assertRaises(OSError):
            asyncio.run(presence._scan_once())
        scanner.stop.assert_awaited_once()
        self.assertFalse(presence.sample().present)

    def test_silent_scan_or_missing_adapter_is_recycled(self):
        presence = self.make_presence()
        scanner = SimpleNamespace(start=mock.AsyncMock(), stop=mock.AsyncMock(), interrupted=False)
        presence._scanner_factory.return_value = scanner
        clock = [100.0]

        async def tick(_delay):
            clock[0] += 1

        with mock.patch.object(guard, "elapsed_seconds", side_effect=lambda: clock[0]), mock.patch.object(guard.asyncio, "sleep", side_effect=tick):
            asyncio.run(presence._scan_once())
        self.assertGreaterEqual(clock[0], 111)
        scanner.stop.assert_awaited_once()

    def test_worker_retries_after_failure_without_touching_input(self):
        presence = self.make_presence()
        attempts = []

        async def scan():
            attempts.append(True)
            if len(attempts) == 1:
                raise OSError("simulated adapter unplug")
            presence._stop.set()

        with mock.patch.object(presence, "_scan_once", side_effect=scan), mock.patch.object(presence._stop, "wait"):
            presence._worker()
        self.assertEqual(len(attempts), 2)
        self.assertFalse(presence.sample().present)

    def test_interrupted_session_recovers_only_with_new_strong_observation(self):
        presence = self.make_presence()
        sessions, outcomes = [], []

        def create(**kwargs):
            scanner = SimpleNamespace(start=mock.AsyncMock(), stop=mock.AsyncMock(), interrupted=False,
                                      callback=kwargs["detection_callback"])
            sessions.append(scanner)
            return scanner

        async def tick(_delay):
            scanner = sessions[-1]
            if len(sessions) == 1:
                scanner.callback(None, packet())
                outcomes.append(presence._state.near)
                scanner.interrupted = True
            else:
                sessions[0].callback(None, packet())  # Old scan still has a queued callback.
                scanner.callback(None, packet(-82))
                outcomes.append(presence._state.near)
                scanner.callback(None, packet())
                outcomes.append(presence._state.near)
                presence._stop.set()

        presence._scanner_factory.side_effect = create
        with mock.patch.object(guard.asyncio, "sleep", side_effect=tick):
            asyncio.run(presence._scan_once())
            self.assertFalse(presence.sample().present)
            asyncio.run(presence._scan_once())
        self.assertEqual(outcomes, [True, False, True])
        self.assertEqual(len(sessions), 2)


class ClassicRegressionTests(unittest.TestCase):
    def test_bredr_disconnect_weak_and_unavailable_rssi_latch(self):
        with mock.patch.object(guard.BluezPresence, "_initialize_dbus"), mock.patch.object(guard.BluezPresence, "_initialize_management_socket", return_value=False):
            presence = guard.BluezPresence(MAC, 2, True, 0)
        with mock.patch.object(presence, "connected", return_value=True), mock.patch.object(presence, "connection_info") as info:
            info.return_value = guard.BluetoothConnectionInfo("BR/EDR", 0)
            self.assertTrue(presence.sample().present)
            info.return_value = guard.BluetoothConnectionInfo("BR/EDR", -1)
            self.assertFalse(presence.sample().present)
            info.return_value = guard.BluetoothConnectionInfo("BR/EDR", None)
            self.assertFalse(presence.sample().present)
            info.return_value = guard.BluetoothConnectionInfo("BR/EDR", 1)
            self.assertTrue(presence.sample().present)
        with mock.patch.object(presence, "connected", return_value=False):
            self.assertFalse(presence.sample().present)


class WifiAndRescueTests(unittest.TestCase):
    def test_empty_or_unavailable_wifi_does_not_match_exclusion(self):
        self.assertEqual(guard.matching_wifi_exclusions(["XX1"], []), [])
        self.assertEqual(guard.matching_wifi_exclusions(["XX1"], None), [])
        self.assertEqual(guard.matching_wifi_exclusions(["XX1"], ["XX10"]), [])
        self.assertEqual(guard.matching_wifi_exclusions(["XX1"], ["xx1"]), ["XX1"])

    def test_wifi_cache_expires_and_is_invalidated_by_suspend(self):
        boot, mono = [100.0], [100.0]
        with mock.patch.object(guard, "elapsed_seconds", side_effect=lambda: boot[0]), mock.patch.object(guard.time, "monotonic", side_effect=lambda: mono[0]):
            wifi = guard.WifiExclusionMonitor(["XX1"], 0.75, 0)
            wifi._active_names = {"XX1"}
            wifi._sampled_at = 100
            self.assertTrue(wifi.decision().paused)
            boot[0] += 1
            self.assertFalse(wifi.decision().paused)
            mono[0] += 1
            self.assertTrue(wifi.decision().paused)
            boot[0] = mono[0] = 104
            self.assertFalse(wifi.decision().paused)

    def test_charger_rescue_requires_three_full_debounced_cycles(self):
        now, online = [0.0], [True]
        with mock.patch.object(guard.time, "monotonic", side_effect=lambda: now[0]), mock.patch.object(guard.PowerCycleRescue, "external_power_online", side_effect=lambda: online[0]):
            rescue = guard.PowerCycleRescue(3, 60, 1)
            for cycle in range(3):
                for state in (False, True):
                    online[0] = state
                    now[0] += 1
                    self.assertFalse(rescue.update())
                    now[0] += 1.1
                    triggered = rescue.update()
                    self.assertEqual(triggered, cycle == 2 and state is True)


class InputReleaseTests(unittest.TestCase):
    def test_continuous_input_cannot_starve_presence_and_rescue_polling(self):
        grabber = guard.InputGrabber([])
        path = Path("/simulated/event10")
        grabber._devices[path] = guard.GrabbedDevice(path, 10, "synthetic", "keyboard")
        with mock.patch.object(guard.os, "read", return_value=b"synthetic event") as read:
            grabber.discard_input()
        self.assertEqual(read.call_count, 32)

    def test_hot_unplug_closes_the_failed_input_handle(self):
        grabber = guard.InputGrabber([])
        path = Path("/simulated/event10")
        grabber._devices[path] = guard.GrabbedDevice(path, 10, "synthetic", "keyboard")
        with mock.patch.object(guard.os, "read", side_effect=OSError(errno.ENODEV, "synthetic unplug")), mock.patch.object(guard.fcntl, "ioctl"), mock.patch.object(guard.os, "close") as close:
            grabber.discard_input()
        close.assert_called_once_with(10)
        self.assertFalse(grabber.is_grabbed)

    def test_release_closes_all_fds_even_when_ungrab_ioctl_fails(self):
        grabber = guard.InputGrabber([])
        for number in (10, 11):
            path = Path(f"/simulated/event{number}")
            grabber._devices[path] = guard.GrabbedDevice(path, number, "synthetic", "keyboard")
        with mock.patch.object(guard.fcntl, "ioctl", side_effect=OSError("device removed")), mock.patch.object(guard.os, "close") as close:
            grabber.release_all()
        self.assertEqual(close.call_args_list, [mock.call(10), mock.call(11)])
        self.assertFalse(grabber.is_grabbed)

    def test_single_instance_lock_prevents_overlapping_grabs(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(guard, "PANEL_RUNTIME_DIR", Path(temporary)):
            with guard.exclusive_input_session():
                with self.assertRaisesRegex(SystemExit, "already running"):
                    with guard.exclusive_input_session():
                        self.fail("overlapping input session")
            with guard.exclusive_input_session():
                pass

    def test_self_test_timeout_is_failure_not_success(self):
        args = argparse.Namespace(config="unused", seconds=3)
        with mock.patch.object(guard, "require_root"), mock.patch.object(guard, "load_config", return_value=ble_config()), mock.patch.object(guard, "run_command", return_value=subprocess.CompletedProcess([], 3)), mock.patch.object(guard.subprocess, "run", side_effect=subprocess.TimeoutExpired("synthetic", 8)) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(guard.self_test(args), 1)
        self.assertEqual(run.call_args.kwargs["timeout"], 8)

    def test_child_self_test_releases_on_exception(self):
        grabber = mock.Mock(is_grabbed=True)
        grabber.discard_input.side_effect = RuntimeError("synthetic input read failure")
        with mock.patch.object(guard, "require_root"), mock.patch.object(guard, "load_config", return_value=ble_config()), mock.patch.object(guard, "InputGrabber", return_value=grabber), mock.patch.object(guard, "exclusive_input_session", return_value=contextlib.nullcontext()), self.assertRaises(RuntimeError):
            guard.input_self_test_child(argparse.Namespace(config="unused", seconds=3))
        grabber.release_all.assert_called_once()

    def test_self_test_refuses_running_service_including_older_versions(self):
        with mock.patch.object(guard, "require_root"), mock.patch.object(guard, "load_config", return_value=ble_config()), mock.patch.object(guard, "run_command", return_value=subprocess.CompletedProcess([], 0)), self.assertRaisesRegex(SystemExit, "Disarm"):
            guard.self_test(argparse.Namespace(config="unused", seconds=3))


if __name__ == "__main__":
    unittest.main()
