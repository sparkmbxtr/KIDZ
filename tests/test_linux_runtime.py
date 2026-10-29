"""Exercise the real guard loop and CLI lifecycle with simulated resources."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from test_linux_guard import guard, ble_config, sample, UUID


class LoopEvent:
    def __init__(self, steps):
        self.steps = steps
        self.step = 0

    def is_set(self):
        return self.step >= self.steps

    def set(self):
        self.step = self.steps

    def wait(self, _seconds):
        self.step += 1


class GuardLoopTests(unittest.TestCase):
    def simulate(self, samples, *, wifi=None, rescue=None, dry_run=False, overlay_error=False, sample_error=False):
        event = LoopEvent(len(samples))
        presence = mock.Mock()
        presence.sample.side_effect = lambda: samples[event.step] if not sample_error or event.step == 0 else (_ for _ in ()).throw(RuntimeError("simulated radio failure"))
        presence.backend = "simulated"
        grabber = mock.Mock(is_grabbed=False)
        actions = []

        def grab():
            actions.append("grab")
            grabber.is_grabbed = True

        def release():
            actions.append("release")
            grabber.is_grabbed = False

        grabber.grab_all.side_effect = grab
        grabber.release_all.side_effect = release
        power = mock.Mock(supply_names=["synthetic"])
        power.update.side_effect = lambda: bool(rescue and rescue[event.step])
        overlay = mock.Mock()
        if overlay_error:
            overlay.show.side_effect = RuntimeError("simulated overlay failure")
            overlay.hide.side_effect = RuntimeError("simulated cleanup failure")
        awake = mock.Mock()
        wifi_monitor = mock.Mock()
        wifi_monitor.decision.side_effect = lambda: guard.WifiPolicyDecision(bool(wifi and wifi[event.step]), "synthetic Wi-Fi policy", ())
        with contextlib.ExitStack() as patches:
            patches.enter_context(mock.patch.object(guard, "load_config", return_value=ble_config()))
            patches.enter_context(mock.patch.object(guard.threading, "Event", return_value=event))
            patches.enter_context(mock.patch.object(guard.signal, "signal"))
            patches.enter_context(mock.patch.object(guard, "create_presence", return_value=presence))
            patches.enter_context(mock.patch.object(guard, "InputGrabber", return_value=grabber))
            patches.enter_context(mock.patch.object(guard, "PowerCycleRescue", return_value=power))
            patches.enter_context(mock.patch.object(guard, "OverlayManager", return_value=overlay))
            patches.enter_context(mock.patch.object(guard, "DisplayAwakeManager", return_value=awake))
            monitor_factory = patches.enter_context(mock.patch.object(guard, "WifiExclusionMonitor", return_value=wifi_monitor))
            if overlay_error or sample_error:
                with self.assertRaises(RuntimeError):
                    guard._run_guard(Path("unused"), dry_run)
            else:
                self.assertEqual(guard._run_guard(Path("unused"), dry_run), 0)
        return argparse.Namespace(actions=actions, grabber=grabber, presence=presence,
                                  power=power, overlay=overlay, awake=awake, wifi=wifi_monitor,
                                  monitor_factory=monitor_factory)

    def test_near_departure_loss_and_return_use_shared_input_path(self):
        result = self.simulate([sample(True), sample(False), sample(False), sample(True)])
        # Repeat grab_all while far also handles newly attached physical devices.
        self.assertEqual(result.actions, ["grab", "grab", "release", "release"])
        self.assertEqual(result.overlay.show.call_count, 2)
        self.assertEqual(result.awake.hold.call_count, 2)
        result.presence.stop.assert_called_once()
        result.wifi.stop.assert_called_once()

    def test_unknown_ble_startup_does_not_wait_for_wifi_settle(self):
        result = self.simulate([sample(False)])
        self.assertEqual(result.actions, ["grab", "release"])
        self.assertEqual(result.monitor_factory.call_args.args[2], 0)

    def test_wifi_exclusion_releases_and_sampling_continues(self):
        result = self.simulate([sample(False)] * 3, wifi=[False, True, False])
        self.assertEqual(result.actions, ["grab", "release", "grab", "release"])
        self.assertEqual(result.presence.sample.call_count, 3)

    def test_emergency_rescue_releases_until_fresh_near_rearms(self):
        result = self.simulate([sample(False), sample(False), sample(True), sample(False)], rescue=[True, False, False, False])
        self.assertEqual(result.actions, ["grab", "release"])

    def test_unexpected_backend_exception_releases_existing_grabs(self):
        result = self.simulate([sample(False), sample(False)], sample_error=True)
        self.assertEqual(result.actions, ["grab", "release"])
        result.presence.stop.assert_called_once()
        result.wifi.stop.assert_called_once()

    def test_indicator_failure_cannot_prevent_input_and_backend_cleanup(self):
        result = self.simulate([sample(False)], overlay_error=True)
        self.assertEqual(result.actions, ["grab", "release"])
        result.awake.release.assert_called_once()
        result.presence.stop.assert_called_once()
        result.wifi.stop.assert_called_once()

    def test_dry_run_never_changes_input_or_indicator_state(self):
        result = self.simulate([sample(False), sample(False)], wifi=[True, False], dry_run=True)
        self.assertEqual(result.actions, [])
        result.overlay.hide.assert_not_called()
        result.overlay.show.assert_not_called()
        result.awake.release.assert_not_called()
        result.awake.hold.assert_not_called()


class InstallAndArmTests(unittest.TestCase):
    def setUp(self):
        self.patches = contextlib.ExitStack()
        self.addCleanup(self.patches.close)
        self.temporary = self.patches.enter_context(tempfile.TemporaryDirectory())
        for name, filename in (("CONFIG_PATH", "settings.json"), ("INSTALL_PATH", "installed.py"), ("SERVICE_PATH", "guard.service")):
            self.patches.enter_context(mock.patch.object(guard, name, Path(self.temporary) / filename))
        self.patches.enter_context(mock.patch.object(guard, "require_root"))
        self.patches.enter_context(mock.patch.object(guard.shutil, "which", return_value="/synthetic/tool"))
        self.patches.enter_context(mock.patch.object(guard, "install_gnome_panel_extension", return_value=(False, False, None, None)))
        self.patches.enter_context(mock.patch.object(guard, "_remove_panel_marker"))
        self.commands = self.patches.enter_context(mock.patch.object(guard, "run_command", return_value=subprocess.CompletedProcess([], 0, "")))
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def args(self, command):
        return guard.build_parser().parse_args(command)

    def test_ble_install_is_disarmed_without_pairing_or_scanning(self):
        with mock.patch.object(guard, "BleAdvertisementPresence") as presence, mock.patch.object(guard, "choose_phone") as choose:
            result = guard.install(self.args(["install", "--mode", "ble", "--service-uuid", UUID, "--clear-wifi-exclusions"]))
        self.assertEqual(result, 0)
        choose.assert_not_called()
        presence.return_value.start.assert_not_called()
        config = guard.load_config(guard.CONFIG_PATH)
        self.assertEqual(config["proximity_mode"], "ble")
        self.assertEqual(guard.CONFIG_PATH.stat().st_mode & 0o777, 0o600)
        calls = [call.args[0] for call in self.commands.call_args_list]
        self.assertIn(["systemctl", "disable", "--now", guard.APP_NAME], calls)
        self.assertFalse(any("restart" in call or "enable" in call for call in calls))

    def test_ble_reinstall_preserves_local_uuid_and_thresholds(self):
        guard.write_config(guard.CONFIG_PATH, ble_config(ble_lock_rssi_dbm=-90, ble_unlock_rssi_dbm=-85, ble_absence_seconds=15))
        with mock.patch.object(guard, "BleAdvertisementPresence"):
            guard.install(self.args(["install"]))
        config = guard.load_config(guard.CONFIG_PATH)
        self.assertEqual((config["ble_service_uuid"], config["ble_lock_rssi_dbm"], config["ble_absence_seconds"]), (UUID, -90, 15))

    def test_invalid_ble_setup_changes_no_files_or_services(self):
        with self.assertRaises(SystemExit):
            guard.install(self.args(["install", "--mode", "ble", "--service-uuid", "invalid"]))
        self.assertFalse(guard.CONFIG_PATH.exists())
        self.commands.assert_not_called()

    def test_ble_rejects_force_install_before_mutation(self):
        with self.assertRaises(SystemExit):
            guard.install(self.args(["install", "--mode", "ble", "--service-uuid", UUID, "--force-start"]))
        self.assertFalse(guard.CONFIG_PATH.exists())
        self.commands.assert_not_called()

    def test_bredr_install_retains_default_selection_and_start_path(self):
        with mock.patch.object(guard, "choose_phone", return_value="00:00:00:00:00:01"), mock.patch.object(guard, "configured_bluetooth_presence", return_value=sample(True)), mock.patch.object(guard, "active_wifi_names", return_value=set()):
            guard.install(self.args(["install"]))
        self.assertEqual(guard.load_config(guard.CONFIG_PATH)["proximity_mode"], "bredr")
        self.commands.assert_any_call(["systemctl", "restart", guard.APP_NAME], check=True)

    def test_ble_arming_refuses_without_fresh_near_evidence(self):
        guard.write_config(guard.CONFIG_PATH, ble_config())
        with mock.patch.object(guard, "configured_bluetooth_presence", return_value=sample(False)), mock.patch.object(guard, "active_wifi_names", return_value=set()), self.assertRaises(SystemExit):
            guard.arm(self.args(["arm"]))
        self.commands.assert_not_called()

    def test_ble_arming_accepts_strong_fresh_packet(self):
        guard.write_config(guard.CONFIG_PATH, ble_config())
        with mock.patch.object(guard, "configured_bluetooth_presence", return_value=sample(True)), mock.patch.object(guard, "active_wifi_names", return_value=set()):
            self.assertEqual(guard.arm(self.args(["arm"])), 0)
        self.commands.assert_called_once_with(["systemctl", "enable", "--now", guard.APP_NAME], check=True)

    def test_wifi_exclusion_can_authorize_arming_without_radio_evidence(self):
        guard.write_config(guard.CONFIG_PATH, ble_config(excluded_wifi_connections=["XX1"]))
        with mock.patch.object(guard, "configured_bluetooth_presence") as presence, mock.patch.object(guard, "active_wifi_names", return_value={"XX1"}):
            self.assertEqual(guard.arm(self.args(["arm"])), 0)
        presence.assert_not_called()

    def test_ble_force_arm_is_rejected(self):
        guard.write_config(guard.CONFIG_PATH, ble_config())
        with self.assertRaises(SystemExit):
            guard.arm(self.args(["arm", "--force"]))
        self.commands.assert_not_called()


if __name__ == "__main__":
    unittest.main()
