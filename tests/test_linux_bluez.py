"""BlueZ signal tests and an isolated D-Bus integration test; no host bus access."""

import asyncio
import contextlib
import importlib.util
import os
import shutil
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from test_linux_guard import guard, UUID, OTHER_UUID


ADAPTER = "/org/bluez/hci0"
DEVICE = ADAPTER + "/dev_00_00_00_00_00_01"
PROPERTIES = "org.freedesktop.DBus.Properties"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"


def properties(**values):
    return {key: SimpleNamespace(value=value) for key, value in values.items()}


class BluezSignalTests(unittest.TestCase):
    def setUp(self):
        # Test signal interpretation without requiring the optional D-Bus module.
        self.scanner = guard.BluezAdvertisementScanner.__new__(guard.BluezAdvertisementScanner)
        self.scanner._MessageType = SimpleNamespace(SIGNAL="signal")
        self.scanner._adapter_path = ADAPTER
        self.scanner._devices = {}
        self.scanner._active = True
        self.scanner._interrupted = False
        self.scanner._callback = mock.Mock()

    def changed(self, path=DEVICE, interface="org.bluez.Device1", invalidated=(), **values):
        self.scanner._message(SimpleNamespace(message_type="signal", interface=PROPERTIES,
                                              member="PropertiesChanged", path=path,
                                              body=[interface, properties(**values), invalidated]))

    def test_connection_name_and_cached_uuid_changes_are_not_advertisements(self):
        self.changed(UUIDs=[UUID], Connected=True, Name="synthetic")
        self.changed(Connected=False)
        self.scanner._callback.assert_not_called()
        self.changed(RSSI=-70)
        self.scanner._callback.assert_called_once()

    def test_live_identical_rssi_updates_are_forwarded(self):
        self.changed(UUIDs=[UUID], RSSI=-70)
        self.changed(RSSI=-70)
        self.assertEqual(self.scanner._callback.call_count, 2)

    def test_uuid_invalidation_and_change_cannot_reuse_old_identity(self):
        self.changed(UUIDs=[UUID])
        self.changed(invalidated=["UUIDs"], RSSI=-70)
        self.assertEqual(self.scanner._callback.call_args.args[1].service_uuids, [])
        self.changed(UUIDs=[OTHER_UUID], RSSI=-70)
        self.assertEqual(self.scanner._callback.call_args.args[1].service_uuids, [OTHER_UUID])

    def test_other_adapter_updates_are_ignored(self):
        self.changed(path="/org/bluez/hci1/dev_00_00_00_00_00_01", UUIDs=[UUID], RSSI=-70)
        self.scanner._callback.assert_not_called()

    def test_power_off_and_discovery_abort_interrupt_scan(self):
        for property_name in ("Powered", "Discovering"):
            with self.subTest(property_name=property_name):
                self.scanner._interrupted = False
                self.changed(path=ADAPTER, interface="org.bluez.Adapter1", **{property_name: False})
                self.assertTrue(self.scanner._interrupted)

    def test_bluetooth_service_restart_interrupts_scan(self):
        self.scanner._message(SimpleNamespace(message_type="signal", interface="org.freedesktop.DBus",
                                              member="NameOwnerChanged", body=["org.bluez", ":1.1", ""]))
        self.assertTrue(self.scanner._interrupted)

    def test_adapter_removal_interrupts_and_device_removal_discards_identity(self):
        self.changed(UUIDs=[UUID])
        for path, interface in ((DEVICE, "org.bluez.Device1"), (ADAPTER, "org.bluez.Adapter1")):
            self.scanner._message(SimpleNamespace(message_type="signal", interface=OBJECT_MANAGER,
                                                  member="InterfacesRemoved", body=[path, [interface]]))
        self.assertNotIn(DEVICE, self.scanner._devices)
        self.assertTrue(self.scanner._interrupted)

    def test_interfaces_added_can_deliver_first_live_advertisement(self):
        self.scanner._message(SimpleNamespace(message_type="signal", interface=OBJECT_MANAGER,
                                              member="InterfacesAdded", body=[DEVICE, {"org.bluez.Device1": properties(UUIDs=[UUID], RSSI=-70)}]))
        self.scanner._callback.assert_called_once()


HAS_BINDING = importlib.util.find_spec("dbus_fast") is not None
HAS_DBUS = HAS_BINDING and shutil.which("dbus-daemon") is not None
if HAS_BINDING:
    from dbus_fast import Message, MessageType, PropertyAccess, Variant
    from dbus_fast.aio import MessageBus
    from dbus_fast.service import ServiceInterface, dbus_property, method

    class SimulatedAdapter(ServiceInterface):
        def __init__(self):
            super().__init__("org.bluez.Adapter1")
            self.filters = None
            self.started = False
            self.stopped = False

        @dbus_property(access=PropertyAccess.READ)
        def Powered(self) -> 'b':
            return True

        @method()
        def SetDiscoveryFilter(self, filters: 'a{sv}'):
            self.filters = filters

        @method()
        def StartDiscovery(self):
            self.started = True

        @method()
        def StopDiscovery(self):
            self.stopped = True

    class SimulatedDevice(ServiceInterface):
        def __init__(self):
            super().__init__("org.bluez.Device1")

        @dbus_property(access=PropertyAccess.READ)
        def UUIDs(self) -> 'as':
            return [UUID]

        @dbus_property(access=PropertyAccess.READ)
        def RSSI(self) -> 'n':
            return -70


@unittest.skipUnless(HAS_BINDING, "optional D-Bus binding required")
class BindingContractTests(unittest.IsolatedAsyncioTestCase):
    """Real Message/Variant types, in-memory transport; also works without sockets."""

    async def asyncSetUp(self):
        self.bus = mock.Mock(connected=True)
        self.bus.connect = mock.AsyncMock()
        self.bus.wait_for_disconnect = mock.AsyncMock()
        self.frames = []

        async def call(message):
            self.frames.append(message)
            return SimpleNamespace(message_type=MessageType.METHOD_RETURN, body=[])

        self.bus.call = mock.AsyncMock(side_effect=call)
        self.bus.disconnect.side_effect = lambda: setattr(self.bus, "connected", False)
        self.callback = mock.Mock()
        with mock.patch("dbus_fast.aio.MessageBus", return_value=self.bus):
            self.scanner = guard.BluezAdvertisementScanner(self.callback, [UUID], {"adapter": "hci0"})

    async def test_binding_accepts_discovery_frames_and_cached_rssi_is_ignored(self):
        # Decorated service methods are wire dispatch wrappers, so use the
        # same explicit return payload for this in-memory contract transport.
        objects = {ADAPTER: {"org.bluez.Adapter1": {"Powered": Variant("b", True)}},
                   DEVICE: {"org.bluez.Device1": {"UUIDs": Variant("as", [UUID]), "RSSI": Variant("n", -70)}}}

        async def call(message):
            self.frames.append(message)
            return SimpleNamespace(message_type=MessageType.METHOD_RETURN,
                                   body=[objects] if message.member == "GetManagedObjects" else [])

        self.bus.call.side_effect = call
        await self.scanner.start()
        self.callback.assert_not_called()
        self.scanner._message(Message.new_signal(DEVICE, PROPERTIES, "PropertiesChanged", "sa{sv}as", ["org.bluez.Device1", {"RSSI": Variant("n", -70)}, []]))
        self.callback.assert_called_once()
        await self.scanner.stop()
        self.assertEqual([frame.member for frame in self.frames], ["AddMatch"] * 3 + ["GetManagedObjects", "SetDiscoveryFilter", "StartDiscovery", "StopDiscovery"])
        self.bus.disconnect.assert_called_once()
        self.bus.wait_for_disconnect.assert_awaited_once()

    async def test_bus_is_closed_even_when_stop_discovery_errors(self):
        self.scanner._adapter_path = ADAPTER
        self.scanner._discovery_started = True
        self.bus.call.side_effect = OSError("simulated service restart")
        with self.assertRaises(OSError):
            await self.scanner.stop()
        self.bus.disconnect.assert_called_once()

    async def test_fixture_exports_properties_for_automatic_object_manager(self):
        # dbus-fast handles GetManagedObjects itself, using exported properties.
        # A method-only fixture would silently return an adapter without Powered.
        self.assertEqual({prop.name: prop.signature for prop in SimulatedAdapter().introspect().properties}, {"Powered": "b"})
        self.assertEqual({prop.name: prop.signature for prop in SimulatedDevice().introspect().properties}, {"UUIDs": "as", "RSSI": "n"})


@unittest.skipUnless(HAS_DBUS, "optional dbus-fast and private dbus-daemon needed (dedicated CI job installs both)")
class PrivateBusTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.daemon = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_daemon)
        address = self.daemon.stdout.readline().strip()
        if not address:
            error = self.daemon.stderr.read().strip()
            if os.environ.get("KIDZ_REQUIRE_PRIVATE_BUS"):
                self.fail(f"Private D-Bus required by CI but could not start: {error}")
            self.skipTest(f"Private D-Bus socket unavailable in this environment: {error}")
        self.environment = mock.patch.dict(os.environ, {"DBUS_SYSTEM_BUS_ADDRESS": address})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.service_bus = await MessageBus(bus_address=address).connect()
        await self.service_bus.request_name("org.bluez")
        self.adapter = SimulatedAdapter()
        # The binding supplies ObjectManager from the real exported interfaces.
        self.service_bus.export(ADAPTER, self.adapter)
        self.service_bus.export(DEVICE, SimulatedDevice())
        self.callback = mock.Mock()
        self.scanner = guard.BluezAdvertisementScanner(self.callback, [UUID], {"adapter": "hci0"})
        self.addAsyncCleanup(self.disconnect)
        await self.scanner.start()

    def stop_daemon(self):
        self.daemon.terminate()
        try:
            self.daemon.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.daemon.kill()
            self.daemon.communicate()

    async def disconnect(self):
        with contextlib.suppress(OSError):
            await self.scanner.stop()
        await self.scanner._bus.wait_for_disconnect()
        self.service_bus.disconnect()
        await self.service_bus.wait_for_disconnect()

    async def emit(self, path=DEVICE, interface="org.bluez.Device1", **values):
        await self.service_bus.send(Message.new_signal(path, PROPERTIES, "PropertiesChanged", "sa{sv}as", [interface, values, []]))
        # A round-trip on the same private bus flushes the signal, then yields
        # to its receiver. No host Bluetooth or input device is involved.
        await self.service_bus.call(Message(destination="org.freedesktop.DBus", path="/org/freedesktop/DBus", interface="org.freedesktop.DBus", member="ListNames"))
        await asyncio.sleep(0.01)

    async def test_real_dbus_round_trip_filters_live_rssi_and_closes_session(self):
        self.assertTrue(self.adapter.started)
        self.assertEqual(self.adapter.filters["Transport"].value, "le")
        self.assertEqual(self.adapter.filters["UUIDs"].value, [UUID])
        self.assertTrue(self.adapter.filters["DuplicateData"].value)
        self.callback.assert_not_called()  # GetManagedObjects' cached RSSI.
        await self.emit(Connected=Variant("b", True))
        self.callback.assert_not_called()
        await self.emit(RSSI=Variant("n", -70))
        await self.emit(RSSI=Variant("n", -70))
        self.assertEqual(self.callback.call_count, 2)
        await self.scanner.stop()
        self.assertTrue(self.adapter.stopped)
        self.assertFalse(self.scanner._bus.connected)

    async def test_adapter_power_interruption_is_observed(self):
        await self.emit(path=ADAPTER, interface="org.bluez.Adapter1", Powered=Variant("b", False))
        self.assertTrue(self.scanner.interrupted)

    async def test_bluetooth_service_loss_is_observed(self):
        await self.service_bus.release_name("org.bluez")
        await asyncio.sleep(0.02)
        self.assertTrue(self.scanner.interrupted)


if __name__ == "__main__":
    unittest.main()
