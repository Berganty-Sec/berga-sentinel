"""Testes da descoberta em camadas e consolidação do inventário."""

import asyncio
import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from berga_sentinel.inventory import build_inventory
from berga_sentinel.models import ScanObservation, ScanSnapshot
from berga_sentinel.network_interface import _valid_profile, detect_active_interface
from berga_sentinel.neighbors import _neighbor_state
from berga_sentinel.reporting import write_html
from berga_sentinel.scanner import _connect_port, _probe_host, _scan_async, scan_network


class NetworkProfileTests(unittest.TestCase):
    def test_detects_ipv4_and_prefix_and_calculates_subnet(self):
        profile = _valid_profile("Wi-Fi", 7, "198.51.100.100", 24, "198.51.100.1")
        self.assertEqual(profile.network, ipaddress.ip_network("198.51.100.0/24"))
        self.assertEqual(profile.scope, "198.51.100.0/24")

    def test_detects_active_interface(self):
        expected = _valid_profile("Ethernet", 7, "198.51.100.100", 24, "198.51.100.1")
        with patch("berga_sentinel.network_interface.platform.system", return_value="Windows"), \
             patch("berga_sentinel.network_interface._detect_windows", return_value=expected):
            self.assertEqual(detect_active_interface(), expected)

    def test_scan_without_manual_scope_uses_detected_interface(self):
        profile = _valid_profile("Ethernet", 7, "198.51.100.1", 30, "198.51.100.2")
        expected = ScanSnapshot(profile.scope, "now")
        with patch("berga_sentinel.scanner.detect_active_interface", return_value=profile), \
             patch("berga_sentinel.scanner._scan_async", new=AsyncMock(return_value=expected)) as scan:
            result = scan_network()
        self.assertIs(result, expected)
        self.assertEqual(scan.await_args.args[0], profile.network)
        self.assertEqual(scan.await_args.args[2], profile)


class InventoryDiscoveryTests(unittest.TestCase):
    def test_consolidates_one_host_found_by_arp_icmp_and_tcp(self):
        snapshot = ScanSnapshot("198.51.100.0/24", "now", local_ipv4="198.51.100.100",
            observations=[ScanObservation("198.51.100.20", True, open_ports=[445],
                mac_address="AA:BB:CC:DD:EE:FF", discovery_methods=["ARP", "ICMP", "TCP"])])
        result = build_inventory(snapshot)
        self.assertEqual(len(result.devices), 1)
        self.assertEqual(result.devices[0].discovered_by, ["ARP", "ICMP", "TCP"])

    def test_distinguishes_local_host_from_remote_hosts(self):
        snapshot = ScanSnapshot("198.51.100.0/24", "now", local_ipv4="198.51.100.100",
            gateway="198.51.100.1", observations=[
                ScanObservation("198.51.100.100", True, discovery_methods=["ICMP", "LOCAL HOST"]),
                ScanObservation("198.51.100.20", False, mac_address="AA:BB:CC:DD:EE:FF",
                                discovery_methods=["ARP"]),
                ScanObservation("198.51.100.1", False, discovery_methods=["ARP"]),
            ])
        result = build_inventory(snapshot)
        by_ip = {device.ip: device for device in result.devices}
        self.assertEqual(by_ip["198.51.100.100"].role, "LOCAL HOST")
        self.assertTrue(by_ip["198.51.100.100"].is_local)
        self.assertEqual(by_ip["198.51.100.20"].role, "Host")
        self.assertEqual(by_ip["198.51.100.1"].role, "Gateway")

    def test_missing_icmp_does_not_mark_arp_host_offline(self):
        snapshot = ScanSnapshot("198.51.100.0/24", "now", observations=[
            ScanObservation("198.51.100.20", False, discovery_methods=["ARP"], mac_address="AA:BB:CC:DD:EE:FF")])
        device = build_inventory(snapshot).devices[0]
        self.assertIn("ARP", device.discovered_by)
        self.assertTrue(device.presence_status.startswith("Ativo confirmado"))

    def test_empty_network_has_empty_inventory(self):
        snapshot = ScanSnapshot("198.51.100.0/30", "now", observations=[
            ScanObservation("198.51.100.1", False), ScanObservation("198.51.100.2", False)])
        self.assertEqual(build_inventory(snapshot).devices, [])

    def test_cached_stale_mac_is_not_claimed_as_active(self):
        snapshot = ScanSnapshot("198.51.100.0/24", "now", observations=[
            ScanObservation("198.51.100.20", False, mac_address="AA:BB:CC:DD:EE:FF",
                            mac_state="Stale", discovery_methods=["ARP cache"])])
        device = build_inventory(snapshot).devices[0]
        self.assertFalse(device.is_active)
        self.assertIn("Não confirmado", device.presence_status)
        self.assertEqual(_neighbor_state(4), "Stale")

    def test_discovered_hosts_are_forwarded_to_evidence_pipeline(self):
        from berga_sentinel.evidence import collect_network_evidence
        snapshot = ScanSnapshot("198.51.100.0/24", "now", observations=[
            ScanObservation("198.51.100.20", False, mac_address="AA:BB:CC:DD:EE:FF", discovery_methods=["ARP"])])
        result = build_inventory(snapshot)
        with patch("berga_sentinel.evidence.collect_service_fingerprints"):
            collect_network_evidence(result, snapshot)
        self.assertEqual([device.ip for device in result.devices], ["198.51.100.20"])
        self.assertTrue(any(e.kind == "network.mac_address" for e in result.devices[0].evidence))

    def test_customer_report_omits_unconfirmed_arp_cache_entries(self):
        snapshot = ScanSnapshot("198.51.100.0/24", "now", local_ipv4="198.51.100.100", observations=[
            ScanObservation("198.51.100.100", True, discovery_methods=["ICMP", "LOCAL HOST"]),
            ScanObservation("198.51.100.20", False, mac_address="AA:BB:CC:DD:EE:FF",
                            mac_state="Stale", discovery_methods=["ARP cache"])])
        result = build_inventory(snapshot)
        with tempfile.TemporaryDirectory() as directory:
            developer_path = write_html(result, Path(directory) / "tech.html", "developer")
            client_path = write_html(result, Path(directory) / "client.html", "client")
            self.assertIn("198.51.100.20", developer_path.read_text(encoding="utf-8"))
            self.assertNotIn("198.51.100.20", client_path.read_text(encoding="utf-8"))


class FailureHandlingTests(unittest.IsolatedAsyncioTestCase):
    async def test_arp_failure_does_not_abort_host_sweep(self):
        observation = ScanObservation("198.51.100.1", False)
        with self.assertLogs("berga_sentinel.scanner", level="ERROR"), \
             patch("berga_sentinel.scanner.read_neighbor_table", side_effect=OSError("ARP indisponível")), \
             patch("berga_sentinel.scanner._probe_host_safely", new=AsyncMock(return_value=observation)):
            snapshot = await _scan_async(ipaddress.ip_network("198.51.100.0/30"))
        self.assertEqual(snapshot.addresses_scanned, 2)
        self.assertTrue(any(error.startswith("ARP") for error in snapshot.discovery_errors))

    async def test_active_arp_response_is_added_to_inventory(self):
        profile = _valid_profile("Ethernet", 7, "198.51.100.1", 30, "198.51.100.2")
        responses = [ScanObservation("198.51.100.1", False), ScanObservation("198.51.100.2", False)]
        with patch("berga_sentinel.scanner.platform.system", return_value="Windows"), \
             patch("berga_sentinel.scanner.read_neighbor_table", return_value={}), \
             patch("berga_sentinel.scanner.probe_arp_network", return_value={"198.51.100.2": ("AA:BB:CC:DD:EE:FF", "Respondendo")}), \
             patch("berga_sentinel.scanner._probe_host_safely", new=AsyncMock(side_effect=responses)):
            snapshot = await _scan_async(profile.network, network_profile=profile)
        inventory = build_inventory(snapshot)
        by_ip = {device.ip: device for device in inventory.devices}
        self.assertIn("ARP", by_ip["198.51.100.2"].discovered_by)
        self.assertTrue(by_ip["198.51.100.1"].is_local)

    async def test_icmp_failure_is_nonfatal_when_tcp_finds_host(self):
        observation = ScanObservation("198.51.100.1", False, open_ports=[80], discovery_methods=["TCP"])
        with patch("berga_sentinel.scanner.read_neighbor_table", return_value={}), \
             patch("berga_sentinel.scanner._probe_host_safely", new=AsyncMock(return_value=observation)):
            snapshot = await _scan_async(ipaddress.ip_network("198.51.100.0/30"))
        self.assertIn("TCP", snapshot.observations[0].discovery_methods)

    async def test_tcp_timeout_is_treated_as_no_response_not_fatal_error(self):
        with patch("berga_sentinel.scanner.asyncio.open_connection", side_effect=asyncio.TimeoutError):
            opened = await _connect_port("192.0.2.1", 80, asyncio.Semaphore(1), asyncio.Semaphore(1))
        self.assertEqual(opened, (False, False, True))

    async def test_tcp_refusal_is_still_evidence_that_host_is_active(self):
        with patch("berga_sentinel.scanner._ping", new=AsyncMock(return_value=(False, "Não identificado", None, False))), \
             patch("berga_sentinel.scanner._connect_port", new=AsyncMock(return_value=(False, True, False))), \
             patch("berga_sentinel.scanner.COMMON_PORTS", {80: "HTTP"}), \
             patch("berga_sentinel.scanner._resolve_hostname", new=AsyncMock(return_value="Não identificado")):
            observation = await _probe_host("198.51.100.20", asyncio.Semaphore(1),
                                            asyncio.Semaphore(1), asyncio.Semaphore(1))
        self.assertIn("TCP", observation.discovery_methods)
        self.assertEqual(observation.open_ports, [])

    async def test_no_responses_is_a_valid_completed_sweep(self):
        with patch("berga_sentinel.scanner.read_neighbor_table", return_value={}), \
             patch("berga_sentinel.scanner._probe_host_safely", new=AsyncMock(side_effect=[
                 ScanObservation("198.51.100.1", False), ScanObservation("198.51.100.2", False)])):
            snapshot = await _scan_async(ipaddress.ip_network("198.51.100.0/30"))
        self.assertEqual(snapshot.addresses_scanned, 2)
        self.assertEqual(build_inventory(snapshot).devices, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
