"""Offline tests for platform adapters, classifiers, and service collectors."""

import asyncio
import ipaddress
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, mock_open, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from berga_sentinel.fingerprints import classify_device, client_device_type, client_display_name
from berga_sentinel.models import Device, Evidence
from berga_sentinel.neighbors import _in_scope, _normalize_mac, probe_arp_network, read_neighbor_table
from berga_sentinel.network_interface import _detect_linux, _detect_windows, _valid_profile
from berga_sentinel.oui import _load_oui, lookup_vendor
from berga_sentinel.service_fingerprint import (
    _http_head, _probe_one, _probe_smb1, _read_banner, collect_service_fingerprints,
)


class FakeSocket:
    """Small socket test double: all bytes are in memory and no OS socket opens."""

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.sent = []
        self.closed = False
        self.timeout = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, _size):
        return self.responses.pop(0) if self.responses else b""

    def close(self):
        self.closed = True


class LocalNeighborTests(unittest.TestCase):
    def test_normalizes_only_individual_unicast_macs(self):
        self.assertEqual(_normalize_mac("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(_normalize_mac("01:00:5e:00:00:01"))
        self.assertIsNone(_normalize_mac("00:00:00:00:00:00"))
        self.assertTrue(_in_scope("198.51.100.20", ipaddress.ip_network("198.51.100.0/24")))
        self.assertFalse(_in_scope("192.0.2.1", ipaddress.ip_network("198.51.100.0/24")))

    def test_windows_neighbor_table_is_filtered_to_scope_and_valid_macs(self):
        rows = [
            {"IPAddress": "198.51.100.1", "LinkLayerAddress": "AA-BB-CC-DD-EE-FF", "State": "Reachable"},
            {"IPAddress": "192.0.2.10", "LinkLayerAddress": "AA-BB-CC-DD-EE-01", "State": "Reachable"},
            {"IPAddress": "198.51.100.2", "LinkLayerAddress": "01-00-5E-00-00-01", "State": "Reachable"},
        ]
        completed = SimpleNamespace(returncode=0, stdout=json.dumps(rows), stderr="")
        with patch("berga_sentinel.neighbors.platform.system", return_value="Windows"), \
             patch("berga_sentinel.neighbors.subprocess.run", return_value=completed):
            neighbors = read_neighbor_table("198.51.100.0/24")
        self.assertEqual(neighbors, {"198.51.100.1": ("AA:BB:CC:DD:EE:FF", "Reachable")})

    def test_linux_neighbor_table_uses_only_valid_in_scope_rows(self):
        table = "IP address HW type Flags HW address Mask Device\n198.51.100.1 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n192.0.2.1 0x1 0x2 aa:bb:cc:dd:ee:01 * eth0\n198.51.100.2 0x1 0x0 aa:bb:cc:dd:ee:02 * eth0\n"
        with patch("berga_sentinel.neighbors.platform.system", return_value="Linux"), \
             patch("builtins.open", mock_open(read_data=table)):
            neighbors = read_neighbor_table("198.51.100.0/24")
        self.assertEqual(neighbors, {"198.51.100.1": ("AA:BB:CC:DD:EE:FF", "ARP cache")})

    def test_linux_arping_probe_is_bounded_and_uses_passed_interface(self):
        completed = SimpleNamespace(returncode=0, stdout="Reply from 198.51.100.2 [AA:BB:CC:DD:EE:FF]", stderr="")
        with patch("berga_sentinel.neighbors.platform.system", return_value="Linux"), \
             patch("berga_sentinel.neighbors.shutil.which", return_value="/usr/sbin/arping"), \
             patch("berga_sentinel.neighbors.subprocess.run", return_value=completed) as run:
            found = probe_arp_network("198.51.100.0/30", "198.51.100.1", "eth-test", max_workers=1)
        self.assertEqual(found["198.51.100.2"][0], "AA:BB:CC:DD:EE:FF")
        command = run.call_args.args[0]
        self.assertIn("eth-test", command)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertLessEqual(run.call_args.kwargs["timeout"], 2.5)

    def test_arp_probe_rejects_source_outside_confirmed_scope(self):
        with self.assertRaises(ValueError):
            probe_arp_network("198.51.100.0/24", "192.0.2.20")


class InterfaceParsingTests(unittest.TestCase):
    def test_windows_interface_json_maps_to_validated_profile(self):
        row = {"InterfaceAlias": "Ethernet", "InterfaceIndex": 7, "IPv4Address": "198.51.100.20",
               "PrefixLength": 24, "Gateway": "198.51.100.1", "MacAddress": "aa-bb-cc-dd-ee-ff"}
        with patch("berga_sentinel.network_interface._run", return_value=json.dumps(row)):
            profile = _detect_windows()
        self.assertEqual(profile.scope, "198.51.100.0/24")
        self.assertEqual(profile.mac_address, "AA:BB:CC:DD:EE:FF")

    def test_linux_route_and_interface_json_are_correlated(self):
        outputs = [
            json.dumps([{"dst": "default", "dev": "eth-test", "gateway": "198.51.100.1", "metric": 10}]),
            json.dumps([{"ifindex": 4, "operstate": "UP", "address": "aa:bb:cc:dd:ee:ff",
                         "addr_info": [{"family": "inet", "scope": "global", "local": "198.51.100.20", "prefixlen": 24}]}]),
        ]
        with patch("berga_sentinel.network_interface._run", side_effect=outputs):
            profile = _detect_linux()
        self.assertEqual(profile.name, "eth-test")
        self.assertEqual(profile.gateway, "198.51.100.1")
        self.assertEqual(profile.network, ipaddress.ip_network("198.51.100.0/24"))

    def test_invalid_network_profiles_are_rejected(self):
        with self.assertRaises(ValueError):
            _valid_profile("lo", 1, "127.0.0.1", 8, "127.0.0.2")
        with self.assertRaises(ValueError):
            _valid_profile("wide", 1, "10.0.0.1", 8, "10.0.0.254")


class ClassificationAndOuiTests(unittest.TestCase):
    def test_classifies_windows_android_printer_and_network_equipment(self):
        cases = [
            (Device("198.51.100.1", operating_system="Provável Windows", open_ports=[445]), "Windows provável"),
            (Device("198.51.100.2", hostname="android-phone", mac_vendor="Samsung Electronics"), "Android provável"),
            (Device("198.51.100.3", open_ports=[9100]), "Impressora de rede provável"),
            (Device("198.51.100.4", mac_vendor="Ubiquiti"), "Equipamento de rede provável"),
        ]
        for device, expected in cases:
            with self.subTest(expected=expected):
                classify_device(device)
                self.assertEqual(device.device_type, expected)
                self.assertGreater(device.device_type_confidence, 0.5)
        self.assertEqual(client_device_type(cases[0][0]), "Computador Windows")

    def test_oui_lookup_is_local_and_handles_missing_and_randomized_macs(self):
        _load_oui.cache_clear()
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "oui.csv"
            database.write_text("Assignment,Organization Name\n00BBCC,Example Network Vendor\n", encoding="utf-8")
            self.assertEqual(lookup_vendor("00:BB:CC:12:34:56", database), "Example Network Vendor")
            self.assertIn("aleatório", lookup_vendor("02:11:22:33:44:55", database))
            self.assertIn("ausente", lookup_vendor("00:BB:CC:12:34:56", Path(directory) / "missing.csv"))
        _load_oui.cache_clear()

    def test_client_display_name_prefers_local_label_then_hostname(self):
        self.assertEqual(client_display_name(Device("198.51.100.10", is_local=True)), "LOCAL HOST")
        self.assertEqual(client_display_name(Device("198.51.100.11", hostname="printer.local")), "printer.local")


class ServiceFingerprintTests(unittest.TestCase):
    def test_http_head_records_status_and_safe_selected_headers(self):
        sock = FakeSocket([b"HTTP/1.1 200 OK\r\nServer: appliance\r\nX-Printer: model-1\r\n\r\n"])
        with patch("berga_sentinel.service_fingerprint.socket.create_connection", return_value=sock):
            evidence = _http_head(Device("198.51.100.10"), 80, False)
        self.assertIn("http.head_response", {item.kind for item in evidence})
        self.assertIn("http.header.server", {item.kind for item in evidence})
        self.assertTrue(any(item.value == "model-1" for item in evidence))
        self.assertIn(b"HEAD / HTTP/1.0", sock.sent[0])
        self.assertTrue(sock.closed)

    def test_telnet_banner_requires_protocol_negotiation_evidence(self):
        sock = FakeSocket([b"\xff\xfb\x01 device banner"])
        with patch("berga_sentinel.service_fingerprint.socket.create_connection", return_value=sock):
            evidence = _read_banner(Device("198.51.100.10"), 23)
        self.assertIn("service.telnet_protocol", {item.kind for item in evidence})
        self.assertEqual(sock.sent, [b"\r\n"])

    def test_ftp_banner_keeps_complete_feat_response_and_does_not_authenticate(self):
        sock = FakeSocket([b"220 ready\r\n", b"211-Features\r\n AUTH TLS\r\n211 End\r\n"])
        with patch("berga_sentinel.service_fingerprint.socket.create_connection", return_value=sock):
            evidence = _read_banner(Device("198.51.100.10"), 21)
        self.assertEqual([item.kind for item in evidence], ["ftp.features"])
        self.assertIn(b"FEAT\r\n", sock.sent)
        self.assertNotIn("USER", b"".join(sock.sent).decode("ascii"))

    def test_smb1_probe_builds_anonymous_negotiation_and_parses_confirmation(self):
        response = bytearray(35)
        response[:4] = b"\xffSMB"
        response[4] = 0x72
        response[33:35] = b"\x00\x00"
        sock = FakeSocket([b"\x00\x00\x00\x23", bytes(response)])
        with patch("berga_sentinel.service_fingerprint.socket.create_connection", return_value=sock):
            evidence = _probe_smb1(Device("198.51.100.10"))
        self.assertEqual(evidence[0].kind, "smb.smb1_supported")
        self.assertIn(b"NT LM 0.12", sock.sent[0])

    def test_probe_dispatch_and_concurrent_collection_attach_host_ip(self):
        with patch("berga_sentinel.service_fingerprint._http_head", return_value=[Evidence("test", "ok", "mock")]) as http:
            _probe_one(Device("198.51.100.10"), 80)
        http.assert_called_once()
        host = Device("198.51.100.10", open_ports=[80])
        with patch("berga_sentinel.service_fingerprint._probe_one",
                   return_value=[Evidence("test", "ok", "mock")]):
            collect_service_fingerprints([host], max_workers=1)
        self.assertEqual(host.evidence[0].host_ip, host.ip)


if __name__ == "__main__":
    unittest.main(verbosity=2)
