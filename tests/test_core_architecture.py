"""Offline unit and integration tests for Sentinel's modular audit pipeline."""

import asyncio
import ipaddress
import json
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from berga_sentinel.comparison import compare_audits, write_comparison_html
from berga_sentinel.config import (
    DEFAULT_CONFIG, ReportConfig, RuleConfig, ScanConfig, SentinelConfig, load_config,
)
from berga_sentinel.evidence import collect_network_evidence
from berga_sentinel.history import AuditHistory
from berga_sentinel.inventory import build_inventory
from berga_sentinel.models import AuditResult, Device, Evidence, Finding, ScanObservation, ScanSnapshot
from berga_sentinel.output_layout import AuditOutputLayout
from berga_sentinel.reporting import write_audit_json, write_html, write_inventory_csv, write_pdf
from berga_sentinel.risk import classify_risks, severity_for_score
from berga_sentinel.rule_engine import RuleRegistry
from berga_sentinel.rules import evaluate_rules
from berga_sentinel.scanner import _scan_async, validate_scope
from berga_sentinel.pipeline import run_audit


def device_fixture(ip: str = "198.51.100.20", kind: str = "Computador provável") -> Device:
    """Create a representative device fixture with discovery provenance."""
    return Device(
        ip=ip, hostname="endpoint.example.test", mac_address="AA:BB:CC:DD:EE:FF",
        mac_vendor="Vendor local de teste", device_type=kind, open_ports=[80],
        services={80: "HTTP"}, discovered_by=["ARP", "TCP"],
        attribute_provenance={"mac_address": {"method": "ARP", "confidence": 0.9}},
    )


class ConfigurationTests(unittest.TestCase):
    def test_loads_and_validates_central_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel.toml"
            path.write_text('''[scan]\nmax_hosts = 64\nhost_workers = 8\nports = [80, 443]\nfingerprint_timeout_seconds = 2.0\n[rules]\nseverity_thresholds = [90, 70, 45, 15]\n[reports]\nformats = ["html", "json"]\nprofiles = ["developer", "client"]\n[logging]\nlevel = "DEBUG"\n''', encoding="utf-8")
            config = load_config(path)
        self.assertEqual(config.scan.max_hosts, 64)
        self.assertEqual(config.scan.ports, (80, 443))
        self.assertEqual(config.rules.severity_thresholds, (90, 70, 45, 15))
        self.assertEqual(config.reports.profiles, ("developer", "client"))
        self.assertEqual(config.log_level, "DEBUG")

    def test_rejects_unsafe_or_unknown_config_values(self):
        with self.assertRaises(ValueError):
            ScanConfig(ports=(80, 80))
        with self.assertRaises(ValueError):
            ScanConfig(host_workers=0)
        with self.assertRaises(ValueError):
            ReportConfig(formats=("html", "script"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinel.toml"
            path.write_text("[scan]\nunknown = true\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)
            path.write_text('[scan]\nports = "80"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)


class InventoryEvidenceAndRuleTests(unittest.TestCase):
    def test_inventory_accepts_windows_android_printer_and_network_fixtures(self):
        kinds = ["Computador provável", "Android provável", "Impressora de rede provável", "Equipamento de rede provável"]
        observations = [ScanObservation(f"198.51.100.{20 + index}", False,
                                        mac_address=f"AA:BB:CC:DD:EE:{index:02X}",
                                        discovery_methods=["ARP"])
                       for index in range(len(kinds))]
        result = build_inventory(ScanSnapshot("198.51.100.0/24", "start", observations=observations))
        self.assertEqual(len(result.devices), 4)
        for device, kind in zip(result.devices, kinds):
            device.device_type = kind  # modeled output of the classification module
        self.assertEqual([device.device_type for device in result.devices], kinds)

    def test_inventory_keeps_timestamp_and_provenance(self):
        observed = ScanObservation("198.51.100.20", False, hostname="host.example.test",
                                   mac_address="AA:BB:CC:DD:EE:FF", open_ports=[80],
                                   discovery_methods=["ARP", "TCP"], observed_at="2026-01-01T00:00:00+00:00")
        device = build_inventory(ScanSnapshot("198.51.100.0/24", "start", observations=[observed])).devices[0]
        self.assertEqual(device.collected_at, observed.observed_at)
        self.assertEqual(device.attribute_provenance["mac_address"]["method"], "ARP ativo")
        self.assertIn("ports", device.attribute_provenance)

    def test_evidence_records_host_origin_time_and_method(self):
        snapshot = ScanSnapshot("198.51.100.0/24", "start", observations=[
            ScanObservation("198.51.100.20", False, open_ports=[80], discovery_methods=["TCP"]),
        ])
        result = build_inventory(snapshot)
        with patch("berga_sentinel.evidence.collect_service_fingerprints"):
            collect_network_evidence(result, snapshot)
        evidence = next(item for item in result.devices[0].evidence if item.kind == "tcp.open_port")
        self.assertEqual(evidence.host_ip, "198.51.100.20")
        self.assertEqual(evidence.source, "Conexão TCP")
        self.assertTrue(evidence.observed_at)
        self.assertEqual(evidence.technical_details["port"], 80)

    def test_open_445_or_80_is_not_itself_a_vulnerability(self):
        result = AuditResult("198.51.100.0/24", devices=[device_fixture()])
        result.devices[0].open_ports.extend([445])
        result.devices[0].evidence.extend([
            Evidence("tcp.open_port", "TCP/445 respondeu", "Conexão TCP", host_ip=result.devices[0].ip),
            Evidence("tcp.open_port", "TCP/80 respondeu", "Conexão TCP", host_ip=result.devices[0].ip),
        ])
        evaluate_rules(result)
        self.assertEqual(result.devices[0].findings, [])

    def test_rule_registry_adds_findings_only_for_explicit_evidence(self):
        result = AuditResult("198.51.100.0/24", devices=[device_fixture()])
        host = result.devices[0]
        host.evidence.append(Evidence("unit.insecure", "confirmed state", "mock collector",
                                      host_ip=host.ip, confidence=0.8))
        registry = RuleRegistry()
        registry.register("unit.rule", "unit.insecure", lambda *_: [Finding(
            "Mock observation", "Informativa", "confirmed state", "Review it", rule_id="unit.rule",
            justification="Test rule requires an explicit evidence item.", risk_score=50)])
        from berga_sentinel.config import DEFAULT_CONFIG
        registry.evaluate(result, DEFAULT_CONFIG.rules.enabled_rule_ids)
        self.assertEqual(host.findings[0].rule_id, "unit.rule")
        self.assertEqual(host.findings[0].evidence, "confirmed state")

    def test_allowlist_disables_non_selected_rule(self):
        result = AuditResult("198.51.100.0/24", devices=[device_fixture()])
        evidence = Evidence("service.telnet_protocol", "Telnet response", "protocol", host_ip=result.devices[0].ip)
        result.devices[0].evidence.append(evidence)
        config = SentinelConfig(rules=RuleConfig(enabled_rule_ids=("some.other.rule",)))
        evaluate_rules(result, config)
        self.assertEqual(result.devices[0].findings, [])

    def test_builtin_protocol_rules_require_confirming_protocol_evidence(self):
        cases = [
            ("smb.smb1_supported", "SMB1 accepted", "protocol.smb1.accepted"),
            ("tls.legacy_version", "TLSv1", "protocol.tls.legacy"),
            ("ftp.features", "211-Features\\r\\n211 End", "service.ftp.tls_not_advertised"),
        ]
        for kind, value, rule_id in cases:
            with self.subTest(kind=kind):
                host = device_fixture()
                host.evidence.append(Evidence(kind, value, "mocked protocol confirmation", host_ip=host.ip))
                evaluate_rules(AuditResult("198.51.100.0/24", devices=[host]))
                self.assertEqual(host.findings[0].rule_id, rule_id)

    def test_ftp_rule_does_not_claim_missing_tls_from_incomplete_or_positive_response(self):
        for value in ("partial reply", "211-Features\\r\\n AUTH TLS\\r\\n211 End"):
            with self.subTest(value=value):
                host = device_fixture()
                host.evidence.append(Evidence("ftp.features", value, "mock", host_ip=host.ip))
                evaluate_rules(AuditResult("198.51.100.0/24", devices=[host]))
                self.assertEqual(host.findings, [])

    def test_windows_posture_rules_distinguish_insecure_unknown_and_not_available(self):
        insecure_values = [
            ("windows.firewall.disabled_profiles", "2"),
            ("windows.defender.antivirus_enabled", "false"),
            ("windows.updates.pending_count", "3"),
            ("windows.uac.enable_lua", "0"),
        ]
        for kind, value in insecure_values:
            with self.subTest(kind=kind):
                host = device_fixture()
                host.evidence.append(Evidence(kind, value, "mock local query", host_ip=host.ip))
                evaluate_rules(AuditResult("198.51.100.0/24", devices=[host]))
                self.assertEqual(len(host.findings), 1)
                self.assertTrue(host.findings[0].rule_id.startswith("posture."))
                self.assertTrue(host.findings[0].justification)

        for kind, value in (("windows.uac.enable_lua", "unknown"),
                            ("windows.defender.antivirus_enabled.error", "query failed"),
                            ("windows.not_available", "not Windows")):
            with self.subTest(kind=kind):
                host = device_fixture()
                host.evidence.append(Evidence(kind, value, "mock local query", host_ip=host.ip))
                evaluate_rules(AuditResult("198.51.100.0/24", devices=[host]))
                self.assertEqual(len(host.findings), 1)
                self.assertIn("não", host.findings[0].justification.lower())


class RiskEngineTests(unittest.TestCase):
    def test_context_and_confidence_are_explained_and_thresholds_are_configurable(self):
        finding = Finding("Confirmed observation", "Informativa", "evidence", "recommend", risk_score=70,
                          confidence=0.5, rule_id="test.explicit", justification="Rule rationale.")
        host = device_fixture()
        host.criticality = "Alta"
        host.findings.append(finding)
        config = SentinelConfig(rules=RuleConfig(severity_thresholds=(90, 75, 55, 25)))
        result = AuditResult("198.51.100.0/24", devices=[host])
        classify_risks(result, config)
        self.assertEqual(finding.risk_score, 70)
        self.assertEqual(finding.severity, "Média")
        self.assertIn("Rule rationale.", finding.justification)
        self.assertEqual(finding.justification, "Rule rationale.")
        self.assertIn("Pontuação:", finding.risk_justification)
        self.assertEqual(finding.context["context_modifier"], 10)
        self.assertEqual(severity_for_score(80, config), "Alta")
        final_score = finding.risk_score
        classify_risks(result, config)
        self.assertEqual(finding.risk_score, final_score)

    def test_invalid_confidence_is_bounded_safely(self):
        finding = Finding("Observation", "Baixa", "evidence", "review", risk_score=35,
                          confidence=float("nan"))
        host = device_fixture()
        host.findings.append(finding)
        classify_risks(AuditResult("198.51.100.0/24", devices=[host]))
        self.assertEqual(finding.confidence, 0.0)
        self.assertGreaterEqual(finding.risk_score, 0)


class ScannerBoundTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_ping_terminates_its_child_process(self):
        from berga_sentinel.scanner import _ping

        class FakeProcess:
            returncode = None
            killed = False

            async def communicate(self):
                await asyncio.sleep(10)
                return b"", b""

            def kill(self):
                self.killed = True
                self.returncode = -9

            async def wait(self):
                return self.returncode

        process = FakeProcess()
        with patch("berga_sentinel.scanner.platform.system", return_value="Windows"), \
             patch("berga_sentinel.scanner.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
            task = asyncio.create_task(_ping("198.51.100.20", asyncio.Semaphore(1), timeout=10))
            await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(process.killed)

    async def test_host_concurrency_is_bounded(self):
        config = replace(DEFAULT_CONFIG, scan=replace(DEFAULT_CONFIG.scan, ports=(80,), host_workers=2,
                                                        tcp_workers=2, tcp_workers_per_host=1))
        active = 0
        maximum = 0
        lock = asyncio.Lock()

        async def probe(ip, *_args):
            nonlocal active, maximum
            async with lock:
                active += 1
                maximum = max(maximum, active)
            await asyncio.sleep(0.01)
            async with lock:
                active -= 1
            return ScanObservation(ip, False, discovery_methods=[])

        with patch("berga_sentinel.scanner.read_neighbor_table", return_value={}), \
             patch("berga_sentinel.scanner._probe_host_safely", new=probe):
            snapshot = await _scan_async(ipaddress.ip_network("198.51.100.0/29"), config=config)
        self.assertEqual(snapshot.addresses_scanned, 6)
        self.assertLessEqual(maximum, config.scan.host_workers)

    async def test_cancellation_interrupts_inflight_host_batch(self):
        config = replace(DEFAULT_CONFIG, scan=replace(DEFAULT_CONFIG.scan, ports=(80,), host_workers=3))
        cancel = threading.Event()
        loop = asyncio.get_running_loop()
        loop.call_later(0.02, cancel.set)

        async def slow_probe(ip, *_args):
            await asyncio.sleep(5)
            return ScanObservation(ip, False)

        with patch("berga_sentinel.scanner.read_neighbor_table", return_value={}), \
             patch("berga_sentinel.scanner._probe_host_safely", new=slow_probe):
            started = time.monotonic()
            snapshot = await _scan_async(ipaddress.ip_network("198.51.100.0/29"), config=config,
                                         cancel_event=cancel)
        self.assertTrue(snapshot.cancelled)
        self.assertLess(time.monotonic() - started, 1.0)

    async def test_large_scope_is_rejected_before_address_expansion(self):
        config = replace(DEFAULT_CONFIG, scan=replace(DEFAULT_CONFIG.scan, max_hosts=8))
        with self.assertRaises(ValueError):
            await _scan_async(ipaddress.ip_network("10.0.0.0/8"), config=config)


class HistoryComparisonAndReportTests(unittest.TestCase):
    def test_history_roundtrip_and_path_validation(self):
        result = AuditResult("198.51.100.0/24", audit_id="audit-001", devices=[device_fixture()])
        result.devices[0].evidence.append(Evidence("test", "safe", "fixture", host_ip=result.devices[0].ip))
        result.devices[0].findings.append(Finding("Check", "Baixa", "observation", "recommend",
                                                   rule_id="test.check", justification="Observed."))
        with tempfile.TemporaryDirectory() as directory:
            history = AuditHistory(Path(directory) / "history")
            stored = history.save(result)
            loaded = history.load("audit-001")
            self.assertEqual(loaded.devices[0].evidence[0].host_ip, result.devices[0].ip)
            self.assertEqual(loaded.devices[0].findings[0].rule_id, "test.check")
            self.assertEqual(history.latest().audit_id, "audit-001")
            self.assertEqual(stored.parent, Path(directory) / "history")
            with self.assertRaises(ValueError):
                history.load("..\\outside")

    def test_comparison_finds_new_resolved_persistent_and_asset_changes(self):
        old = AuditResult("198.51.100.0/24", audit_id="old", completed_at="t1", devices=[device_fixture()])
        current_device = device_fixture()
        current_device.hostname = "renamed.example.test"
        current = AuditResult("198.51.100.0/24", audit_id="new", completed_at="t2", devices=[current_device])
        old.devices[0].findings.extend([
            Finding("Persistent", "Média", "e1", "r", rule_id="persist"),
            Finding("Resolved", "Baixa", "e2", "r", rule_id="resolved"),
        ])
        current_device.findings.extend([
            Finding("Persistent", "Média", "e1", "r", rule_id="persist"),
            Finding("New", "Alta", "e3", "r", rule_id="new"),
        ])
        comparison = compare_audits(old, current)
        self.assertEqual([x.rule_id for x in comparison.new_findings], ["new"])
        self.assertEqual([x.rule_id for x in comparison.resolved_findings], ["resolved"])
        self.assertEqual([x.rule_id for x in comparison.persistent_findings], ["persist"])
        self.assertIn("hostname", comparison.changed_assets[0].changed_fields)
        with tempfile.TemporaryDirectory() as directory:
            target = write_comparison_html(comparison, Path(directory) / "compare.html")
            self.assertIn("Achados persistentes", target.read_text(encoding="utf-8"))

    def test_comparison_rejects_different_scopes(self):
        with self.assertRaises(ValueError):
            compare_audits(AuditResult("192.0.2.0/24"), AuditResult("198.51.100.0/24"))

    def test_html_reports_escape_untrusted_values_and_client_view_is_simple(self):
        host = device_fixture()
        host.hostname = '<script>alert("x")</script>'
        host.evidence.append(Evidence("test", "<img src=x onerror=alert(1)>", "fixture", host_ip=host.ip))
        host.findings.append(Finding("Observation", "Alta", "<script>bad</script>", "Review safely",
                                     rule_id="test.rule", justification="Evidence based."))
        result = AuditResult("198.51.100.0/24", audit_id="safe-001", devices=[host])
        with tempfile.TemporaryDirectory() as directory:
            technical = write_html(result, Path(directory) / "technical.html", "developer").read_text(encoding="utf-8")
            client = write_html(result, Path(directory) / "client.html", "client").read_text(encoding="utf-8")
            self.assertNotIn("<script>", technical)
            self.assertNotIn("<img src=x", technical)
            self.assertIn("safe-001", client)
            self.assertNotIn("Evidências completas", client)
            self.assertNotIn("onerror=alert(1)", client)

    def test_csv_json_pdf_and_audit_directory_exports(self):
        result = AuditResult("198.51.100.0/24", audit_id="export-1", devices=[device_fixture()])
        with tempfile.TemporaryDirectory() as directory:
            layout = AuditOutputLayout.create(Path(directory), result.audit_id)
            csv_path = write_inventory_csv(result, layout.directory / "inventory.csv")
            json_path = write_audit_json(result, layout.directory / "audit.json")
            pdf_path = write_pdf(result, layout.directory / "report.pdf", "developer")
            self.assertIn("Procedência por campo", csv_path.read_text(encoding="utf-8-sig"))
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["audit_id"], "export-1")
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))
            self.assertEqual(len(list(layout.directory.iterdir())), 3)

    def test_client_log_is_single_line_and_uses_shared_plain_language(self):
        from berga_sentinel.client_log import append_client_log, write_client_summary
        result = AuditResult("198.51.100.0/24", audit_id="client-1", completed_at="now",
                             devices=[device_fixture()])
        result.devices[0].findings.append(Finding(
            "Protocolo Telnet confirmado e acessível", "Alta", "protocol evidence",
            "Use SSH em vez de Telnet.", rule_id="protocol.telnet.cleartext"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "client.log"
            append_client_log(path, "line one\nforged second line")
            write_client_summary(result, path)
            content = path.read_text(encoding="utf-8")
        self.assertIn("line one forged second line", content)
        self.assertIn("Acesso remoto usa Telnet, sem criptografia", content)
        self.assertNotIn("protocol evidence", content)


class LoggingTests(unittest.TestCase):
    def test_logging_configuration_uses_rotation_and_rejects_unknown_level(self):
        from berga_sentinel.logging_config import configure_logging
        fake_root = MagicMock()
        fake_root.handlers = []
        with tempfile.TemporaryDirectory() as directory, \
             patch("berga_sentinel.logging_config.logging.getLogger", return_value=fake_root):
            logfile = configure_logging(Path(directory), "audit123", "DEBUG")
            self.assertTrue(logfile.exists())
            handlers = [call.args[0] for call in fake_root.addHandler.call_args_list]
            self.assertEqual(len(handlers), 2)
            rotating = next(item for item in handlers if hasattr(item, "maxBytes"))
            self.assertEqual(rotating.maxBytes, 5 * 1024 * 1024)
            rotating.close()
            for item in handlers:
                item.close()
            with self.assertRaises(ValueError):
                configure_logging(Path(directory), level="TRACEISH")


class OfflinePipelineIntegrationTests(unittest.TestCase):
    def test_pipeline_connects_inventory_evidence_rules_and_risk_without_network(self):
        observation = ScanObservation("198.51.100.20", False, open_ports=[23],
                                      discovery_methods=["TCP"])
        snapshot = ScanSnapshot("198.51.100.0/24", "2026-01-01T00:00:00+00:00",
                                observations=[observation], addresses_scanned=1)
        config = replace(DEFAULT_CONFIG, scan=replace(DEFAULT_CONFIG.scan, ports=(23,)))

        def inject_observation(result, _snapshot, _config):
            host = result.devices[0]
            host.evidence.append(Evidence("service.telnet_protocol", "Telnet negotiation", "mocked TCP",
                                          host_ip=host.ip, confidence=0.95))

        with patch("berga_sentinel.pipeline.scan_network", return_value=snapshot), \
             patch("berga_sentinel.pipeline.collect_network_evidence", side_effect=inject_observation), \
             patch("berga_sentinel.pipeline.collect_windows_evidence", return_value=[]):
            result = run_audit("198.51.100.0/24", config=config)
        host = result.devices[0]
        self.assertEqual(host.ip, "198.51.100.20")
        self.assertTrue(host.findings)
        self.assertEqual(host.findings[0].rule_id, "protocol.telnet.cleartext")
        self.assertIsNotNone(host.findings[0].risk_score)
        self.assertIn("Pontuação:", host.findings[0].risk_justification)
        self.assertEqual(result.evidence, [])  # device evidence stays attributed to its host

    def test_windows_collection_uses_fixed_local_queries_and_records_each_control(self):
        from berga_sentinel.checks import collect_windows_evidence
        completed = type("Completed", (), {"returncode": 0, "stdout": "True", "stderr": ""})()
        with patch("berga_sentinel.checks.platform.system", return_value="Windows"), \
             patch("berga_sentinel.checks.subprocess.run", return_value=completed) as run:
            evidence = collect_windows_evidence()
        self.assertEqual(len(evidence), 4)
        self.assertEqual(run.call_count, 4)
        for command in (run.call_args_list[0].args[0], run.call_args_list[-1].args[0]):
            self.assertEqual(command[0], "powershell")
            self.assertIn("-NonInteractive", command)
        self.assertEqual({item.kind for item in evidence}, {
            "windows.firewall.disabled_profiles", "windows.defender.antivirus_enabled",
            "windows.updates.pending_count", "windows.uac.enable_lua",
        })


if __name__ == "__main__":
    unittest.main(verbosity=2)
