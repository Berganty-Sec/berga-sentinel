"""Integração de rede real. Só executa com escopo e autorização explícitos."""

import ipaddress
import os
import sys
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

PROJECT_SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(PROJECT_SRC))

from berga_sentinel.models import AuditResult
from berga_sentinel.output_layout import AuditOutputLayout
from berga_sentinel.reporting import write_audit_json, write_html, write_inventory_csv, write_pdf
from berga_sentinel.scanner import scan_network, validate_scope
from berga_sentinel.inventory import build_inventory
from berga_sentinel.service_catalog import COMMON_PORTS


REQUIRED_ENV = (
    "BERGA_SENTINEL_LIVE_CIDR",
    "BERGA_SENTINEL_EXPECTED_HOSTS",
    "BERGA_SENTINEL_AUTHORIZED",
)
LIVE_TEST_REQUESTED = any(os.environ.get(name, "").strip() for name in REQUIRED_ENV)


@unittest.skipUnless(
    LIVE_TEST_REQUESTED,
    "Teste real bloqueado: configure CIDR, IPs conhecidos ativos e autorização explícita no ambiente.",
)
class LiveNetworkAuditTests(unittest.TestCase):
    """Varrimento real restrito ao CIDR fornecido pelo operador autorizado."""

    @classmethod
    def setUpClass(cls):
        missing = [name for name in REQUIRED_ENV if not os.environ.get(name, "").strip()]
        if missing:
            raise ValueError(f"Configuração incompleta do teste real; faltam: {', '.join(missing)}")
        if os.environ["BERGA_SENTINEL_AUTHORIZED"].strip().upper() != "YES":
            raise PermissionError("Teste real bloqueado: defina BERGA_SENTINEL_AUTHORIZED=YES somente após confirmar autorização.")
        cls.scope = validate_scope(os.environ["BERGA_SENTINEL_LIVE_CIDR"])
        cls.expected_hosts = {
            str(ipaddress.ip_address(value.strip()))
            for value in os.environ["BERGA_SENTINEL_EXPECTED_HOSTS"].split(",")
            if value.strip()
        }
        if not cls.expected_hosts:
            raise unittest.SkipTest("Informe ao menos um IP que você sabe estar ativo.")
        usable = {str(address) for address in cls.scope.hosts()}
        outside_scope = cls.expected_hosts - usable
        if outside_scope:
            raise ValueError(f"IP(s) esperado(s) fora dos endereços utilizáveis do CIDR: {sorted(outside_scope)}")

    def test_real_scan_covers_scope_catalog_and_known_active_hosts(self):
        progress = []
        snapshot = scan_network(str(self.scope), lambda done, total, ip: progress.append((done, total, ip)))
        usable = {str(address) for address in self.scope.hosts()}
        expected_ports = sorted(COMMON_PORTS)

        # Prova que o scanner concluiu todas as sondagens no intervalo configurado.
        self.assertEqual(snapshot.addresses_scanned, len(usable))
        self.assertEqual({item.ip for item in snapshot.observations}, usable)
        self.assertEqual(len(progress), len(usable))
        for observation in snapshot.observations:
            self.assertEqual(observation.tcp_ports_attempted, expected_ports, observation.ip)

        result = build_inventory(snapshot, audit_id=f"live-{uuid4().hex[:10]}")
        discovered = {device.ip for device in result.devices}
        missing_known_hosts = self.expected_hosts - discovered
        self.assertFalse(
            missing_known_hosts,
            "Equipamento(s) conhecido(s) ativo(s) não apareceram no inventário: "
            f"{sorted(missing_known_hosts)}. Verifique filtros ICMP/TCP e tabela ARP.",
        )

        # Gera artefatos a partir dos resultados da rede real e confere a pasta única.
        with tempfile.TemporaryDirectory(prefix="berga-sentinel-live-") as temporary:
            layout = AuditOutputLayout.create(Path(temporary), result.audit_id)
            write_html(result, layout.directory / "relatorio-tecnico.html", "developer")
            write_pdf(result, layout.directory / "relatorio-tecnico.pdf", "developer")
            write_html(result, layout.directory / "relatorio-operacional.html", "analyst")
            write_pdf(result, layout.directory / "relatorio-operacional.pdf", "analyst")
            client_html = write_html(result, layout.directory / "relatorio-cliente.html", "client")
            write_pdf(result, layout.directory / "relatorio-cliente.pdf", "client")
            write_inventory_csv(result, layout.directory / "inventario-detalhado.csv", "developer")
            write_inventory_csv(result, layout.directory / "inventario-cliente.csv", "client")
            write_audit_json(result, layout.directory / "auditoria-completa.json")

            artifacts = list(layout.directory.iterdir())
            self.assertEqual(len(artifacts), 9)
            self.assertTrue(all(path.is_file() for path in artifacts))
            self.assertEqual(list(Path(temporary).iterdir()), [layout.directory])
            technical_report = (layout.directory / "relatorio-tecnico.html").read_text(encoding="utf-8")
            client_report = client_html.read_text(encoding="utf-8")
            self.assertNotIn("Observações brutas do scanner", technical_report)
            self.assertNotIn("Observações brutas do scanner", client_report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
