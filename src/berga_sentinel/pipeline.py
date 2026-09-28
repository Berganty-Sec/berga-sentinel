"""Orquestra o fluxo Scanner → Inventário → Evidências → Regras → Risco."""

import logging
from datetime import datetime, timezone

from .checks import collect_windows_evidence
from .evidence import collect_network_evidence
from .inventory import build_inventory
from .risk import classify_risks
from .rules import evaluate_rules
from .scanner import scan_network
from .network_interface import NetworkInterface

LOG = logging.getLogger(__name__)

def run_audit(scope: str, progress=None, on_stage=None, audit_id: str | None = None,
              network_profile: NetworkInterface | None = None):
    def stage(name: str):
        LOG.info("Etapa da auditoria: %s", name)
        if on_stage:
            on_stage(name)

    stage("Scanner")
    snapshot = scan_network(scope, progress, network_profile)
    stage("Inventário")
    result = build_inventory(snapshot, audit_id)
    stage("Evidências")
    collect_network_evidence(result, snapshot)
    result.evidence.extend(collect_windows_evidence())
    stage("Regras")
    evaluate_rules(result)
    stage("Risco")
    classify_risks(result)
    result.notes.append("Severidade e pontuação são classificações heurísticas do Berga Sentinel; não equivalem a CVSS nem confirmam vulnerabilidade.")
    result.completed_at = datetime.now(timezone.utc).isoformat()
    LOG.info("Auditoria %s concluída: %d ativos, %d achados", result.audit_id,
             len(result.devices), sum(len(device.findings) for device in result.devices) + len(result.findings))
    return result
