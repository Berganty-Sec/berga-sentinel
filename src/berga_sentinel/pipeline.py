"""Orquestra o fluxo Scanner → Inventário → Evidências → Regras → Risco."""

import logging
import threading
from datetime import datetime, timezone

from .config import DEFAULT_CONFIG, SentinelConfig
from .checks import collect_windows_evidence
from .evidence import collect_network_evidence
from .inventory import build_inventory
from .risk import classify_risks
from .rules import evaluate_rules
from .scanner import scan_network
from .network_interface import NetworkInterface

LOG = logging.getLogger(__name__)

def run_audit(scope: str, progress=None, on_stage=None, audit_id: str | None = None,
              network_profile: NetworkInterface | None = None,
              config: SentinelConfig = DEFAULT_CONFIG,
              cancel_event: threading.Event | None = None):
    def stage(name: str):
        LOG.info("Etapa da auditoria: %s", name)
        if on_stage:
            on_stage(name)

    stage("Scanner")
    snapshot = scan_network(scope, progress, network_profile, config, cancel_event)
    stage("Inventário")
    result = build_inventory(snapshot, audit_id)
    stage("Evidências")
    if not snapshot.cancelled and not (cancel_event and cancel_event.is_set()):
        collect_network_evidence(result, snapshot, config)
        if not (cancel_event and cancel_event.is_set()):
            windows_evidence = collect_windows_evidence()
            for evidence in windows_evidence:
                evidence.host_ip = result.local_ipv4 or "LOCAL HOST"
                evidence.technical_details.setdefault("scope", result.scope)
            result.evidence.extend(windows_evidence)
    stage("Regras")
    evaluate_rules(result, config)
    stage("Risco")
    classify_risks(result, config)
    result.notes.append("Severidade e pontuação são classificações heurísticas do Berga Sentinel; não equivalem a CVSS nem confirmam vulnerabilidade.")
    result.completed_at = datetime.now(timezone.utc).isoformat()
    result.cancelled = snapshot.cancelled or bool(cancel_event and cancel_event.is_set())
    LOG.info("Auditoria %s concluída: %d ativos, %d achados", result.audit_id,
             len(result.devices), sum(len(device.findings) for device in result.devices) + len(result.findings))
    return result
