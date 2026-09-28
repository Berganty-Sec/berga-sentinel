"""Tipos de dados compartilhados entre scanner, verificações e relatórios."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

SEVERITY_ORDER = {"Crítica": 0, "Alta": 1, "Média": 2, "Baixa": 3, "Informativa": 4}

@dataclass
class Finding:
    title: str
    severity: str
    evidence: str
    recommendation: str
    category: str = "Configuração"
    risk_score: int | None = None
    confidence: float = 0.6
    context: dict[str, str | int | float | bool] = field(default_factory=dict)
    rule_id: str = ""
    justification: str = ""
    risk_justification: str = ""
    base_risk_score: int | None = None

@dataclass
class Evidence:
    """Observação coletada; ainda não é, por si só, uma conclusão de risco."""
    kind: str
    value: str
    source: str
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 0.8
    host_ip: str = ""
    technical_details: dict[str, str | int | float | bool] = field(default_factory=dict)

@dataclass
class Device:
    ip: str
    hostname: str = "Não identificado"
    operating_system: str = "Não identificado"
    mac_address: str = "Não identificado"
    mac_vendor: str = "Não identificado"
    device_type: str = "Não classificado"
    device_type_confidence: float = 0.0
    presence_status: str = "Respondendo"
    discovered_by: list[str] = field(default_factory=list)
    is_active: bool = True
    is_local: bool = False
    role: str = "Host"
    criticality: str = "Desconhecida"
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attribute_provenance: dict[str, dict[str, str | float]] = field(default_factory=dict)

@dataclass
class AuditResult:
    scope: str
    audit_id: str = field(default_factory=lambda: uuid4().hex[:12])
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""
    devices: list[Device] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    addresses_scanned: int = 0
    interface_name: str = ""
    local_ipv4: str = ""
    prefix_length: int | None = None
    gateway: str = ""
    discovery_method_counts: dict[str, int] = field(default_factory=dict)
    discovery_timeout_counts: dict[str, int] = field(default_factory=dict)
    discovery_errors: list[str] = field(default_factory=list)
    raw_scan: list[dict[str, Any]] = field(default_factory=list)
    cancelled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class ScanObservation:
    """Resultado bruto de sondas para um endereço do escopo."""
    ip: str
    icmp_reachable: bool
    operating_system_hint: str = "Não identificado"
    ttl: int | None = None
    hostname: str = "Não identificado"
    mac_address: str = "Não identificado"
    mac_state: str = ""
    open_ports: list[int] = field(default_factory=list)
    tcp_ports_attempted: list[int] = field(default_factory=list)
    discovery_methods: list[str] = field(default_factory=list)
    icmp_timeout: bool = False
    tcp_timeouts: int = 0
    error: str = ""
    observed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class ScanSnapshot:
    scope: str
    started_at: str
    addresses_scanned: int = 0
    observations: list[ScanObservation] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    interface_name: str = ""
    local_ipv4: str = ""
    prefix_length: int | None = None
    gateway: str = ""
    method_counts: dict[str, int] = field(default_factory=dict)
    timeout_counts: dict[str, int] = field(default_factory=dict)
    discovery_errors: list[str] = field(default_factory=list)
    cancelled: bool = False
