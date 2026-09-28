"""Transforma as respostas brutas do scanner em um inventário de ativos."""

from dataclasses import asdict
from uuid import uuid4

from .models import AuditResult, Device, ScanSnapshot
from .oui import lookup_vendor

def build_inventory(snapshot: ScanSnapshot, audit_id: str | None = None) -> AuditResult:
    """Consolida evidências ARP/ICMP/TCP por IP e envia cada host uma vez ao pipeline."""
    devices = [
        Device(
            ip=item.ip,
            hostname=item.hostname,
            operating_system=item.operating_system_hint,
            mac_address=item.mac_address,
            mac_vendor=lookup_vendor(item.mac_address) if item.mac_address != "Não identificado" else "Não identificado",
            presence_status=(f"Ativo confirmado via {', '.join(item.discovery_methods)}"
                             if {"ARP", "ICMP", "TCP", "LOCAL HOST"}.intersection(item.discovery_methods)
                             else f"Não confirmado; somente cache ARP ({item.mac_state or 'estado desconhecido'})"),
            discovered_by=list(dict.fromkeys(item.discovery_methods)),
            is_active=bool({"ARP", "ICMP", "TCP", "LOCAL HOST"}.intersection(item.discovery_methods)),
            is_local=item.ip == snapshot.local_ipv4,
            role=("Gateway" if item.ip == snapshot.gateway else
                  "LOCAL HOST" if item.ip == snapshot.local_ipv4 else "Host"),
            open_ports=sorted(item.open_ports),
            services={},
        )
        for item in snapshot.observations
        if item.discovery_methods or item.icmp_reachable or item.open_ports or item.mac_address != "Não identificado"
    ]
    return AuditResult(
        scope=snapshot.scope,
        audit_id=audit_id or uuid4().hex[:12],
        started_at=snapshot.started_at,
        devices=devices,
        notes=list(snapshot.notes),
        addresses_scanned=snapshot.addresses_scanned,
        interface_name=snapshot.interface_name,
        local_ipv4=snapshot.local_ipv4,
        prefix_length=snapshot.prefix_length,
        gateway=snapshot.gateway,
        discovery_method_counts=dict(snapshot.method_counts),
        discovery_timeout_counts=dict(snapshot.timeout_counts),
        discovery_errors=list(snapshot.discovery_errors),
        raw_scan=[asdict(item) for item in snapshot.observations],
    )
