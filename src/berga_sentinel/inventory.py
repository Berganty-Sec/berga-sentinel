"""Transforma as respostas brutas do scanner em um inventário de ativos."""

from dataclasses import asdict
from uuid import uuid4

from .models import AuditResult, Device, ScanObservation, ScanSnapshot
from .oui import lookup_vendor

def build_inventory(snapshot: ScanSnapshot, audit_id: str | None = None) -> AuditResult:
    """Consolida evidências ARP/ICMP/TCP por IP e envia cada host uma vez ao pipeline."""
    def to_device(item: ScanObservation) -> Device:
        vendor = lookup_vendor(item.mac_address) if item.mac_address != "Não identificado" else "Não identificado"
        mac_method = ("ARP ativo" if "ARP" in item.discovery_methods else
                      f"Tabela local de vizinhos ({item.mac_state})" if item.mac_address != "Não identificado" else "")
        provenance = {
            "ip": {"method": "Sondas limitadas ao escopo autorizado", "observed_at": item.observed_at,
                   "confidence": 1.0},
        }
        if item.hostname != "Não identificado":
            provenance["hostname"] = {"method": "DNS reverso", "observed_at": item.observed_at,
                                      "confidence": 0.65}
        if item.mac_address != "Não identificado":
            provenance["mac_address"] = {"method": mac_method, "observed_at": item.observed_at,
                                         "confidence": 0.99 if "ARP" in item.discovery_methods else 0.65}
        if vendor != "Não identificado" and "não identificado" not in vendor.lower() and "não disponível" not in vendor.lower():
            provenance["mac_vendor"] = {"method": "Consulta OUI local", "observed_at": item.observed_at,
                                         "confidence": 0.9}
        if item.operating_system_hint != "Não identificado":
            provenance["operating_system"] = {"method": "Inferência heurística de TTL ICMP",
                                              "observed_at": item.observed_at, "confidence": 0.35}
        if item.open_ports:
            provenance["ports"] = {"method": "Conexão TCP", "observed_at": item.observed_at,
                                    "confidence": 0.95}
            provenance["services"] = {"method": "Catálogo local por porta", "observed_at": item.observed_at,
                                      "confidence": 0.5}
        return Device(
            ip=item.ip,
            hostname=item.hostname,
            operating_system=item.operating_system_hint,
            mac_address=item.mac_address,
            mac_vendor=vendor,
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
            collected_at=item.observed_at,
            attribute_provenance=provenance,
        )
    devices = [to_device(item) for item in snapshot.observations
               if item.discovery_methods or item.icmp_reachable or item.open_ports
               or item.mac_address != "Não identificado"]
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
        cancelled=snapshot.cancelled,
    )
