"""Normaliza observações do scanner como evidências atribuídas aos ativos."""

from .models import AuditResult, Evidence, ScanSnapshot
from .config import DEFAULT_CONFIG, SentinelConfig
from .fingerprints import classify_device
from .service_fingerprint import collect_service_fingerprints
from .service_catalog import COMMON_PORTS

def collect_network_evidence(result: AuditResult, snapshot: ScanSnapshot,
                             config: SentinelConfig = DEFAULT_CONFIG) -> None:
    by_ip = {device.ip: device for device in result.devices}
    for observation in snapshot.observations:
        device = by_ip.get(observation.ip)
        if device is None:
            continue
        if observation.icmp_reachable:
            device.evidence.append(Evidence(
                kind="icmp.reachable", value="Host respondeu a uma sondagem ICMP.",
                source="ICMP echo", confidence=0.9, host_ip=observation.ip,
                technical_details={"ttl": observation.ttl} if observation.ttl is not None else {},
            ))
        if observation.operating_system_hint != "Não identificado":
            device.evidence.append(Evidence(
                kind="os.ttl_hint", value=f"TTL observado={observation.ttl}; pista={observation.operating_system_hint}",
                source="Inferência heurística baseada no TTL de ICMP", confidence=0.35,
                host_ip=observation.ip, technical_details={"ttl": observation.ttl or 0},
            ))
        if observation.hostname != "Não identificado":
            device.evidence.append(Evidence(
                kind="dns.reverse_name", value=observation.hostname,
                source="Resolução DNS reversa", confidence=0.65, host_ip=observation.ip,
            ))
        if observation.mac_address != "Não identificado":
            device.evidence.append(Evidence(
                kind="network.mac_address", value=observation.mac_address,
                source=f"Tabela local de vizinhos ARP ({observation.mac_state})", confidence=0.9,
                host_ip=observation.ip, technical_details={"neighbor_state": observation.mac_state},
            ))
        for port in observation.open_ports:
            service = COMMON_PORTS.get(port, "serviço desconhecido")
            device.services[port] = service
            device.evidence.append(Evidence(
                kind="tcp.open_port", value=f"TCP/{port} respondeu ({service}).",
                source="Conexão TCP", confidence=0.95, host_ip=observation.ip,
                technical_details={"protocol": "tcp", "port": port, "catalog_label": service},
            ))
    collect_service_fingerprints(result.devices, config.scan.fingerprint_workers,
                                 config.scan.fingerprint_timeout_seconds)
    for device in result.devices:
        classify_device(device)
        device.attribute_provenance["device_type"] = {
            "method": "Inferência por OUI, hostname e serviços observados",
            "observed_at": device.collected_at,
            "confidence": device.device_type_confidence,
        }
