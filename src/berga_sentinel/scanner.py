"""Descoberta conservadora e sondagem TCP, limitadas ao escopo aprovado."""

import asyncio
import ipaddress
import logging
import platform
import re
import socket
from datetime import datetime, timezone

from .models import ScanObservation, ScanSnapshot
from .neighbors import probe_arp_network, read_neighbor_table
from .network_interface import NetworkInterface, detect_active_interface
from .service_catalog import COMMON_PORTS

LOG = logging.getLogger(__name__)
MAX_ADDRESSES = 256
MAX_CONCURRENT_TCP = 192
MAX_CONCURRENT_PER_HOST = 6
MAX_CONCURRENT_PINGS = 32
CONNECT_TIMEOUT = 0.5
DNS_TIMEOUT = 1.0
def validate_scope(value: str) -> ipaddress.IPv4Network:
    """Aceita somente CIDR IPv4 explícito de até 256 endereços."""
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError as exc:
        raise ValueError("Informe a rede IPv4 na notação CIDR usando o endereço base, por exemplo 198.51.100.0/24; host bits não serão normalizados automaticamente.") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("A primeira versão aceita somente redes IPv4.")
    if network.num_addresses > MAX_ADDRESSES:
        raise ValueError("O escopo máximo desta versão é de 256 endereços IPv4.")
    return network

async def _ping(ip: str, ping_limit: asyncio.Semaphore) -> tuple[bool, str, int | None, bool]:
    """Executa ping curto; sua saída fornece uma pista fraca de sistema operacional."""
    command = (["ping", "-n", "1", "-w", "500", ip] if platform.system().lower() == "windows"
               else ["ping", "-c", "1", "-W", "1", ip])
    process = None
    try:
        LOG.debug("Executando descoberta ICMP: %s", command)
        async with ping_limit:
            process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=2.0)
        output = (stdout + b" " + stderr).decode(errors="replace")
        match = re.search(r"\bttl\s*[=:]\s*(\d+)", output, re.IGNORECASE)
        ttl = int(match.group(1)) if match else None
        # Heurística de TTL inicial comum; roteadores podem reduzir o valor em trânsito.
        os_hint = "Não identificado"
        if ttl is not None:
            os_hint = ("Provável Windows" if ttl > 64 and ttl <= 128 else
                       "Provável Linux/Unix" if ttl <= 64 else "Possível equipamento de rede/Unix")
            LOG.info("Resposta ICMP de %s; TTL observado=%d; pista SO=%s", ip, ttl, os_hint)
        return process.returncode == 0, os_hint, ttl, False
    except (OSError, asyncio.TimeoutError) as exc:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        LOG.debug("ICMP sem resposta de %s: %s", ip, exc)
        return False, "Não identificado", None, isinstance(exc, asyncio.TimeoutError)

async def _connect_port(ip: str, port: int, global_limit: asyncio.Semaphore,
                        host_limit: asyncio.Semaphore) -> tuple[bool, bool, bool]:
    async with host_limit:
        async with global_limit:
            LOG.debug("Executando sonda TCP de conexão: destino=%s porta=%d", ip, port)
            writer = None
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT)
                LOG.debug("Conexão TCP estabelecida em %s:%d", ip, port)
                return True, True, False
            except (ConnectionRefusedError, ConnectionResetError):
                # RST/recusa é resposta TCP válida: a porta está fechada, mas
                # demonstra que há uma pilha TCP alcançável nesse endereço.
                LOG.debug("Resposta TCP de porta fechada em %s:%d", ip, port)
                return False, True, False
            except asyncio.TimeoutError:
                LOG.debug("Timeout TCP em %s:%d", ip, port)
                return False, False, True
            except OSError:
                return False, False, False
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await asyncio.wait_for(writer.wait_closed(), timeout=0.2)
                    except (OSError, asyncio.TimeoutError):
                        pass

async def _resolve_hostname(ip: str) -> str:
    try:
        return (await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, ip), timeout=DNS_TIMEOUT))[0]
    except (OSError, socket.herror, asyncio.TimeoutError):
        return "Não identificado"

async def _probe_host(ip: str, global_limit: asyncio.Semaphore, ping_limit: asyncio.Semaphore,
                      host_limit: asyncio.Semaphore) -> ScanObservation:
    ping_task = asyncio.create_task(_ping(ip, ping_limit))
    ports = list(COMMON_PORTS)
    outcomes = await asyncio.gather(*(
        _connect_port(ip, port, global_limit, host_limit) for port in ports
    ), return_exceptions=True)
    opened = [port for port, outcome in zip(ports, outcomes)
              if isinstance(outcome, tuple) and outcome[0]]
    tcp_responsive = any(isinstance(outcome, tuple) and outcome[1] for outcome in outcomes)
    tcp_timeouts = sum(outcome[2] for outcome in outcomes if isinstance(outcome, tuple))
    for port, outcome in zip(ports, outcomes):
        if isinstance(outcome, Exception):
            LOG.warning("Falha de sonda em %s:%d: %s", ip, port, outcome)
    active, os_hint, ttl, icmp_timeout = await ping_task
    hostname = await _resolve_hostname(ip) if active or opened else "Não identificado"
    if active or opened:
        LOG.info("Resolução reversa de %s: %s", ip, hostname)
    methods = (["ICMP"] if active else [])
    if tcp_responsive:
        methods.append("TCP")
    return ScanObservation(ip=ip, icmp_reachable=active, operating_system_hint=os_hint,
                           ttl=ttl, hostname=hostname, open_ports=opened,
                           tcp_ports_attempted=sorted(ports), discovery_methods=methods,
                           icmp_timeout=icmp_timeout, tcp_timeouts=tcp_timeouts)

async def _probe_host_safely(ip: str, global_limit: asyncio.Semaphore, ping_limit: asyncio.Semaphore,
                             host_limit: asyncio.Semaphore) -> ScanObservation:
    """Garante uma observação por endereço mesmo quando uma sonda lança erro inesperado."""
    try:
        return await _probe_host(ip, global_limit, ping_limit, host_limit)
    except Exception:
        LOG.exception("Falha não tratada durante a sondagem do host %s", ip)
        return ScanObservation(ip=ip, icmp_reachable=False,
                               error="Falha de coleta; detalhes no log técnico.")

async def _scan_async(network: ipaddress.IPv4Network, progress=None,
                      network_profile: NetworkInterface | None = None) -> ScanSnapshot:
    addresses = [str(ip) for ip in (network.hosts() if network.num_addresses > 2 else network)]
    LOG.info("Início da auditoria; escopo=%s; endereços=%d; portas=%d", network, len(addresses), len(COMMON_PORTS))
    snapshot = ScanSnapshot(scope=str(network), started_at=datetime.now(timezone.utc).isoformat(),
                            addresses_scanned=len(addresses))
    if network_profile:
        snapshot.interface_name = network_profile.name
        snapshot.local_ipv4 = network_profile.ipv4
        snapshot.prefix_length = network_profile.prefix_length
        snapshot.gateway = network_profile.gateway
    LOG.info("BERGA SENTINEL — NETWORK DISCOVERY | interface=%s IPv4=%s/%s gateway=%s scope=%s",
             snapshot.interface_name or "não informada", snapshot.local_ipv4 or "não informada",
             snapshot.prefix_length if snapshot.prefix_length is not None else "?",
             snapshot.gateway or "não identificado", network)
    # Primeiro aproveita entradas locais de vizinhança já conhecidas. As sondas
    # ICMP/TCP seguintes também provocam resolução ARP natural em LAN Ethernet/Wi-Fi.
    try:
        initial_neighbors = await asyncio.to_thread(read_neighbor_table, str(network))
    except Exception as exc:
        initial_neighbors = {}
        snapshot.discovery_errors.append(f"ARP inicial: {type(exc).__name__}: {exc}")
        LOG.exception("Falha na descoberta inicial via ARP")
    LOG.info("Método ARP (cache local inicial): %d host(s)", len(initial_neighbors))
    active_neighbors: dict[str, tuple[str, str]] = {}
    if network_profile and network_profile.network == network and platform.system().lower() in {"windows", "linux"}:
        try:
            active_neighbors = await asyncio.to_thread(
                probe_arp_network, str(network), network_profile.ipv4, network_profile.name)
            initial_neighbors.update(active_neighbors)
        except (OSError, ValueError, RuntimeError) as exc:
            snapshot.discovery_errors.append(f"ARP ativo: {type(exc).__name__}: {exc}")
            LOG.exception("Sonda ARP ativa falhou; continuará com cache local, ICMP e TCP")
    else:
        LOG.info("ARP ativo não aplicável; serão usados cache local, ICMP e TCP")
    global_limit = asyncio.Semaphore(MAX_CONCURRENT_TCP)
    ping_limit = asyncio.Semaphore(MAX_CONCURRENT_PINGS)
    host_limits = {ip: asyncio.Semaphore(MAX_CONCURRENT_PER_HOST) for ip in addresses}
    tasks = [asyncio.create_task(_probe_host_safely(ip, global_limit, ping_limit, host_limits[ip]), name=ip) for ip in addresses]
    done = 0
    for task in asyncio.as_completed(tasks):
        done += 1
        observation = await task
        snapshot.observations.append(observation)
        if observation.icmp_reachable or observation.discovery_methods:
            LOG.info("Host respondeu às sondas: %s; métodos=%s; portas=%s", observation.ip,
                     observation.discovery_methods, observation.open_ports)
        else:
            LOG.debug("Sem resposta às sondas configuradas: %s", observation.ip)
        if progress:
            progress(done, len(addresses), snapshot.observations[-1].ip)

    snapshot.observations.sort(key=lambda item: ipaddress.ip_address(item.ip))
    LOG.info("Enriquecendo inventário com tabela local de vizinhos após ICMP/TCP")
    neighbor_map = dict(initial_neighbors)
    try:
        final_neighbors = await asyncio.to_thread(read_neighbor_table, str(network))
        for ip, entry in final_neighbors.items():
            if ip not in active_neighbors:
                neighbor_map[ip] = entry
    except Exception as exc:
        snapshot.discovery_errors.append(f"ARP: {type(exc).__name__}: {exc}")
        LOG.exception("Falha consultando a tabela de vizinhos após as sondas")
    by_ip = {item.ip: item for item in snapshot.observations}
    hostname_lookups = []
    for ip, (mac, state) in neighbor_map.items():
        observation = by_ip.get(ip)
        if observation:
            observation.mac_address = mac
            observation.mac_state = state
            # Só resposta à sonda SendARP ou vizinhança atualmente Reachable
            # confirma presença ARP. Stale/Permanent permanecem como pista de cache.
            method = "ARP" if ip in active_neighbors or state.lower() == "reachable" else "ARP cache"
            if method not in observation.discovery_methods:
                observation.discovery_methods.append(method)
            if observation.hostname == "Não identificado":
                hostname_lookups.append((observation, ip))
            LOG.info("Vizinho ARP associado: ip=%s mac=%s estado=%s", ip, mac, state)
    dns_limit = asyncio.Semaphore(32)
    async def resolve_arp_hostname(observation: ScanObservation, ip: str):
        async with dns_limit:
            observation.hostname = await _resolve_hostname(ip)
    if hostname_lookups:
        await asyncio.gather(*(resolve_arp_hostname(observation, ip)
                               for observation, ip in hostname_lookups))
    if network_profile and network_profile.ipv4 in by_ip:
        local = by_ip[network_profile.ipv4]
        local.discovery_methods.append("LOCAL HOST")
        if network_profile.mac_address and local.mac_address == "Não identificado":
            local.mac_address = network_profile.mac_address
            local.mac_state = "Interface local"
        if local.hostname == "Não identificado":
            local.hostname = "LOCAL HOST"
    method_order = {"ARP": 0, "ICMP": 1, "TCP": 2, "LOCAL HOST": 3}
    for observation in snapshot.observations:
        observation.discovery_methods = sorted(set(observation.discovery_methods),
                                               key=lambda method: method_order.get(method, 99))
    snapshot.method_counts = {
        method: sum(method in observation.discovery_methods for observation in snapshot.observations)
        for method in ("ARP", "ICMP", "TCP", "LOCAL HOST", "ARP cache")
    }
    snapshot.timeout_counts = {
        "ICMP": sum(item.icmp_timeout for item in snapshot.observations),
        "TCP": sum(item.tcp_timeouts for item in snapshot.observations),
    }
    snapshot.discovery_errors.extend(
        f"{item.ip}: {item.error}" for item in snapshot.observations if item.error
    )

    snapshot.notes.extend([
        "A ausência de resposta não confirma que um host esteja desligado; ICMP e portas podem ser filtrados.",
        "A pista de sistema operacional usa heurística de TTL de ping e pode estar incorreta ou indisponível quando ICMP é filtrado.",
        "Entradas ARP em cache sem resposta ativa são listadas como não confirmadas e não contam como host ativo.",
        "O inventário lista respostas ICMP/TCP e vizinhos MAC observados; equipamentos silenciosos podem permanecer invisíveis.",
        "A classificação de fabricante depende de uma base OUI local; nenhum endereço MAC é enviado para serviços externos.",
    ])
    active_methods = {"ARP", "ICMP", "TCP", "LOCAL HOST"}
    responding = sum(bool(active_methods.intersection(item.discovery_methods))
                     for item in snapshot.observations)
    LOG.info("BERGA SENTINEL — NETWORK DISCOVERY concluída | escopo=%s | endereços sondados=%d | hosts ativos=%d | entradas observadas=%d | por método=%s | timeouts=%s | erros=%d",
             network, len(addresses), responding, len(snapshot.observations), snapshot.method_counts, snapshot.timeout_counts,
             len(snapshot.discovery_errors))
    return snapshot

def scan_network(scope: str | None = None, progress=None,
                 network_profile: NetworkInterface | None = None) -> ScanSnapshot:
    """Sonda todos os endereços autorizados com concorrência global e por host limitada."""
    profile = network_profile
    if scope is None:
        profile = profile or detect_active_interface()
        scope = profile.scope
    network = validate_scope(scope)
    if profile and profile.network != network:
        # Permite escopo manual autorizado, mas não atribui metadados de outra rede.
        profile = None
    return asyncio.run(_scan_async(network, progress, profile))
