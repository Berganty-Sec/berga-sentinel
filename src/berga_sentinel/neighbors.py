"""Leitura local, somente de leitura, da tabela de vizinhos (ARP)."""

import ipaddress
import json
import logging
import platform
import re
import subprocess
import socket
import struct
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

LOG = logging.getLogger(__name__)
MAC_RE = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _normalize_mac(value: str) -> str | None:
    compact = re.sub(r"[^0-9a-f]", "", value.lower())
    if len(compact) != 12 or compact == "000000000000":
        return None
    first_octet = int(compact[:2], 16)
    if first_octet & 1:  # multicast MAC não identifica um host individual
        return None
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2)).upper()

def _neighbor_state(value) -> str:
    """Normaliza os valores enum numéricos devolvidos por Get-NetNeighbor."""
    states = {0: "Unreachable", 1: "Incomplete", 2: "Probe", 3: "Delay",
              4: "Stale", 5: "Reachable", 6: "Permanent"}
    try:
        return states.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)

def read_neighbor_table(scope: str) -> dict[str, tuple[str, str]]:
    """Retorna IP -> (MAC, estado). Entradas são filtradas pelo escopo da auditoria."""
    network = ipaddress.ip_network(scope, strict=True)
    entries: dict[str, tuple[str, str]] = {}
    system = platform.system().lower()
    try:
        if system == "windows":
            script = "Get-NetNeighbor -AddressFamily IPv4 | Where-Object {$_.LinkLayerAddress -and $_.State.ToString() -ne 'Incomplete'} | Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress"
            command = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
            LOG.info("Lendo tabela local de vizinhos Windows (somente leitura)")
            completed = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
            if completed.returncode == 0 and completed.stdout.strip():
                rows = json.loads(completed.stdout)
                if isinstance(rows, dict):
                    rows = [rows]
                for row in rows:
                    ip = str(row.get("IPAddress", ""))
                    mac = _normalize_mac(str(row.get("LinkLayerAddress", "")))
                    if mac and _in_scope(ip, network):
                        entries[ip] = (mac, _neighbor_state(row.get("State", "unknown")))
        elif system == "linux":
            arp_file = "/proc/net/arp"
            LOG.info("Lendo tabela local de vizinhos: %s", arp_file)
            with open(arp_file, "r", encoding="ascii", errors="replace") as stream:
                next(stream, None)
                for line in stream:
                    fields = line.split()
                    if len(fields) < 6:
                        continue
                    ip, flags, mac = fields[0], fields[2], fields[3]
                    normalized = _normalize_mac(mac)
                    if normalized and flags != "0x0" and _in_scope(ip, network):
                        entries[ip] = (normalized, "ARP cache")
        else:
            command = ["arp", "-an"] if system == "darwin" else ["arp", "-a"]
            LOG.info("Lendo tabela local de vizinhos: %s", command)
            completed = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
            for line in completed.stdout.splitlines():
                ip_match, mac_match = IP_RE.search(line), MAC_RE.search(line)
                if not ip_match or not mac_match:
                    continue
                ip, mac = ip_match.group(0), _normalize_mac(mac_match.group(0))
                if mac and _in_scope(ip, network):
                    entries[ip] = (mac, "ARP cache")
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        LOG.warning("Não foi possível consultar a tabela ARP local: %s", exc)
    LOG.info("Vizinhos ARP no escopo encontrados: %d", len(entries))
    return entries

def probe_arp_network(scope: str, source_ipv4: str, interface_name: str = "",
                      max_workers: int = 64) -> dict[str, tuple[str, str]]:
    """Consulta cada endereço do enlace local usando recursos ARP nativos disponíveis."""
    system = platform.system().lower()
    network = ipaddress.ip_network(scope, strict=True)
    source = ipaddress.ip_address(source_ipv4)
    if not isinstance(source, ipaddress.IPv4Address) or source not in network:
        raise ValueError("A origem ARP precisa pertencer ao escopo IPv4 detectado.")
    if system == "windows":
        import ctypes
        try:
            api = ctypes.WinDLL("iphlpapi.dll")
            send_arp = api.SendARP
            send_arp.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                 ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
            send_arp.restype = ctypes.c_ulong
        except (AttributeError, OSError) as exc:
            raise OSError(f"API SendARP não disponível: {exc}") from exc

        def probe(address: str) -> tuple[str, str] | None:
            buffer = (ctypes.c_ulong * 2)()
            length = ctypes.c_ulong(ctypes.sizeof(buffer))
            destination = struct.unpack("=I", socket.inet_aton(address))[0]
            origin = struct.unpack("=I", socket.inet_aton(str(source)))[0]
            try:
                status = send_arp(destination, origin, buffer, ctypes.byref(length))
            except OSError:
                return None
            if status != 0 or length.value < 6:
                return None
            raw_mac = ctypes.string_at(ctypes.addressof(buffer), min(length.value, 8))[:6]
            mac = _normalize_mac(":".join(f"{octet:02X}" for octet in raw_mac))
            return (mac, "Respondendo à sonda ARP") if mac else None

        state = "Windows SendARP"
    elif system == "linux":
        arping = shutil.which("arping")
        if not arping:
            raise OSError("arping não está instalado; será usado o cache local ARP.")
        if not interface_name:
            raise ValueError("Interface local necessária para a sonda arping.")

        def probe(address: str) -> tuple[str, str] | None:
            command = [arping, "-c", "1", "-w", "1", "-I", interface_name,
                       "-s", str(source), address]
            try:
                completed = subprocess.run(command, capture_output=True, text=True,
                                           encoding="utf-8", errors="replace", timeout=2.5,
                                           check=False, shell=False)
            except (OSError, subprocess.TimeoutExpired):
                return None
            match = MAC_RE.search(completed.stdout + " " + completed.stderr)
            mac = _normalize_mac(match.group(0)) if completed.returncode == 0 and match else None
            return (mac, "Respondendo à sonda ARP") if mac else None

        state = "Linux arping"
    else:
        raise OSError(f"Sonda ARP ativa não disponível em {platform.system()}.")

    targets = [str(address) for address in network.hosts() if address != source]
    LOG.info("Sonda ARP ativa iniciada: método=%s interface=%s IPv4=%s escopo=%s alvos=%d concorrência=%d",
             state, interface_name or "não informada", source, network,
             len(targets), min(max_workers, len(targets) or 1))
    found: dict[str, tuple[str, str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(targets) or 1))) as pool:
        futures = {pool.submit(probe, address): address for address in targets}
        for future in as_completed(futures):
            address = futures[future]
            try:
                result = future.result()
            except Exception:
                LOG.exception("Falha na sonda ARP para %s", address)
                continue
            if result:
                found[address] = result
    LOG.info("Sonda ARP ativa concluída: alvos=%d respostas=%d", len(targets), len(found))
    return found

def _in_scope(value: str, network: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(value) in network
    except ValueError:
        return False
