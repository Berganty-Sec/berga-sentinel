"""Detecção somente leitura da interface IPv4 com rota padrão ativa."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import logging
import platform
import re
import subprocess

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    interface_index: int | None
    ipv4: str
    prefix_length: int
    gateway: str
    mac_address: str = ""
    source: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_interface(f"{self.ipv4}/{self.prefix_length}").network

    @property
    def scope(self) -> str:
        return str(self.network)


def _run(command: list[str], timeout: float = 5) -> str:
    completed = subprocess.run(command, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=timeout,
                               check=False, shell=False)
    if completed.returncode:
        raise OSError(completed.stderr.strip() or f"Comando retornou {completed.returncode}")
    return completed.stdout.strip()


def _valid_profile(name: str, index: int | None, ipv4: str, prefix: int,
                   gateway: str, mac: str = "", source: str = "") -> NetworkInterface:
    address = ipaddress.ip_address(ipv4)
    if not isinstance(address, ipaddress.IPv4Address) or address.is_loopback or address.is_link_local:
        raise ValueError("A interface não possui IPv4 unicast utilizável.")
    if not 0 <= int(prefix) <= 32:
        raise ValueError("Prefixo IPv4 inválido.")
    gateway_address = ipaddress.ip_address(gateway)
    if not isinstance(gateway_address, ipaddress.IPv4Address):
        raise ValueError("O gateway IPv4 da rota padrão não é válido.")
    normalized_mac = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(normalized_mac) == 12:
        normalized_mac = ":".join(normalized_mac[position:position + 2] for position in range(0, 12, 2))
    else:
        normalized_mac = ""
    profile = NetworkInterface(name=name.strip(), interface_index=index, ipv4=str(address),
                               prefix_length=int(prefix), gateway=str(gateway_address),
                               mac_address=normalized_mac, source=source)
    if profile.network.num_addresses > 256:
        raise ValueError(f"A rede detectada ({profile.scope}) excede o limite seguro de 256 endereços.")
    return profile


def _detect_windows() -> NetworkInterface:
    # Escolhe somente interfaces com rota padrão IPv4 ativa; não usa adaptadores
    # virtuais/desconectados nem amplia o escopo além da sub-rede local.
    script = (
        "$ErrorActionPreference='Stop'; "
        "$routes=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
        "| Where-Object {$_.State -eq 'Alive'} | Sort-Object RouteMetric,InterfaceMetric; "
        "foreach($r in $routes){ $c=Get-NetIPConfiguration -InterfaceIndex $r.InterfaceIndex "
        "-ErrorAction SilentlyContinue; if($c.IPv4Address -and $r.NextHop -and $r.NextHop -ne '0.0.0.0'){ "
        "$a=$c.IPv4Address | Where-Object {$_.IPAddress -notlike '169.254.*'} | Select-Object -First 1; "
        "if($a){$n=Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{InterfaceAlias=$c.InterfaceAlias;InterfaceIndex=$r.InterfaceIndex; "
        "IPv4Address=$a.IPAddress;PrefixLength=$a.PrefixLength;Gateway=$r.NextHop; "
        "MacAddress=$n.MacAddress} | ConvertTo-Json -Compress; break}}}"
    )
    raw = _run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script])
    if not raw:
        raise OSError("Nenhuma interface IPv4 ativa com gateway padrão foi encontrada.")
    row = json.loads(raw)
    return _valid_profile(str(row["InterfaceAlias"]), int(row["InterfaceIndex"]),
                          str(row["IPv4Address"]), int(row["PrefixLength"]),
                          str(row["Gateway"]), str(row.get("MacAddress") or ""),
                          "Get-NetRoute/Get-NetIPConfiguration")


def _detect_linux() -> NetworkInterface:
    routes = json.loads(_run(["ip", "-j", "route", "show", "default"]))
    if not routes:
        raise OSError("Nenhuma rota padrão foi encontrada.")
    routes.sort(key=lambda route: (int(route.get("metric", 0)), route.get("dev", "")))
    last_error: Exception | None = None
    for route in routes:
        name = route.get("dev")
        gateway = route.get("gateway")
        if not name or not gateway:
            continue
        try:
            addresses = json.loads(_run(["ip", "-j", "address", "show", "dev", name]))
            for interface in addresses:
                if not interface.get("operstate", "UP") == "UP":
                    continue
                for address in interface.get("addr_info", []):
                    if address.get("family") == "inet" and address.get("scope") == "global":
                        return _valid_profile(name, int(interface.get("ifindex", 0)),
                                              address["local"], int(address["prefixlen"]),
                                              gateway, interface.get("address", ""), "ip route/ip address")
        except (OSError, ValueError, KeyError) as exc:
            last_error = exc
    raise OSError(f"Não foi possível associar a rota padrão a um IPv4 ativo: {last_error or 'sem IPv4 global'}")


def detect_active_interface() -> NetworkInterface:
    """Retorna a interface IPv4 associada à rota padrão, sem iniciar sondas."""
    system = platform.system().lower()
    LOG.info("Detectando interface IPv4 ativa do sistema operacional: %s", system)
    if system == "windows":
        profile = _detect_windows()
    elif system == "linux":
        profile = _detect_linux()
    else:
        raise OSError(f"Detecção automática de interface ainda não implementada para {platform.system()}.")
    LOG.info("Interface detectada: interface=%s índice=%s IPv4=%s/%d gateway=%s escopo=%s MAC=%s",
             profile.name, profile.interface_index, profile.ipv4, profile.prefix_length,
             profile.gateway, profile.scope, profile.mac_address or "não disponível")
    return profile
