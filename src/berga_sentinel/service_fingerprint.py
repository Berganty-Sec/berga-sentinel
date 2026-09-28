"""Identificação protocolar não autenticada, sem comandos de alteração."""

import logging
import struct
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import DEFAULT_CONFIG
from .models import Device, Evidence
from .service_catalog import HTTP_PORTS, HTTPS_PORTS

LOG = logging.getLogger(__name__)
MAX_FINGERPRINT_WORKERS = DEFAULT_CONFIG.scan.fingerprint_workers
FINGERPRINT_TIMEOUT = DEFAULT_CONFIG.scan.fingerprint_timeout_seconds
MAX_RESPONSE_BYTES = 4096

def _printable(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    text = "".join(character if character.isprintable() or character in "\r\n\t" else " " for character in text)
    return text.strip()[:512]

def _read_banner(device: Device, port: int, timeout: float = FINGERPRINT_TIMEOUT) -> list[Evidence]:
    results: list[Evidence] = []
    try:
        with socket.create_connection((device.ip, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            if port == 23:
                connection.sendall(b"\r\n")
            if port == 21:
                try:
                    connection.recv(2048)  # greeting FTP
                    connection.sendall(b"FEAT\r\n")  # consulta de capacidade; não autentica nem altera estado
                    chunks = []
                    total = 0
                    # Exige o terminador da resposta multilinha para evitar conclusões
                    # a partir de uma resposta FEAT truncada.
                    while total < MAX_RESPONSE_BYTES:
                        chunk = connection.recv(min(1024, MAX_RESPONSE_BYTES - total))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if b"211 End" in b"".join(chunks):
                            break
                    response = b"".join(chunks)
                    text = _printable(response)
                    if text:
                        results.append(Evidence("ftp.features", text, "Resposta à consulta FTP FEAT", confidence=0.85))
                except (OSError, TimeoutError):
                    pass
            else:
                try:
                    data = connection.recv(MAX_RESPONSE_BYTES)
                    if port == 23 and b"\xff" in data:
                        results.append(Evidence("service.telnet_protocol", "Negociação de opções Telnet recebida.",
                                                "Resposta ao protocolo Telnet", confidence=0.95))
                    text = _printable(data)
                    if text:
                        results.append(Evidence("service.banner", text, f"Banner TCP em {port}", confidence=0.8))
                except (OSError, TimeoutError):
                    pass
    except (OSError, TimeoutError) as exc:
        LOG.debug("Fingerprint de banner indisponível para %s:%d: %s", device.ip, port, exc)
    return results

def _http_head(device: Device, port: int, use_tls: bool,
               timeout: float = FINGERPRINT_TIMEOUT) -> list[Evidence]:
    results: list[Evidence] = []
    raw_socket = None
    try:
        raw_socket = socket.create_connection((device.ip, port), timeout=timeout)
        raw_socket.settimeout(timeout)
        connection = raw_socket
        if use_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # apenas coleta de metadados, nunca envia credenciais
            connection = context.wrap_socket(raw_socket, server_hostname=device.hostname if device.hostname != "Não identificado" else device.ip)
            results.append(Evidence("tls.negotiated", f"{connection.version()} / {connection.cipher()[0] if connection.cipher() else 'cifra desconhecida'}", f"Handshake TLS na porta {port}", confidence=0.95))
        request = f"HEAD / HTTP/1.0\r\nHost: {device.ip}\r\nUser-Agent: BergaSentinel-Audit\r\nConnection: close\r\n\r\n".encode("ascii")
        connection.sendall(request)
        response = connection.recv(MAX_RESPONSE_BYTES)
        headers = _printable(response)
        if headers:
            status = headers.splitlines()[0] if headers.splitlines() else headers[:120]
            results.append(Evidence("http.head_response", status, f"HEAD / porta {port}", confidence=0.9))
            for header in headers.splitlines()[1:]:
                if header.lower().startswith(("server:", "www-authenticate:", "x-device-model:", "x-printer:")):
                    key, value = header.split(":", 1)
                    results.append(Evidence(f"http.header.{key.lower()}", value.strip(), f"Cabeçalho HTTP na porta {port}", confidence=0.85))
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        LOG.debug("Fingerprint HTTP/TLS indisponível para %s:%d: %s", device.ip, port, exc)
    finally:
        if raw_socket:
            try:
                raw_socket.close()
            except OSError:
                pass
    return results

def _probe_legacy_tls(device: Device, port: int, version: ssl.TLSVersion,
                      timeout: float = FINGERPRINT_TIMEOUT) -> Evidence | None:
    """Tests whether a TLS endpoint accepts a legacy protocol; no credentials are sent."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        with socket.create_connection((device.ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=device.ip) as secured:
                negotiated = secured.version() or version.name
                return Evidence("tls.legacy_version", negotiated,
                                f"Handshake TLS limitado a {version.name} na porta {port}", confidence=0.95)
    except (OSError, ssl.SSLError, ValueError, TimeoutError):
        return None

def _probe_smb1(device: Device, timeout: float = FINGERPRINT_TIMEOUT) -> list[Evidence]:
    """Envia apenas uma negociação SMB sem autenticação, sem acesso a arquivos."""
    dialect = b"\x02NT LM 0.12\x00"
    smb_header = struct.pack("<4sBIBHH8sHHHHH", b"\xffSMB", 0x72, 0, 0x18, 0xC853,
                             0, bytes(8), 0, 0, 0, 0, 1)
    body = b"\x00" + struct.pack("<H", len(dialect)) + dialect
    payload = smb_header + body
    packet = b"\x00" + len(payload).to_bytes(3, "big") + payload
    try:
        with socket.create_connection((device.ip, 445), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(packet)
            netbios = connection.recv(4)
            if len(netbios) != 4:
                return [Evidence("smb.smb1_probe", "Sem resposta completa à negociação SMB1.", "Negociação SMB sem autenticação", confidence=0.4)]
            length = int.from_bytes(netbios[1:], "big")
            response = bytearray()
            while len(response) < min(length, 2048):
                chunk = connection.recv(min(2048, length) - len(response))
                if not chunk:
                    break
                response.extend(chunk)
            if len(response) >= 35 and response[:4] == b"\xffSMB" and response[4] == 0x72:
                status = struct.unpack_from("<I", response, 5)[0]
                dialect_index = struct.unpack_from("<H", response, 33)[0]
                if status == 0 and dialect_index != 0xFFFF:
                    return [Evidence("smb.smb1_supported", f"Servidor aceitou o dialeto SMB1 (índice {dialect_index}).",
                                     "Negociação SMB sem autenticação, sem acesso a arquivos", confidence=0.99)]
            return [Evidence("smb.smb1_probe", "SMB1 não foi confirmado pela resposta observada.",
                             "Negociação SMB sem autenticação", confidence=0.65)]
    except (OSError, TimeoutError) as exc:
        LOG.debug("Negociação SMB1 não conclusiva em %s: %s", device.ip, exc)
        return [Evidence("smb.smb1_probe", f"Negociação SMB1 não conclusiva: {type(exc).__name__}.",
                         "Negociação SMB sem autenticação", confidence=0.35)]

def _probe_one(device: Device, port: int, timeout: float = FINGERPRINT_TIMEOUT) -> list[Evidence]:
    if port in HTTP_PORTS:
        return _http_head(device, port, False, timeout)
    if port in HTTPS_PORTS:
        results = _http_head(device, port, True, timeout)
        for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            evidence = _probe_legacy_tls(device, port, version, timeout)
            if evidence:
                results.append(evidence)
        return results
    if port == 445:
        return _probe_smb1(device, timeout)
    if port in {21, 22, 23, 25, 110, 143}:
        return _read_banner(device, port, timeout)
    return []

def collect_service_fingerprints(devices: list[Device], max_workers: int = MAX_FINGERPRINT_WORKERS,
                                 timeout: float = FINGERPRINT_TIMEOUT) -> None:
    jobs = [(device, port) for device in devices for port in device.open_ports
            if port in HTTP_PORTS | HTTPS_PORTS | {21, 22, 23, 25, 110, 143, 445}]
    LOG.info("Coletando fingerprints não autenticados para %d serviço(s)", len(jobs))
    if not jobs:
        return
    workers = max(1, min(max_workers, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sentinel-fingerprint") as pool:
        # Submit bounded batches so a large inventory cannot leave every probe
        # job queued in the executor at once.
        for offset in range(0, len(jobs), workers * 2):
            batch = jobs[offset:offset + workers * 2]
            futures = {pool.submit(_probe_one, device, port, timeout): (device, port)
                       for device, port in batch}
            for future in as_completed(futures):
                device, port = futures[future]
                try:
                    findings = future.result()
                    for evidence in findings:
                        evidence.host_ip = device.ip
                    device.evidence.extend(findings)
                except Exception:
                    LOG.exception("Falha ao obter fingerprint de %s:%d", device.ip, port)
