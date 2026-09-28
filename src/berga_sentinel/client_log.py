"""Gera a trilha simplificada destinada à leitura e apresentação ao cliente."""

from datetime import datetime
from pathlib import Path

from .models import AuditResult, SEVERITY_ORDER
from .fingerprints import client_device_type, client_display_name
from .presentation import client_finding_title, client_severity

def client_log_path(output_dir: Path, audit_id: str) -> Path:
    return output_dir / f"auditoria-{audit_id}-cliente.log"

def append_client_log(path: Path, message: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_message = str(message).replace("\r", " ").replace("\n", " ")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(f"{datetime.now().astimezone().isoformat(timespec='seconds')} | {safe_message}\n")

def write_client_summary(result: AuditResult, path: Path) -> None:
    append_client_log(path, f"Berga CyberSec | Resumo da auditoria {result.audit_id}")
    append_client_log(path, f"Equipamentos identificados: {len(result.devices)}")
    append_client_log(path, "EQUIPAMENTOS")
    if not result.devices:
        append_client_log(path, "Nenhum equipamento respondeu às verificações desta auditoria.")
    for index, device in enumerate(result.devices, start=1):
        append_client_log(path, f"{index}. {client_display_name(device)} | {device.ip} | {client_device_type(device)}")
    findings = [(client_display_name(device), finding) for device in result.devices for finding in device.findings]
    findings.sort(key=lambda item: SEVERITY_ORDER.get(item[1].severity, 99))
    append_client_log(path, "PONTOS PARA REVISÃO")
    if not findings:
        append_client_log(path, "Nenhum ponto de atenção foi identificado nas verificações realizadas.")
    for target, finding in findings:
        priority = client_severity(finding.severity)
        title = client_finding_title(finding.title)
        append_client_log(path, f"[{priority}] {target} | {title}")
        append_client_log(path, f"Próximo passo recomendado: {finding.recommendation}")
    append_client_log(path, "Equipamentos que não responderam podem não aparecer no inventário.")
    append_client_log(path, "As recomendações devem ser revisadas pelo responsável técnico antes de qualquer mudança.")
    append_client_log(path, f"Auditoria concluída em {result.completed_at}.")
