"""Regras de achados e verificações locais de segurança Windows."""

import logging
import platform
import subprocess

from .models import Evidence


LOG = logging.getLogger(__name__)

def _run_powershell(script: str) -> str:
    """Executa script fixo e somente de leitura, sem interpolar entrada do usuário."""
    command = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
    LOG.info("Executando consulta local Windows somente leitura: %s", command)
    completed = subprocess.run(command, capture_output=True, text=True, timeout=25, check=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "PowerShell retornou erro.")
    return completed.stdout.strip()

def collect_windows_evidence() -> list[Evidence]:
    """Coleta evidências locais de Windows sem decidir severidade ou correção."""
    if platform.system().lower() != "windows":
        return [Evidence("windows.not_available", "O auditor não está sendo executado em Windows.", "Plataforma local", confidence=1.0)]
    checks = [
        ("windows.firewall.disabled_profiles", "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Count"),
        ("windows.defender.antivirus_enabled", "(Get-MpComputerStatus).AntivirusEnabled"),
        ("windows.updates.pending_count", "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search(\"IsInstalled=0 and Type='Software'\").Updates.Count"),
        ("windows.uac.enable_lua", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA"),
    ]
    evidence_items: list[Evidence] = []
    for kind, expression in checks:
        try:
            value = _run_powershell(f"$ErrorActionPreference='Stop'; {expression}") or "Sem resultado"
            evidence_items.append(Evidence(kind, value, "PowerShell local somente leitura", confidence=0.95))
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            LOG.exception("Falha na coleta Windows: %s", kind)
            evidence_items.append(Evidence(f"{kind}.error", str(exc), "PowerShell local", confidence=1.0))
    return evidence_items
