"""Deterministic comparison of two audit snapshots and safe HTML export."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import html
import json
from pathlib import Path

from .models import AuditResult, Device, Finding


@dataclass(frozen=True)
class FindingChange:
    host_ip: str
    rule_id: str
    title: str
    severity: str


@dataclass(frozen=True)
class AssetChange:
    host_ip: str
    changed_fields: tuple[str, ...]
    before: dict[str, object]
    after: dict[str, object]


@dataclass(frozen=True)
class AuditComparison:
    previous_audit_id: str
    current_audit_id: str
    previous_completed_at: str
    current_completed_at: str
    new_findings: tuple[FindingChange, ...]
    resolved_findings: tuple[FindingChange, ...]
    persistent_findings: tuple[FindingChange, ...]
    added_assets: tuple[str, ...]
    removed_assets: tuple[str, ...]
    changed_assets: tuple[AssetChange, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize comparison into JSON-safe builtin values."""
        return asdict(self)


def _finding_map(result: AuditResult) -> dict[tuple[str, str], FindingChange]:
    findings: dict[tuple[str, str], FindingChange] = {}
    groups: list[tuple[str, list[Finding]]] = [("ESCOPO", result.findings)]
    groups.extend((device.ip, device.findings) for device in result.devices)
    for host, items in groups:
        for finding in items:
            rule_id = finding.rule_id or f"{finding.category}:{finding.title}"
            findings[(host, rule_id)] = FindingChange(host, rule_id, finding.title, finding.severity)
    return findings


def _asset_map(result: AuditResult) -> dict[str, Device]:
    return {device.ip: device for device in result.devices}


def compare_audits(previous: AuditResult, current: AuditResult) -> AuditComparison:
    """Compare findings and inventory without interpreting observations as risks."""
    if previous.scope != current.scope:
        raise ValueError("Só é possível comparar auditorias do mesmo escopo IPv4.")
    before_findings = _finding_map(previous)
    after_findings = _finding_map(current)
    new_keys = after_findings.keys() - before_findings.keys()
    resolved_keys = before_findings.keys() - after_findings.keys()
    persistent_keys = before_findings.keys() & after_findings.keys()

    before_assets, after_assets = _asset_map(previous), _asset_map(current)
    shared_ips = before_assets.keys() & after_assets.keys()
    fields = ("hostname", "mac_address", "mac_vendor", "operating_system", "device_type",
              "open_ports", "services", "is_active", "presence_status")
    changed: list[AssetChange] = []
    for ip in sorted(shared_ips):
        old, new = before_assets[ip], after_assets[ip]
        changed_fields = tuple(name for name in fields if getattr(old, name) != getattr(new, name))
        if changed_fields:
            changed.append(AssetChange(
                ip, changed_fields,
                {name: getattr(old, name) for name in changed_fields},
                {name: getattr(new, name) for name in changed_fields},
            ))

    return AuditComparison(
        previous_audit_id=previous.audit_id,
        current_audit_id=current.audit_id,
        previous_completed_at=previous.completed_at,
        current_completed_at=current.completed_at,
        new_findings=tuple(after_findings[key] for key in sorted(new_keys)),
        resolved_findings=tuple(before_findings[key] for key in sorted(resolved_keys)),
        persistent_findings=tuple(after_findings[key] for key in sorted(persistent_keys)),
        added_assets=tuple(sorted(after_assets.keys() - before_assets.keys())),
        removed_assets=tuple(sorted(before_assets.keys() - after_assets.keys())),
        changed_assets=tuple(changed),
    )


def write_comparison_html(comparison: AuditComparison, path: Path) -> Path:
    """Write a standalone escaped HTML comparison report."""
    esc = lambda value: html.escape(str(value), quote=True)

    def finding_rows(items: tuple[FindingChange, ...]) -> str:
        return "".join(
            f"<tr><td>{esc(item.host_ip)}</td><td>{esc(item.severity)}</td>"
            f"<td>{esc(item.title)}</td><td>{esc(item.rule_id)}</td></tr>"
            for item in items
        ) or '<tr><td colspan="4">Nenhum item.</td></tr>'

    changes = "".join(
        f"<tr><td>{esc(item.host_ip)}</td><td>{esc(', '.join(item.changed_fields))}</td>"
        f"<td>{esc(json.dumps(item.before, ensure_ascii=False, sort_keys=True))}</td>"
        f"<td>{esc(json.dumps(item.after, ensure_ascii=False, sort_keys=True))}</td></tr>"
        for item in comparison.changed_assets
    ) or '<tr><td colspan="4">Nenhuma alteração nos ativos compartilhados.</td></tr>'
    asset_rows = lambda items: "".join(f"<li>{esc(ip)}</li>" for ip in items) or "<li>Nenhum.</li>"
    doc = f'''<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Comparação de auditorias · Berga CyberSec</title>
<style>body{{font:14px/1.5 Arial,sans-serif;color:#152334;margin:30px auto;max-width:1200px;padding:0 20px}}header{{background:#10243a;color:white;padding:24px;border-radius:10px}}h2{{margin-top:28px;border-bottom:2px solid #16a085}}table{{border-collapse:collapse;width:100%;margin:12px 0 24px}}th,td{{border:1px solid #d7dee5;padding:8px;text-align:left;vertical-align:top}}th{{background:#eef3f7}}</style>
<body><header><strong>BERGA CYBERSEC · COMPARAÇÃO DE AUDITORIAS</strong><h1>Alterações entre auditorias</h1>
<p>Anterior: {esc(comparison.previous_audit_id)} · {esc(comparison.previous_completed_at)}</p>
<p>Atual: {esc(comparison.current_audit_id)} · {esc(comparison.current_completed_at)}</p></header>
<h2>Novos achados</h2><table><tr><th>IP</th><th>Severidade</th><th>Achado</th><th>Regra</th></tr>{finding_rows(comparison.new_findings)}</table>
<h2>Achados resolvidos</h2><table><tr><th>IP</th><th>Severidade anterior</th><th>Achado</th><th>Regra</th></tr>{finding_rows(comparison.resolved_findings)}</table>
<h2>Achados persistentes</h2><table><tr><th>IP</th><th>Severidade</th><th>Achado</th><th>Regra</th></tr>{finding_rows(comparison.persistent_findings)}</table>
<h2>Ativos adicionados</h2><ul>{asset_rows(comparison.added_assets)}</ul><h2>Ativos removidos</h2><ul>{asset_rows(comparison.removed_assets)}</ul>
<h2>Alterações no inventário</h2><table><tr><th>IP</th><th>Campos alterados</th><th>Antes</th><th>Depois</th></tr>{changes}</table>
<p>Comparação descritiva de snapshots locais. Diferenças não confirmam causa ou remediação.</p></body></html>'''
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(doc, encoding="utf-8")
    return path
