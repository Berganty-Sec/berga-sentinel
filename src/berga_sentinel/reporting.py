"""Relatórios em três níveis: técnico, operacional e cliente."""

import csv
import html
import json
from datetime import datetime
from pathlib import Path

from .fingerprints import client_device_type, client_display_name
from .models import AuditResult, Finding, SEVERITY_ORDER
from .presentation import CLIENT_SEVERITIES, CLIENT_TITLES
from .service_catalog import COMMON_PORTS

PROFILE_TITLES = {
    "developer": "Relatório Técnico Completo",
    "analyst": "Relatório Operacional de Auditoria",
    "client": "Resumo Executivo de Segurança",
}

def _e(value) -> str:
    return html.escape(str(value), quote=True)

def _all_findings(result: AuditResult, profile: str = "analyst"):
    if profile != "client":
        for finding in result.findings:
            yield "Notebook auditor", finding
    for device in result.devices:
        if profile == "client" and not device.is_active:
            continue
        for finding in device.findings:
            yield client_display_name(device), finding

def _evidence_rows(result: AuditResult, profile: str):
    if profile != "client":
        for evidence in result.evidence:
            yield "Notebook auditor", evidence
    for device in result.devices:
        for evidence in device.evidence:
            yield client_display_name(device), evidence

def write_html(result: AuditResult, path: Path, profile: str = "analyst") -> Path:
    if profile not in PROFILE_TITLES:
        raise ValueError(f"Perfil de relatório desconhecido: {profile}")
    client_view = profile == "client"
    assets = []
    report_devices = [device for device in result.devices if not client_view or device.is_active]
    for device in report_devices:
        name = client_display_name(device)
        if client_view:
            assets.append(f"<tr><td>{_e(device.ip)}</td><td>{_e(name)}</td><td>{_e(client_device_type(device))}</td></tr>")
        else:
            services = ", ".join(f"TCP/{port} {device.services.get(port, 'serviço provável')}" for port in device.open_ports) or "Sem portas da lista respondendo"
            mac = f"{device.mac_address} · {device.mac_vendor}"
            methods = ", ".join(device.discovered_by) or "Não identificado"
            assets.append(f"<tr><td>{_e(device.ip)}</td><td>{_e(name)}</td><td>{_e(device.device_type)} ({device.device_type_confidence:.0%})</td><td>{_e(device.hostname)}</td><td>{_e(device.operating_system)}</td><td>{_e(mac)}</td><td>{_e(services)}</td><td>{_e(methods)}</td><td>{_e(device.presence_status)}</td></tr>")

    findings = sorted(_all_findings(result, profile), key=lambda pair: SEVERITY_ORDER.get(pair[1].severity, 99))
    severity_counts = {severity: sum(finding.severity == severity for _, finding in findings)
                       for severity in SEVERITY_ORDER}
    severity_summary = " · ".join(f"{_e(severity)}: {count}" for severity, count in severity_counts.items() if count) or "Nenhum achado classificado"
    affected_assets = sorted({target for target, _ in findings if target != "Notebook auditor"})
    finding_rows = []
    for target, finding in findings:
        if client_view:
            title = CLIENT_TITLES.get(finding.title, finding.title)
            priority = CLIENT_SEVERITIES.get(finding.severity, finding.severity)
            finding_rows.append(f"<tr><td>{_e(priority)}</td><td>{_e(target)}</td><td>{_e(title)}</td><td>{_e(finding.recommendation)}</td></tr>")
        elif profile == "developer":
            context = json.dumps(finding.context, ensure_ascii=False, sort_keys=True)
            rule_label = f"{finding.rule_id or 'Regra não identificada'} · {finding.title}"
            rationale_parts = []
            if finding.justification:
                rationale_parts.append(f"Regra: {finding.justification}")
            if finding.risk_justification:
                rationale_parts.append(f"Risco: {finding.risk_justification}")
            rationale = f"<br><small>{_e(' '.join(rationale_parts))}</small>" if rationale_parts else ""
            finding_rows.append(f"<tr><td>{_e(finding.severity)}</td><td>{finding.risk_score if finding.risk_score is not None else '—'}/100</td><td>{_e(target)}</td><td>{_e(finding.category)}</td><td>{_e(rule_label)}{rationale}</td><td>{finding.confidence:.0%}</td><td>{_e(finding.evidence)}</td><td>{_e(finding.recommendation)}</td><td>{_e(context)}</td></tr>")
        else:
            rationale_values = [value for value in (finding.justification, finding.risk_justification) if value]
            rationale = f" Justificativa: {' '.join(rationale_values)}" if rationale_values else ""
            finding_rows.append(f"<tr><td>{_e(finding.severity)}</td><td>{finding.risk_score if finding.risk_score is not None else '—'}/100</td><td>{_e(target)}</td><td>{_e(finding.title)}</td><td>{_e(finding.evidence + rationale)}</td><td>{_e(finding.recommendation)}</td></tr>")

    evidence_rows = []
    if not client_view:
        for target, evidence in _evidence_rows(result, profile):
            if profile == "developer":
                details = json.dumps(evidence.technical_details, ensure_ascii=False, sort_keys=True)
                evidence_rows.append(f"<tr><td>{_e(target)}</td><td>{_e(evidence.host_ip or 'não atribuído')}</td><td>{_e(evidence.kind)}</td><td>{_e(evidence.value)}</td><td>{_e(evidence.source)}</td><td>{evidence.confidence:.0%}</td><td>{_e(evidence.observed_at)}</td><td>{_e(details)}</td></tr>")
            else:
                evidence_rows.append(f"<tr><td>{_e(target)}</td><td>{_e(evidence.kind)}</td><td>{_e(evidence.value)}</td><td>{_e(evidence.source)}</td><td>{evidence.confidence:.0%}</td></tr>")

    generated = datetime.now().astimezone().strftime("%d/%m/%Y %H:%M:%S %Z")
    if client_view:
        asset_header = "<th>Endereço</th><th>Dispositivo</th><th>Tipo de equipamento</th>"
        findings_header = "<th>Prioridade</th><th>Ativo</th><th>Resultado</th><th>Recomendação</th>"
        colspan = 4
        caveat = "O tipo de equipamento é estimado. Somente dispositivos confirmados por resposta ativa são incluídos no resumo."
        evidence_section = ""
        summary_stats = f"Equipamentos encontrados: <strong>{len(report_devices)}</strong> · Pontos para revisão: <strong>{len(findings)}</strong>"
        summary_heading = "Visão geral"
    else:
        summary_stats = f"Endereços verificados: <strong>{result.addresses_scanned}</strong> · Dispositivos observados: <strong>{len(result.devices)}</strong> · Ativos afetados: <strong>{len(affected_assets)}</strong> · Achados neste perfil: <strong>{len(findings)}</strong>"
        summary_heading = "Resumo"
        asset_header = "<th>IP</th><th>Nome</th><th>Tipo provável</th><th>Hostname</th><th>SO estimado</th><th>MAC · fabricante</th><th>Serviços TCP</th><th>Métodos de descoberta</th><th>Presença</th>"
        if profile == "developer":
            findings_header = "<th>Severidade</th><th>Score</th><th>Ativo</th><th>Categoria</th><th>Regra</th><th>Confiança</th><th>Evidência</th><th>Recomendação</th><th>Contexto do risco</th>"
            evidence_header = "<th>Ativo</th><th>IP de origem</th><th>Tipo</th><th>Valor</th><th>Origem</th><th>Confiança</th><th>Data observada</th><th>Detalhes técnicos</th>"
            evidence_section = f"<h2>Evidências completas</h2><table><thead><tr>{evidence_header}</tr></thead><tbody>{''.join(evidence_rows) or '<tr><td colspan=\"8\">Sem evidências.</td></tr>'}</tbody></table>"
            colspan = 9
        else:
            findings_header = "<th>Severidade</th><th>Score</th><th>Ativo</th><th>Resultado</th><th>Evidência</th><th>Recomendação</th>"
            evidence_header = "<th>Ativo</th><th>Tipo</th><th>Valor observado</th><th>Origem</th><th>Confiança</th>"
            evidence_section = f"<h2>Evidências</h2><table><thead><tr>{evidence_header}</tr></thead><tbody>{''.join(evidence_rows) or '<tr><td colspan=\"5\">Sem evidências.</td></tr>'}</tbody></table>"
            colspan = 6
        caveat = "Porta acessível é observação de exposição, não confirmação automática de vulnerabilidade. Pontuação e severidade são heurísticas do Berga Sentinel; não equivalem a CVSS."

    details = ""
    if profile == "developer":
        method_counts = ", ".join(f"{_e(name)}: {count}" for name, count in result.discovery_method_counts.items()) or "não disponível"
        active_count = sum(device.is_active for device in result.devices)
        details = (f"<p>ID da auditoria: {_e(result.audit_id)} · Hosts ativos: {active_count} · "
                   f"Entradas ARP não confirmadas: {len(result.devices) - active_count} · Interface: {_e(result.interface_name or 'não identificada')} · "
                   f"IPv4: {_e(result.local_ipv4 or 'não identificado')}/{result.prefix_length if result.prefix_length is not None else '?'} · "
                   f"Gateway: {_e(result.gateway or 'não identificado')} · Endereços sondados: {result.addresses_scanned} · "
                   f"Descobertas por método: {method_counts} · Catálogo TCP: {_e(', '.join(map(str, sorted(COMMON_PORTS))))}</p>")
        if result.discovery_errors:
            details += "<p>Erros de descoberta: " + _e("; ".join(result.discovery_errors)) + "</p>"
        if result.discovery_timeout_counts:
            details += "<p>Timeouts: " + _e(", ".join(f"{name}: {count}" for name, count in result.discovery_timeout_counts.items())) + "</p>"
    notes = result.notes if not client_view else [
        "A verificação é somente de leitura e não altera os dispositivos.",
        "Equipamentos que não responderam podem não aparecer neste resumo.",
        "Os pontos identificados são recomendações para revisão pelo responsável técnico.",
    ]
    executive = (f"<p>Achados por severidade: {severity_summary}</p>"
                 f"<p>Máquinas afetadas: {_e(', '.join(affected_assets) or 'Nenhuma')}</p>")
    document = f'''<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>{_e(PROFILE_TITLES[profile])} · Berga CyberSec</title>
<style>body{{font:14px/1.5 Arial,sans-serif;color:#152334;margin:30px auto;max-width:1400px;padding:0 20px}}header{{background:#10243a;color:white;padding:26px;border-radius:10px}}h1{{margin:4px 0}}h2{{margin-top:28px;border-bottom:2px solid #16a085;padding-bottom:6px}}table{{border-collapse:collapse;width:100%;margin:12px 0 24px}}th,td{{border:1px solid #d7dee5;padding:8px;text-align:left;vertical-align:top}}th{{background:#eef3f7}}.muted{{color:#536779}}.badge{{font-weight:bold}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f5f8;padding:12px;font-size:11px}}@media print{{body{{margin:0;max-width:none}}header{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}tr{{break-inside:avoid}}}}</style></head><body>
<header><div>BERGA CYBERSEC · AUDITORIA AUTORIZADA</div><h1>{_e(PROFILE_TITLES[profile])}</h1><p>Auditoria: {_e(result.audit_id)} · Escopo: {_e(result.scope)}</p><p>Início: {_e(result.started_at)} · Conclusão: {_e(result.completed_at or 'Em andamento')} · Gerado: {_e(generated)}</p></header>
<h2>{summary_heading}</h2><p>{summary_stats}</p>{executive}{details}<p class="muted">{_e(caveat)}</p>
<h2>Inventário de ativos</h2><table><thead><tr>{asset_header}</tr></thead><tbody>{''.join(assets) or f'<tr><td colspan="{3 if client_view else 9}">Nenhum dispositivo foi identificado pelos métodos de descoberta configurados.</td></tr>'}</tbody></table>
{evidence_section}<h2>Achados e recomendações</h2><table><thead><tr>{findings_header}</tr></thead><tbody>{''.join(finding_rows) or f'<tr><td colspan="{colspan}">Nenhum achado foi classificado.</td></tr>'}</tbody></table>
<h2>Limitações</h2><ul>{''.join(f'<li>{_e(note)}</li>' for note in notes)}</ul><p class="muted">Documento confidencial · Berga CyberSec · Somente leitura</p></body></html>'''
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
    return path

def write_pdf(result: AuditResult, path: Path, profile: str = "analyst") -> Path:
    """Gera PDF adequado ao nível solicitado."""
    if profile not in PROFILE_TITLES:
        raise ValueError(f"Perfil de relatório desconhecido: {profile}")
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(path), pagesize=landscape(A4), rightMargin=14*mm, leftMargin=14*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7.1, leading=8.5, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="Brand", parent=styles["Title"], textColor=colors.HexColor("#10243a")))
    cell = styles["SmallCell"]
    client_view = profile == "client"
    findings = sorted(_all_findings(result, profile), key=lambda pair: SEVERITY_ORDER.get(pair[1].severity, 99))
    active_count = sum(device.is_active for device in result.devices)
    asset_summary = (f"Hosts ativos confirmados: {active_count}" if client_view else
                     f"Hosts ativos confirmados: {active_count} · Entradas não confirmadas: {len(result.devices) - active_count}")
    affected_summary = ", ".join(sorted({target for target, _ in findings
                                           if target != "Notebook auditor"})) or "Nenhum"
    story = [Paragraph(f"BERGA CYBERSEC · {_e(PROFILE_TITLES[profile]).upper()}", styles["Brand"]),
             Paragraph(f"ID da auditoria: {_e(result.audit_id)}", styles["BodyText"]),
             Paragraph(f"Escopo: {_e(result.scope)}", styles["Heading2"]),
             Paragraph(f"Início: {_e(result.started_at)} · Conclusão: {_e(result.completed_at or 'Em andamento')} · "
                       f"Gerado: {_e(datetime.now().astimezone().isoformat(timespec='seconds'))}", styles["BodyText"]),
             Spacer(1, 6), Paragraph(f"Endereços verificados: {result.addresses_scanned} · {asset_summary} · Achados: {len(findings)}", styles["BodyText"]),
             Paragraph("Achados por severidade: " + _e(", ".join(
                 f"{severity}: {sum(f.severity == severity for _, f in findings)}"
                 for severity in SEVERITY_ORDER
                 if any(f.severity == severity for _, f in findings)
             ) or "Nenhum achado classificado"), styles["BodyText"]),
             Paragraph("Ativos afetados: " + _e(affected_summary), styles["BodyText"]),
             Spacer(1, 8), Paragraph("Inventário de ativos", styles["Heading2"])]
    if client_view:
        headers = ["Endereço", "Dispositivo", "Tipo de equipamento"]
        asset_widths = [40, 110, 98]
        rows = [[device.ip, client_display_name(device), client_device_type(device)] for device in result.devices if device.is_active]
    else:
        headers = ["IP", "Nome", "Tipo", "Hostname", "MAC / fabricante", "SO estimado", "Serviços TCP"]
        asset_widths = [19, 35, 34, 34, 45, 31, 67]
        rows = [[device.ip, client_display_name(device), f"{device.device_type} ({device.device_type_confidence:.0%})", device.hostname,
                 f"{device.mac_address} / {device.mac_vendor}", device.operating_system,
                 ", ".join(f"{port}/{device.services.get(port, 'TCP')}" for port in device.open_ports) or "—"] for device in result.devices]
    assets = [[Paragraph(_e(value), cell) for value in row] for row in [headers] + rows]
    asset_table = Table(assets, colWidths=[width*mm for width in asset_widths], repeatRows=1)
    asset_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#10243a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#b8c4ce")),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f1f5f8")]),("PADDING",(0,0),(-1,-1),4)]))
    story.extend([asset_table, Spacer(1, 12), Paragraph("Achados e recomendações", styles["Heading2"])])
    if client_view:
        headers = ["Prioridade", "Dispositivo", "O que encontramos", "O que recomendamos"]
        widths = [28, 48, 75, 105]
        finding_rows = [[CLIENT_SEVERITIES.get(finding.severity, finding.severity), target,
                         CLIENT_TITLES.get(finding.title, finding.title), finding.recommendation]
                        for target, finding in findings]
    else:
        headers = ["Severidade", "Risco", "Ativo", "Evidência observada", "Recomendação"]
        widths = [25, 20, 42, 82, 87]
        finding_rows = [[finding.severity, f"{finding.risk_score or 0}/100", target,
                         f"Regra: {finding.rule_id or 'não identificada'}. {finding.title}. {finding.evidence}. "
                         f"Justificativa: {finding.justification} {finding.risk_justification}",
                         finding.recommendation] for target, finding in findings]
    if not finding_rows:
        finding_rows = [["—", "—", "Nenhum achado classificado.", "—"]] if client_view else [["—", "—", "—", "Nenhum achado classificado.", "—"]]
    table_data = [[Paragraph(_e(value), cell) for value in row] for row in [headers] + finding_rows]
    finding_table = Table(table_data, colWidths=[width*mm for width in widths], repeatRows=1)
    finding_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#10243a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#b8c4ce")),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f1f5f8")]),("PADDING",(0,0),(-1,-1),4)]))
    story.append(finding_table)
    if not client_view:
        story.append(Spacer(1, 12))
        story.append(Paragraph("Evidências", styles["Heading2"]))
        evidence_rows = [["Ativo", "Tipo", "Valor", "Origem", "Confiança"]]
        for target, evidence in _evidence_rows(result, profile):
            evidence_rows.append([target, evidence.kind, evidence.value, evidence.source, f"{evidence.confidence:.0%}"])
        if len(evidence_rows) == 1:
            evidence_rows.append(["—", "—", "Sem evidências.", "—", "—"])
        evidence_table = Table([[Paragraph(_e(value), cell) for value in row] for row in evidence_rows],
                               colWidths=[38*mm, 42*mm, 105*mm, 55*mm, 28*mm], repeatRows=1)
        evidence_table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#10243a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#b8c4ce")),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f1f5f8")]),("PADDING",(0,0),(-1,-1),4)]))
        story.append(evidence_table)
    story.extend([Spacer(1, 10), Paragraph("Limitações", styles["Heading2"])])
    notes = result.notes if not client_view else [
        "A verificação não altera os equipamentos.",
        "Equipamentos que não responderam podem não aparecer no inventário.",
        "As recomendações devem ser revisadas pelo responsável técnico antes de qualquer mudança.",
    ]
    story.extend(Paragraph("• " + _e(note), cell) for note in notes)
    doc.build(story)
    return path

def write_inventory_csv(result: AuditResult, path: Path, profile: str = "developer") -> Path:
    """Exporta o inventário com colunas adequadas ao público e protege contra CSV injection."""
    path.parent.mkdir(parents=True, exist_ok=True)
    def safe_cell(value) -> str:
        text = str(value)
        first_value = text.lstrip(" \t\r\n")
        return "'" + text if first_value.startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")) else text
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream, delimiter=";")
        if profile == "client":
            writer.writerow(["Endereço", "Dispositivo", "Tipo de equipamento"])
            for device in result.devices:
                if not device.is_active:
                    continue
                writer.writerow([safe_cell(device.ip), safe_cell(client_display_name(device)), safe_cell(client_device_type(device))])
        else:
            writer.writerow(["IP", "Hostname / identificação", "Hostname", "Tipo provável", "Confiança do tipo", "Sistema operacional estimado", "MAC", "Fabricante da interface", "Métodos de descoberta", "Presença", "Serviços TCP", "Coletado em", "Procedência por campo", "Achados"])
            for device in result.devices:
                ports = ", ".join(f"{port}/{device.services.get(port, 'TCP')}" for port in device.open_ports)
                findings_text = "; ".join(item.title for item in device.findings)
                writer.writerow([safe_cell(device.ip), safe_cell(client_display_name(device)), safe_cell(device.hostname), safe_cell(device.device_type),
                    f"{device.device_type_confidence:.0%}", safe_cell(device.operating_system), safe_cell(device.mac_address), safe_cell(device.mac_vendor),
                    safe_cell(", ".join(device.discovered_by)), safe_cell(device.presence_status), safe_cell(ports),
                    safe_cell(device.collected_at), safe_cell(json.dumps(device.attribute_provenance, ensure_ascii=False, sort_keys=True)),
                    safe_cell(findings_text)])
    return path

def write_audit_json(result: AuditResult, path: Path) -> Path:
    """Write a UTF-8 JSON snapshot suitable for local audit history."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return path
