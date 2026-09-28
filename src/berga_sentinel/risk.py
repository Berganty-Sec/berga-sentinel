"""Classificação de risco independente da coleta e das regras de evidência."""

from .models import AuditResult

def severity_for_score(score: int) -> str:
    if score >= 80:
        return "Crítica"
    if score >= 60:
        return "Alta"
    if score >= 40:
        return "Média"
    if score >= 20:
        return "Baixa"
    return "Informativa"

def classify_risks(result: AuditResult) -> None:
    findings = [(finding, None) for finding in result.findings]
    for device in result.devices:
        findings.extend((finding, device) for finding in device.findings)
    for finding, device in findings:
        base_score = finding.risk_score
        if base_score is None:
            base_score = {
                "Crítica": 90, "Alta": 70, "Média": 50,
                "Baixa": 30, "Informativa": 10,
            }.get(finding.severity, 10)
        context = dict(finding.context)
        modifier = 0
        if device is not None:
            context.setdefault("asset_type", device.device_type)
            context.setdefault("asset_criticality", device.criticality)
            context.setdefault("exposure", "Acessível a partir do notebook na rede auditada")
            if context.get("service_expected_for_role") is False:
                modifier += 8
                context["context_adjustment"] = "+8: serviço administrativo inesperado para este tipo de ativo"
            if device.criticality.lower() in ("crítica", "critica"):
                modifier += 15
            elif device.criticality.lower() == "alta":
                modifier += 10
            elif device.criticality.lower() == "média":
                modifier += 5
        # Menor confiança reduz a pontuação, mas não apaga a evidência coletada.
        confidence_factor = 0.75 + (0.25 * max(0.0, min(1.0, finding.confidence)))
        adjusted = round((base_score + modifier) * confidence_factor)
        finding.risk_score = max(0, min(100, adjusted))
        context["base_score"] = base_score
        context["evidence_confidence"] = round(finding.confidence, 2)
        context["confidence_factor"] = round(confidence_factor, 2)
        context["context_modifier"] = modifier
        finding.context = context
        finding.severity = severity_for_score(finding.risk_score)
