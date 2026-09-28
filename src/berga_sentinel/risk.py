"""Context-aware risk scoring kept separate from observations and rules."""

from __future__ import annotations

from .config import DEFAULT_CONFIG, SentinelConfig
from .models import AuditResult, Device, Finding

_BASE_SCORES = {
    "Crítica": 90,
    "Alta": 70,
    "Média": 50,
    "Baixa": 30,
    "Informativa": 10,
}


def severity_for_score(score: int, config: SentinelConfig = DEFAULT_CONFIG) -> str:
    """Map a bounded score to severity using configured descending thresholds."""
    critical, high, medium, low = config.rules.severity_thresholds
    if score >= critical:
        return "Crítica"
    if score >= high:
        return "Alta"
    if score >= medium:
        return "Média"
    if score >= low:
        return "Baixa"
    return "Informativa"


def _confidence(value: object) -> float:
    """Return a safe confidence value for externally sourced evidence."""
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return 0.0
    if numeric != numeric:  # NaN
        return 0.0
    return max(0.0, min(1.0, numeric))


def _score_finding(finding: Finding, device: Device | None, config: SentinelConfig) -> None:
    base_score = finding.base_risk_score
    if base_score is None:
        base_score = finding.risk_score
        if base_score is None:
            base_score = _BASE_SCORES.get(finding.severity, 10)
    try:
        base_score = max(0, min(100, int(base_score)))
    except (TypeError, ValueError):
        base_score = 10
    finding.base_risk_score = base_score

    context = dict(finding.context)
    modifier = 0
    reasons: list[str] = []
    if device is not None:
        context.setdefault("asset_type", device.device_type)
        context.setdefault("asset_criticality", device.criticality)
        context.setdefault("exposure", "Acessível a partir do notebook na rede auditada")
        if context.get("service_expected_for_role") is False:
            modifier += 8
            reasons.append("+8 por serviço não esperado para a função identificada do ativo")
        criticality = str(device.criticality).strip().lower()
        if criticality in ("crítica", "critica"):
            modifier += 15
            reasons.append("+15 por criticidade crítica do ativo")
        elif criticality == "alta":
            modifier += 10
            reasons.append("+10 por criticidade alta do ativo")
        elif criticality == "média":
            modifier += 5
            reasons.append("+5 por criticidade média do ativo")

    confidence = _confidence(finding.confidence)
    confidence_factor = 0.75 + (0.25 * confidence)
    adjusted = max(0, min(100, round((base_score + modifier) * confidence_factor)))
    context.update({
        "base_score": base_score,
        "evidence_confidence": round(confidence, 2),
        "confidence_factor": round(confidence_factor, 2),
        "context_modifier": modifier,
    })
    if reasons:
        context["context_adjustment"] = "; ".join(reasons)
    finding.context = context
    finding.confidence = confidence
    finding.risk_score = adjusted
    finding.severity = severity_for_score(adjusted, config)

    finding.risk_justification = (
        f"Pontuação: {base_score} base, {modifier:+d} de contexto, "
        f"confiança {confidence:.0%} (fator {confidence_factor:.2f}), resultado {adjusted}/100."
    )


def classify_risks(result: AuditResult, config: SentinelConfig = DEFAULT_CONFIG) -> None:
    """Score findings without changing the original evidence or rule conclusion."""
    for finding in result.findings:
        _score_finding(finding, None, config)
    for device in result.devices:
        for finding in device.findings:
            _score_finding(finding, device, config)
