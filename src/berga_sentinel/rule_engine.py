"""Small registry-based rule engine; collectors and risk scoring stay independent."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from .models import AuditResult, Device, Evidence, Finding

RuleEvaluator = Callable[[AuditResult, Device | None, Evidence], Iterable[Finding]]


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    evidence_kind: str
    evaluator: RuleEvaluator


class RuleRegistry:
    """Dispatch evidence to registered rules without coupling the risk engine."""

    def __init__(self) -> None:
        self._by_kind: dict[str, list[RuleDefinition]] = {}
        self._ids: set[str] = set()

    def register(self, rule_id: str, evidence_kind: str, evaluator: RuleEvaluator) -> None:
        """Register an evaluator for one kind or a supported wildcard kind."""
        if not rule_id.strip() or not evidence_kind.strip() or not callable(evaluator):
            raise ValueError("Uma regra exige ID, tipo de evidência e avaliador válidos.")
        if rule_id in self._ids:
            raise ValueError(f"ID de regra duplicado: {rule_id}")
        definition = RuleDefinition(rule_id, evidence_kind, evaluator)
        self._by_kind.setdefault(evidence_kind, []).append(definition)
        self._ids.add(rule_id)

    def evaluate(self, result: AuditResult, enabled_rule_ids: tuple[str, ...] = ()) -> None:
        """Evaluate collected evidence and append findings to the associated host."""
        by_ip = {device.ip: device for device in result.devices}
        sources: list[tuple[Device | None, Evidence]] = [
            (by_ip.get(item.host_ip), item) for item in result.evidence
        ]
        sources.extend((device, item) for device in result.devices for item in device.evidence)
        allowlist = set(enabled_rule_ids)
        for device, evidence in sources:
            definitions = list(self._by_kind.get(evidence.kind, ()))
            if evidence.kind.startswith("windows.") and evidence.kind.endswith(".error"):
                definitions.extend(self._by_kind.get("windows.*.error", ()))
            for rule in definitions:
                if allowlist and rule.rule_id not in allowlist:
                    continue
                findings = list(rule.evaluator(result, device, evidence))
                for finding in findings:
                    finding.rule_id = finding.rule_id or rule.rule_id
                    (device.findings if device else result.findings).append(finding)
