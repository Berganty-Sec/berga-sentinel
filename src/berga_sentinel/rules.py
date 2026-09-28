"""Built-in evidence rules; each plugin rule is independently registered."""

from __future__ import annotations

from .config import DEFAULT_CONFIG, SentinelConfig
from .models import AuditResult, Device, Evidence, Finding
from .rule_engine import RuleEvaluator, RuleRegistry

DEFAULT_RULES = RuleRegistry()


def _finding(title: str, recommendation: str, category: str, score: int,
             evidence: Evidence, justification: str, rule_id: str,
             context: dict[str, str | int | float | bool] | None = None) -> Finding:
    return Finding(
        title=title,
        severity="Informativa",
        evidence=evidence.value,
        recommendation=recommendation,
        category=category,
        risk_score=score,
        confidence=evidence.confidence,
        context=dict(context or {}),
        rule_id=rule_id,
        justification=justification,
    )


def _context(device: Device | None, **extra: str | int | float | bool) -> dict[str, str | int | float | bool]:
    values: dict[str, str | int | float | bool] = dict(extra)
    if device:
        values.update({"asset_type": device.device_type, "asset_criticality": device.criticality})
    return values


def _telnet(_result: AuditResult, device: Device | None, evidence: Evidence):
    yield _finding(
        "Protocolo Telnet confirmado e acessível",
        "Desative Telnet quando não for necessário; prefira administração por SSH ou canal protegido.",
        "Protocolo administrativo em texto claro", 62, evidence,
        "A resposta confirmou negociação Telnet; nenhuma autenticação foi tentada.",
        "protocol.telnet.cleartext",
        _context(device, exposure="Acessível a partir do notebook na rede auditada",
                 service_expected_for_role=False if device and device.device_type in (
                     "Impressora de rede provável", "Android provável") else "unknown"),
    )


def _smb1(_result: AuditResult, device: Device | None, evidence: Evidence):
    yield _finding(
        "Servidor SMBv1 aceitou negociação",
        "Confirme dependências legadas e desative SMBv1 conforme a política do cliente, usando mudança controlada.",
        "Protocolo legado confirmado", 72, evidence,
        "A negociação SMB sem autenticação foi aceita; nenhum login ou acesso a arquivo ocorreu.",
        "protocol.smb1.accepted",
        _context(device, exposure="Negociação SMB acessível na rede auditada"),
    )


def _legacy_tls(_result: AuditResult, device: Device | None, evidence: Evidence):
    yield _finding(
        f"Endpoint TLS aceita {evidence.value}",
        "Revise compatibilidade e desabilite versões TLS legadas onde não forem necessárias.",
        "Protocolo criptográfico legado", 58, evidence,
        "Handshake limitado à versão indicada foi concluído sem enviar credenciais.",
        "protocol.tls.legacy",
        _context(device, exposure="Handshake TLS acessível na rede auditada"),
    )


def _ftp_features(_result: AuditResult, device: Device | None, evidence: Evidence):
    response = evidence.value.lower()
    if "211 end" not in response or "auth tls" in response:
        return
    yield _finding(
        "Servidor FTP não anunciou AUTH TLS na resposta FEAT",
        "Confirme a política de criptografia do serviço; a resposta FEAT isolada não prova que TLS esteja indisponível.",
        "Configuração de serviço a validar", 34, evidence,
        "A resposta FTP FEAT completa não continha AUTH TLS; isso não confirma a configuração de todos os modos do servidor.",
        "service.ftp.tls_not_advertised",
        _context(device, exposure="Acessível a partir do notebook na rede auditada",
                 tls_support_advertised=False),
    )


WINDOWS_RULES: dict[str, tuple[str, int, str, str]] = {
    "windows.firewall.disabled_profiles": (
        "Firewall do Windows desabilitado em perfis", 55,
        "Revise as políticas do cliente e habilite os perfis de firewall que deveriam estar ativos.",
        "O coletor local reportou um ou mais perfis desabilitados.",
    ),
    "windows.defender.antivirus_enabled": (
        "Microsoft Defender não reporta antivírus ativo", 70,
        "Confirme qual antivírus está aprovado pela organização; um antivírus de terceiros pode explicar este estado.",
        "O estado recebido foi false; a presença de outro antivírus ainda precisa ser verificada.",
    ),
    "windows.updates.pending_count": (
        "Atualizações de software pendentes detectadas", 45,
        "Revise as atualizações disponíveis conforme a política de mudança do cliente.",
        "A coleta encontrou atualizações oferecidas pelo Windows Update Agent, sem inferir criticidade ou CVEs.",
    ),
    "windows.uac.enable_lua": (
        "UAC desabilitado", 65,
        "Revise a política local de UAC e mantenha-a habilitada conforme a política do cliente.",
        "O valor EnableLUA recebido foi false.",
    ),
}


def _windows_state(evidence_kind: str) -> RuleEvaluator:
    title, score, recommendation, justification = WINDOWS_RULES[evidence_kind]

    def evaluate(_result: AuditResult, device: Device | None, evidence: Evidence):
        value = evidence.value.strip().lower()
        if evidence_kind == "windows.firewall.disabled_profiles":
            valid, insecure = value.isdigit(), value.isdigit() and int(value) > 0
            observed = f"Perfis desabilitados: {evidence.value}"
        elif evidence_kind == "windows.updates.pending_count":
            valid, insecure = value.isdigit(), value.isdigit() and int(value) > 0
            observed = f"Atualizações pendentes: {evidence.value}"
        else:
            valid = value in {"true", "false", "1", "0"}
            insecure = value in {"false", "0"}
            observed = f"Valor observado: {evidence.value}"
        if not valid:
            yield _finding(
                "Estado de segurança Windows não pôde ser interpretado",
                "Confirme manualmente o estado do controle e revise o log técnico da coleta.",
                "Verificação Windows", 10, evidence,
                "O valor retornado não correspondeu ao formato esperado; nenhum estado inseguro foi presumido.",
                f"posture.windows.unreadable:{evidence_kind}",
                _context(device, collection_source=evidence.source),
            )
            return
        if not insecure:
            return
        yield _finding(
            title, recommendation, "Postura Windows", score, evidence, justification,
            f"posture.{evidence_kind.replace('.', '_')}",
            _context(device, collection_source=evidence.source, observed_value=observed),
        )
    return evaluate


def _windows_error(_result: AuditResult, device: Device | None, evidence: Evidence):
    yield _finding(
        "Não foi possível verificar uma configuração Windows",
        "Revise a disponibilidade da consulta e confirme o estado com o responsável técnico; falha de coleta não comprova configuração insegura.",
        "Verificação Windows", 10, evidence,
        "A consulta não retornou um estado utilizável; a condição de segurança permanece desconhecida.",
        f"posture.windows.collection_error:{evidence.kind.removesuffix('.error')}",
        _context(device, collection_source=evidence.source),
    )


def _windows_not_available(_result: AuditResult, device: Device | None, evidence: Evidence):
    yield _finding(
        "Verificações Windows locais não executadas",
        "Execute o auditor em um notebook Windows se estas verificações locais forem necessárias.",
        "Verificação Windows", 10, evidence,
        "O host que executa a auditoria não é Windows; nenhuma configuração de outros computadores foi inferida.",
        "posture.windows.local_checks_unavailable",
        _context(device, collection_source=evidence.source),
    )


for _kind, _evaluator in (
    ("service.telnet_protocol", _telnet),
    ("smb.smb1_supported", _smb1),
    ("tls.legacy_version", _legacy_tls),
    ("ftp.features", _ftp_features),
):
    DEFAULT_RULES.register(
        {"service.telnet_protocol": "protocol.telnet.cleartext",
         "smb.smb1_supported": "protocol.smb1.accepted",
         "tls.legacy_version": "protocol.tls.legacy",
         "ftp.features": "service.ftp.tls_not_advertised"}[_kind],
        _kind, _evaluator,
    )
for _kind in WINDOWS_RULES:
    DEFAULT_RULES.register(f"posture.{_kind.replace('.', '_')}", _kind, _windows_state(_kind))
DEFAULT_RULES.register("posture.windows.collection_error", "windows.*.error", _windows_error)
DEFAULT_RULES.register("posture.windows.local_checks_unavailable", "windows.not_available",
                       _windows_not_available)


def register_rule(rule_id: str, evidence_kind: str, evaluator: RuleEvaluator) -> None:
    """Register an additional evidence rule without editing the dispatcher."""
    DEFAULT_RULES.register(rule_id, evidence_kind, evaluator)


def evaluate_rules(result: AuditResult, config: SentinelConfig = DEFAULT_CONFIG,
                   registry: RuleRegistry | None = None) -> None:
    """Apply registered rules; conclusions remain separate from collected evidence."""
    (registry or DEFAULT_RULES).evaluate(result, config.rules.enabled_rule_ids)
