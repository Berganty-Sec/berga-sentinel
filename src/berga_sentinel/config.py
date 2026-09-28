"""Validated, centralized runtime configuration for Berga Sentinel."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys
from typing import Any

from .service_catalog import COMMON_PORTS


@dataclass(frozen=True)
class ScanConfig:
    """Resource and scope limits used by network collection."""

    connect_timeout_seconds: float = 0.5
    icmp_timeout_seconds: float = 1.0
    dns_timeout_seconds: float = 1.0
    fingerprint_timeout_seconds: float = 1.2
    max_hosts: int = 256
    host_workers: int = 32
    tcp_workers: int = 192
    tcp_workers_per_host: int = 6
    icmp_workers: int = 32
    dns_workers: int = 32
    arp_workers: int = 64
    fingerprint_workers: int = 24
    ports: tuple[int, ...] = field(default_factory=lambda: tuple(COMMON_PORTS))

    def __post_init__(self) -> None:
        for name in (
            "connect_timeout_seconds", "icmp_timeout_seconds", "dns_timeout_seconds",
            "fingerprint_timeout_seconds", "max_hosts",
            "host_workers", "tcp_workers", "tcp_workers_per_host",
            "icmp_workers", "dns_workers", "arp_workers", "fingerprint_workers",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} deve ser um número positivo.")
        for name in ("max_hosts", "host_workers", "tcp_workers", "tcp_workers_per_host",
                     "icmp_workers", "dns_workers", "arp_workers", "fingerprint_workers"):
            if isinstance(getattr(self, name), bool) or not isinstance(getattr(self, name), int):
                raise ValueError(f"{name} deve ser um número inteiro.")
        if self.max_hosts > 65_536:
            raise ValueError("max_hosts não pode exceder 65536 endereços.")
        if any(getattr(self, name) > 30 for name in (
            "connect_timeout_seconds", "icmp_timeout_seconds", "dns_timeout_seconds",
            "fingerprint_timeout_seconds",
        )):
            raise ValueError("Timeouts não podem exceder 30 segundos.")
        if not isinstance(self.ports, (tuple, list)) or not self.ports:
            raise ValueError("ports deve ser uma lista de portas e não pode ser vazia.")
        if any(isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
               for port in self.ports):
            raise ValueError("Cada porta deve ser um inteiro entre 1 e 65535.")
        if len(set(self.ports)) != len(self.ports):
            raise ValueError("ports deve conter portas únicas.")


@dataclass(frozen=True)
class RuleConfig:
    """Risk score cutoffs and optional rule allowlist."""

    severity_thresholds: tuple[int, int, int, int] = (80, 60, 40, 20)
    enabled_rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if len(self.severity_thresholds) != 4:
            raise ValueError("severity_thresholds precisa ter quatro limites.")
        values = self.severity_thresholds
        if any(isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100
               for value in values) or tuple(sorted(values, reverse=True)) != values:
            raise ValueError("Limites de severidade devem ser inteiros decrescentes entre 0 e 100.")
        if not isinstance(self.enabled_rule_ids, (tuple, list)) or any(
            not isinstance(rule_id, str) or not rule_id.strip() for rule_id in self.enabled_rule_ids
        ):
            raise ValueError("enabled_rule_ids não pode conter valores vazios.")


@dataclass(frozen=True)
class ReportConfig:
    """Enabled export formats and profile names."""

    formats: tuple[str, ...] = ("html", "pdf", "json", "csv")
    profiles: tuple[str, ...] = ("developer", "analyst", "client")

    def __post_init__(self) -> None:
        if not isinstance(self.formats, (tuple, list)) or not self.formats or any(
            not isinstance(item, str) or item not in {"html", "pdf", "json", "csv"}
            for item in self.formats
        ):
            raise ValueError("formats aceita somente html, pdf, json e csv.")
        if not isinstance(self.profiles, (tuple, list)) or not self.profiles or any(
            not isinstance(item, str) or item not in {"developer", "analyst", "client"}
            for item in self.profiles
        ):
            raise ValueError("profiles aceita developer, analyst e client.")


@dataclass(frozen=True)
class SentinelConfig:
    """Application configuration loaded from trusted local TOML or defaults."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    rules: RuleConfig = field(default_factory=RuleConfig)
    reports: ReportConfig = field(default_factory=ReportConfig)
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        if not isinstance(self.log_level, str) or self.log_level.upper() not in {
            "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"
        }:
            raise ValueError("log_level não é um nível logging válido.")


DEFAULT_CONFIG = SentinelConfig()


def load_config(path: Path | None = None) -> SentinelConfig:
    """Load optional TOML configuration; unknown keys fail closed with a useful error."""
    if path is None or not path.exists():
        return DEFAULT_CONFIG
    try:
        if sys.version_info >= (3, 11):
            import tomllib
        else:  # pragma: no cover - exercised by supported Python 3.10 installations
            import tomli as tomllib  # type: ignore[no-redef, import-not-found]
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"Não foi possível ler a configuração {path}: {exc}") from exc
    except ImportError as exc:
        raise RuntimeError("Python 3.10 requer a dependência tomli para ler configuração TOML.") from exc

    if not isinstance(raw, dict) or set(raw) - {"scan", "rules", "reports", "logging"}:
        raise ValueError("Seções TOML aceitas: scan, rules, reports e logging.")
    scan_values = _section(raw, "scan", {
        "connect_timeout_seconds", "icmp_timeout_seconds", "dns_timeout_seconds",
        "fingerprint_timeout_seconds", "max_hosts", "host_workers",
        "tcp_workers", "tcp_workers_per_host", "icmp_workers", "dns_workers", "arp_workers",
        "fingerprint_workers", "ports",
    })
    rule_values = _section(raw, "rules", {"severity_thresholds", "enabled_rule_ids"})
    report_values = _section(raw, "reports", {"formats", "profiles"})
    logging_values = _section(raw, "logging", {"level"})
    for values, keys in ((scan_values, ("ports",)),
                         (rule_values, ("severity_thresholds", "enabled_rule_ids")),
                         (report_values, ("formats", "profiles"))):
        for key in keys:
            if key in values:
                raw_value = values[key]
                if not isinstance(raw_value, list):
                    raise ValueError(f"{key} deve ser uma lista TOML.")
                values[key] = tuple(raw_value)
    try:
        return SentinelConfig(
            scan=ScanConfig(**scan_values),
            rules=RuleConfig(**rule_values),
            reports=ReportConfig(**report_values),
            log_level=str(logging_values.get("level", "INFO")).upper(),
        )
    except (TypeError, AttributeError) as exc:
        raise ValueError(f"Configuração TOML com tipo inválido: {exc}") from exc


def _section(raw: dict[str, Any], name: str, allowed: set[str]) -> dict[str, Any]:
    value = raw.get(name, {})
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError(f"A seção [{name}] possui estrutura ou chaves não reconhecidas.")
    return dict(value)
