"""Private, bounded local storage for completed audit snapshots."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import tempfile
from typing import Any

from .models import AuditResult, Device, Evidence, Finding
from .output_layout import validate_audit_id

LOG = logging.getLogger(__name__)
MAX_HISTORY_FILE_BYTES = 25 * 1024 * 1024
MAX_HISTORY_RECORDS = 500


def audit_from_dict(payload: dict[str, Any]) -> AuditResult:
    """Rebuild the typed audit graph while ignoring unknown future fields."""
    evidence_fields = Evidence.__dataclass_fields__
    finding_fields = Finding.__dataclass_fields__
    device_fields = Device.__dataclass_fields__
    audit_fields = AuditResult.__dataclass_fields__

    def evidence_from(item: dict[str, Any]) -> Evidence:
        return Evidence(**{key: value for key, value in item.items() if key in evidence_fields})

    def finding_from(item: dict[str, Any]) -> Finding:
        return Finding(**{key: value for key, value in item.items() if key in finding_fields})

    devices: list[Device] = []
    for raw_device in payload.get("devices", []):
        if not isinstance(raw_device, dict):
            continue
        item = {key: value for key, value in raw_device.items() if key in device_fields}
        item["evidence"] = [evidence_from(value) for value in raw_device.get("evidence", [])
                            if isinstance(value, dict)]
        item["findings"] = [finding_from(value) for value in raw_device.get("findings", [])
                            if isinstance(value, dict)]
        devices.append(Device(**item))
    result_data = {key: value for key, value in payload.items() if key in audit_fields}
    result_data["devices"] = devices
    result_data["evidence"] = [evidence_from(value) for value in payload.get("evidence", [])
                               if isinstance(value, dict)]
    result_data["findings"] = [finding_from(value) for value in payload.get("findings", [])
                               if isinstance(value, dict)]
    return AuditResult(**result_data)


class AuditHistory:
    """Store and retrieve local audit snapshots without executing any checks."""

    def __init__(self, directory: Path, max_records: int = MAX_HISTORY_RECORDS) -> None:
        if isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1:
            raise ValueError("max_records deve ser um inteiro positivo.")
        requested_directory = directory.expanduser().absolute()
        if requested_directory.is_symlink():
            raise ValueError("A pasta de histórico não pode ser um link simbólico.")
        self.directory = requested_directory.resolve()
        self.max_records = min(max_records, MAX_HISTORY_RECORDS)

    def _path(self, audit_id: str) -> Path:
        name = validate_audit_id(audit_id)
        path = (self.directory / f"{name}.json").resolve()
        if path.parent != self.directory:
            raise ValueError("O snapshot precisa permanecer dentro da pasta de histórico.")
        return path

    def save(self, result: AuditResult) -> Path:
        """Atomically persist an audit snapshot with owner-only POSIX permissions."""
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = self._path(result.audit_id)
        content = json.dumps(result.to_dict(), ensure_ascii=False, indent=2).encode("utf-8")
        if len(content) > MAX_HISTORY_FILE_BYTES:
            raise ValueError("O snapshot excede o tamanho máximo permitido para o histórico.")
        temp_name = ""
        try:
            with tempfile.NamedTemporaryFile(prefix=".sentinel-", suffix=".tmp", dir=self.directory,
                                             delete=False) as stream:
                temp_name = stream.name
                try:
                    os.chmod(temp_name, 0o600)
                except OSError:
                    LOG.debug("O sistema não permite ajustar as permissões POSIX do snapshot")
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, target)
            try:
                os.chmod(target, 0o600)
            except OSError:
                LOG.debug("O sistema não permite ajustar as permissões POSIX do histórico")
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)
        self._prune()
        return target

    def load(self, audit_id: str) -> AuditResult:
        """Load one validated snapshot and reject oversized or malformed input."""
        path = self._path(audit_id)
        size = path.stat().st_size
        if size > MAX_HISTORY_FILE_BYTES:
            raise ValueError("O arquivo do histórico excede o tamanho máximo permitido.")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Formato inválido para snapshot de auditoria.")
        return audit_from_dict(payload)

    def list_results(self) -> list[AuditResult]:
        """Return valid snapshots newest first; log corrupt records and continue."""
        if not self.directory.exists():
            return []
        paths = sorted(self.directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        results: list[AuditResult] = []
        for path in paths[:self.max_records]:
            try:
                results.append(self.load(path.stem))
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                LOG.warning("Snapshot inválido ignorado no histórico: %s", path.name)
        return results

    def latest(self, exclude_audit_id: str = "", scope: str = "") -> AuditResult | None:
        """Return the newest matching snapshot, optionally restricted to one scope."""
        for result in self.list_results():
            if result.audit_id != exclude_audit_id and (not scope or result.scope == scope):
                return result
        return None

    def _prune(self) -> None:
        paths = sorted(self.directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for stale in paths[self.max_records:]:
            try:
                # Only validated direct children matching the expected file suffix are removed.
                try:
                    validate_audit_id(stale.stem)
                except ValueError:
                    continue
                if stale.resolve().parent == self.directory:
                    stale.unlink()
            except OSError:
                LOG.warning("Não foi possível remover snapshot antigo do histórico: %s", stale.name)
