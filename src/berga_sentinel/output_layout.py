"""Define uma única pasta para todos os artefatos de cada auditoria."""

from dataclasses import dataclass
from pathlib import Path
import re

AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")


def validate_audit_id(audit_id: str) -> str:
    """Validate an ID before using it in an output path or filename."""
    if not isinstance(audit_id, str) or not AUDIT_ID_RE.fullmatch(audit_id):
        raise ValueError("ID de auditoria inválido; use até 64 letras, números ou hífens.")
    return audit_id

@dataclass(frozen=True)
class AuditOutputLayout:
    directory: Path

    @classmethod
    def create(cls, root: Path, audit_id: str) -> "AuditOutputLayout":
        audit_id = validate_audit_id(audit_id)
        root = root.expanduser().resolve()
        directory = (root / audit_id).resolve()
        if directory.parent != root:
            raise ValueError("O diretório da auditoria precisa estar dentro da pasta de saídas.")
        directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        return cls(directory=directory)
