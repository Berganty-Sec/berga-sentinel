"""Define uma única pasta para todos os artefatos de cada auditoria."""

from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class AuditOutputLayout:
    directory: Path

    @classmethod
    def create(cls, root: Path, audit_id: str) -> "AuditOutputLayout":
        directory = root / audit_id
        directory.mkdir(parents=True, exist_ok=True)
        return cls(directory=directory)
