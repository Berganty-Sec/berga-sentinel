"""Configuração central de logs para execução e evidências operacionais."""

import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler

def configure_logging(output_dir: Path, audit_id: str | None = None,
                      level: str = "INFO") -> Path:
    """Configure bounded technical logs for one audit run."""
    normalized_level = level.upper()
    if normalized_level not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
        raise ValueError("Nível de log inválido.")
    output_dir.mkdir(parents=True, exist_ok=True)
    logfile = output_dir / (f"auditoria-{audit_id}-tecnico.log" if audit_id else "berga-sentinel.log")
    root = logging.getLogger()
    root.setLevel(getattr(logging, normalized_level))
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = RotatingFileHandler(logfile, maxBytes=5 * 1024 * 1024,
                                       backupCount=3, encoding="utf-8")
    file_handler.setLevel(getattr(logging, normalized_level))
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(getattr(logging, normalized_level))
    stream_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)
    return logfile
