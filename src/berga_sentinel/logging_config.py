"""Configuração central de logs para execução e evidências operacionais."""

import logging
from pathlib import Path

def configure_logging(output_dir: Path, audit_id: str | None = None) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    logfile = output_dir / (f"auditoria-{audit_id}-tecnico.log" if audit_id else "berga-sentinel.log")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in root.handlers[:]:
        root.removeHandler(handler)
        handler.close()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)
    return logfile
