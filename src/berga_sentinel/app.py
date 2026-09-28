"""Inicialização da interface e infraestrutura de logs."""

import logging
from pathlib import Path
import tkinter as tk
from tkinter import messagebox

from .config import load_config
from .ui import AuditUI

def main():
    output_dir = Path.cwd() / "output"
    try:
        config = load_config(Path.cwd() / "berga-sentinel.toml")
    except (OSError, ValueError, RuntimeError) as exc:
        messagebox.showerror("Configuração inválida", str(exc))
        return
    logging.basicConfig(level=getattr(logging, config.log_level),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger(__name__).info("Berga Sentinel iniciado; artefatos serão organizados por auditoria em %s", output_dir)
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        logging.getLogger(__name__).exception("Não foi possível iniciar a interface gráfica")
        messagebox.showerror("Berga Sentinel", f"Não foi possível abrir a interface gráfica: {exc}")
        return
    AuditUI(root, output_dir, config)
    root.mainloop()
