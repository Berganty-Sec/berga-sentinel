"""Lookup offline de fabricante via base OUI local opcional (sem enviar MACs)."""

import csv
import logging
import os
import re
from functools import lru_cache
from pathlib import Path

LOG = logging.getLogger(__name__)
DEFAULT_OUI_PATH = Path(__file__).with_name("data") / "oui.csv"

def _prefix(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value).upper()

@lru_cache(maxsize=4)
def _load_oui(path_text: str, mtime: float) -> dict[str, str]:
    del mtime  # mtime participa da chave do cache para recarregar após atualização da base.
    path = Path(path_text)
    entries: dict[str, str] = {}
    try:
        with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as stream:
            reader = csv.DictReader(stream)
            for row in reader:
                assignment = _prefix(row.get("Assignment", row.get("Prefix", "")))
                organization = (row.get("Organization Name") or row.get("Organization") or row.get("Vendor") or "").strip()
                if len(assignment) in (6, 7, 9) and organization:
                    entries[assignment] = organization
    except OSError as exc:
        LOG.info("Base OUI local não encontrada em %s: %s", path, exc)
    return entries

def lookup_vendor(mac_address: str, database: Path | None = None) -> str:
    compact_mac = _prefix(mac_address)
    if len(compact_mac) != 12:
        return "MAC inválido ou não identificado"
    if int(compact_mac[:2], 16) & 0x02:
        return "MAC local/aleatório; fabricante não pode ser inferido por OUI"
    source = database or Path(os.environ.get("BERGA_OUI_DATABASE", DEFAULT_OUI_PATH))
    try:
        prefixes = _load_oui(str(source.resolve()), source.stat().st_mtime)
    except OSError:
        return "Fabricante não disponível (base OUI local ausente)"
    for prefix_length in (9, 7, 6):
        organization = prefixes.get(compact_mac[:prefix_length])
        if organization:
            return organization
    return "Fabricante não identificado na base OUI local"
