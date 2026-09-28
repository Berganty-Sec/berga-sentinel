"""Classificação prudente de tipo de ativo a partir de evidências coletadas."""

from .models import Device
from .service_catalog import LIKELY_PRINTER_PORTS, WINDOWS_PORTS

MOBILE_VENDOR_HINTS = ("samsung", "xiaomi", "google", "motorola", "oneplus", "oppo", "vivo", "huawei", "hon hai")
PRINTER_VENDOR_HINTS = ("hewlett", "hp inc", "brother", "canon", "epson", "lexmark", "xerox", "ricoh", "kyocera", "konica")

def classify_device(device: Device) -> None:
    """Preenche tipo estimado e confiança sem substituir hostname ou MAC observado."""
    vendor = device.mac_vendor.lower()
    hostname = device.hostname.lower()
    evidence_text = " ".join(item.value.lower() for item in device.evidence)
    ports = set(device.open_ports)
    if (ports.intersection(LIKELY_PRINTER_PORTS)
            or any(word in vendor for word in PRINTER_VENDOR_HINTS)
            or any(word in evidence_text for word in PRINTER_VENDOR_HINTS)):
        device.device_type = "Impressora de rede provável"
        device.device_type_confidence = 0.85 if ports.intersection(LIKELY_PRINTER_PORTS) else 0.65
        if any(word in vendor for word in PRINTER_VENDOR_HINTS):
            device.device_type_confidence = 0.95
    elif "android" in hostname or (any(word in vendor for word in MOBILE_VENDOR_HINTS) and not ports.intersection(WINDOWS_PORTS)):
        device.device_type = "Android provável"
        device.device_type_confidence = 0.9 if "android" in hostname else 0.65
    elif "windows" in device.operating_system.lower() or ports.intersection(WINDOWS_PORTS):
        device.device_type = "Windows provável"
        device.device_type_confidence = 0.9 if "windows" in device.operating_system.lower() else 0.72
    elif "linux" in device.operating_system.lower() or "unix" in device.operating_system.lower():
        device.device_type = "Linux/Unix provável"
        device.device_type_confidence = 0.75
    elif any(word in vendor for word in ("cisco", "ubiquiti", "mikrotik", "tp-link", "netgear", "juniper")):
        device.device_type = "Equipamento de rede provável"
        device.device_type_confidence = 0.7
    else:
        device.device_type = "Dispositivo de rede não classificado"
        device.device_type_confidence = 0.25

def client_display_name(device: Device) -> str:
    if device.is_local:
        return "LOCAL HOST"
    if device.hostname != "Não identificado":
        return device.hostname
    return f"{device.device_type} ({device.ip})"


def client_device_type(device: Device) -> str:
    """Traduz a classificação técnica provável para uma descrição curta ao cliente."""
    return {
        "Windows provável": "Computador Windows",
        "Android provável": "Celular ou tablet Android",
        "Impressora de rede provável": "Impressora de rede",
        "Linux/Unix provável": "Dispositivo Linux/Unix",
        "Equipamento de rede provável": "Equipamento de rede",
        "Dispositivo de rede não classificado": "Outro dispositivo de rede",
    }.get(device.device_type, device.device_type)
