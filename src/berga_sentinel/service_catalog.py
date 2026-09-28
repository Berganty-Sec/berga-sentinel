"""Catálogo de nomes prováveis associado às portas inspecionadas."""

COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 515: "LPD printer",
    554: "RTSP", 631: "IPP printer", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5555: "Possible Android ADB",
    5900: "VNC", 5985: "WinRM HTTP", 5986: "WinRM HTTPS",
    5357: "WSD (descoberta de dispositivos/impressoras)",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9100: "JetDirect printer",
}

HTTP_PORTS = {80, 631, 8000, 8080}
HTTPS_PORTS = {443, 8443}
LIKELY_PRINTER_PORTS = {515, 631, 9100}
WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}
