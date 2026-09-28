"""Shared, non-technical wording used by client-facing exports."""

CLIENT_TITLES: dict[str, str] = {
    "Protocolo Telnet confirmado e acessível": "Acesso remoto usa Telnet, sem criptografia",
    "Servidor SMBv1 aceitou negociação": "Compartilhamento aceita um protocolo antigo",
    "Firewall do Windows desabilitado em perfis": "Firewall do Windows está desativado em um ou mais perfis",
    "Microsoft Defender não reporta antivírus ativo": "Proteção antivírus do Microsoft Defender não está ativa",
    "Atualizações de software pendentes detectadas": "Há atualizações de software disponíveis",
    "UAC desabilitado": "Controle de Conta de Usuário (UAC) está desativado",
    "Coleta remota Windows não concluída": "Não foi possível verificar este computador Windows",
    "Não foi possível verificar uma configuração Windows": "Uma verificação do Windows não pôde ser concluída",
}

CLIENT_SEVERITIES: dict[str, str] = {
    "Crítica": "Urgente",
    "Alta": "Alta",
    "Média": "Moderada",
    "Baixa": "Baixa",
    "Informativa": "Informativo",
}


def client_finding_title(title: str) -> str:
    """Translate known technical rule titles into clear client wording."""
    return CLIENT_TITLES.get(title, title)


def client_severity(severity: str) -> str:
    """Return the simplified priority label for client reports."""
    return CLIENT_SEVERITIES.get(severity, severity)
