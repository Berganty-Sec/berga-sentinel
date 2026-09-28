"""Regras interpretam evidências; não fazem novas conexões de rede."""

from .models import AuditResult, Finding

def evaluate_rules(result: AuditResult) -> None:
    for device in result.devices:
        kinds = {item.kind for item in device.evidence}
        if "service.telnet_protocol" in kinds:
            device.findings.append(Finding(
                title="Protocolo Telnet confirmado e acessível",
                severity="Informativa",  # O Risk Engine define a severidade final.
                evidence=f"O host {device.ip} respondeu com negociação de opções Telnet, confirmando o protocolo sem autenticação.",
                recommendation="Desative Telnet quando não for necessário; prefira administração por SSH ou canal protegido.",
                category="Protocolo administrativo em texto claro",
                risk_score=62,
                confidence=0.95,
                context={"asset_type": device.device_type, "asset_criticality": device.criticality,
                         "exposure": "Acessível a partir do notebook na rede auditada", "protocol_confirmed": True,
                         "service_expected_for_role": False if device.device_type in ("Impressora de rede provável", "Android provável") else "unknown"},
            ))
        for evidence in device.evidence:
            if evidence.kind == "smb.smb1_supported":
                device.findings.append(Finding(
                    "Servidor SMBv1 aceitou negociação", "Informativa",
                    evidence.value + " Nenhuma autenticação ou operação de arquivo foi executada.",
                    "Confirme dependências legadas e desative SMBv1 conforme a política do cliente, usando mudança controlada.",
                    "Protocolo legado confirmado", risk_score=72, confidence=evidence.confidence,
                    context={"asset_type": device.device_type, "asset_criticality": device.criticality,
                             "exposure": "Negociação SMB acessível na rede auditada", "protocol_confirmed": True},
                ))
            elif evidence.kind == "tls.legacy_version":
                device.findings.append(Finding(
                    f"Endpoint TLS aceita {evidence.value}", "Informativa",
                    f"Negociação TLS limitada ao protocolo legado foi aceita em {device.ip}.",
                    "Revise compatibilidade e desabilite versões TLS legadas onde não forem necessárias.",
                    "Protocolo criptográfico legado", risk_score=58, confidence=evidence.confidence,
                    context={"asset_type": device.device_type, "asset_criticality": device.criticality,
                             "exposure": "Handshake TLS acessível na rede auditada", "protocol_confirmed": True},
                ))
            elif evidence.kind == "service.telnet_protocol":
                continue
            elif evidence.kind == "ftp.features":
                continue
            if evidence.kind != "ftp.features":
                continue
            features = evidence.value.lower()
            if "211 end" in features and "auth tls" not in features:
                device.findings.append(Finding(
                    "Servidor FTP não anunciou AUTH TLS na resposta FEAT", "Informativa",
                    f"Resposta FEAT observada em {device.ip}: {evidence.value}",
                    "Confirme a política de criptografia do serviço; a ausência na resposta FEAT é uma indicação, não prova de que TLS não esteja disponível.",
                    "Configuração de serviço a validar", risk_score=34, confidence=0.7,
                    context={"asset_type": device.device_type, "asset_criticality": device.criticality,
                             "exposure": "Acessível a partir do notebook na rede auditada", "tls_support_advertised": False},
                ))
    windows_rules = {
        "windows.firewall.disabled_profiles": ("Firewall do Windows desabilitado em perfis", 55,
            "Revise as políticas do cliente e habilite os perfis de firewall que deveriam estar ativos."),
        "windows.defender.antivirus_enabled": ("Microsoft Defender não reporta antivírus ativo", 70,
            "Confirme qual antivírus está aprovado pela organização; um antivírus de terceiros pode explicar este estado."),
        "windows.updates.pending_count": ("Atualizações de software pendentes detectadas", 45,
            "Revise as atualizações disponíveis conforme a política de mudança do cliente."),
        "windows.uac.enable_lua": ("UAC desabilitado", 65,
            "Revise a política local de UAC e mantenha-a habilitada conforme a política do cliente."),
    }
    windows_observations = [(None, evidence) for evidence in result.evidence]
    windows_observations.extend((device, evidence) for device in result.devices for evidence in device.evidence
                                if evidence.kind.startswith("windows."))
    for target_device, evidence in windows_observations:
        if evidence.kind.endswith(".error"):
            finding = Finding(
                "Não foi possível verificar uma configuração Windows", "Informativa",
                evidence.value, "Revise o log técnico e a disponibilidade da consulta; o estado não foi confirmado.",
                "Verificação Windows", risk_score=10, confidence=0.95,
                context={"collection_source": evidence.source},
            )
            (target_device.findings if target_device else result.findings).append(finding)
            continue
        if evidence.kind == "windows.not_available":
            finding = Finding(
                "Verificações Windows locais não executadas", "Informativa", evidence.value,
                "Execute o auditor em um notebook Windows se estas verificações forem necessárias.",
                "Verificação Windows", risk_score=10, confidence=1.0,
                context={"collection_source": evidence.source},
            )
            result.findings.append(finding)
            continue
        rule = windows_rules.get(evidence.kind)
        if not rule:
            continue
        title, score, recommendation = rule
        value = evidence.value.strip().lower()
        if evidence.kind == "windows.firewall.disabled_profiles":
            if not value.isdigit():
                (target_device.findings if target_device else result.findings).append(Finding("Estado do firewall não pôde ser interpretado", "Informativa",
                    f"Valor retornado: {evidence.value}", "Revise o log técnico e confirme o estado dos perfis manualmente.",
                    "Postura Windows", risk_score=10, confidence=0.5, context={"collection_source": evidence.source}))
                continue
            insecure = int(value) > 0
            observed = f"Perfis de firewall desabilitados: {evidence.value}"
        elif evidence.kind == "windows.defender.antivirus_enabled":
            if value not in ("true", "false", "1", "0"):
                (target_device.findings if target_device else result.findings).append(Finding("Estado do Microsoft Defender não pôde ser interpretado", "Informativa",
                    f"Valor retornado: {evidence.value}", "Revise o log técnico e confirme o antivírus ativo.",
                    "Postura Windows", risk_score=10, confidence=0.5, context={"collection_source": evidence.source}))
                continue
            insecure = value in ("false", "0")
            observed = f"AntivirusEnabled: {evidence.value}"
        elif evidence.kind == "windows.updates.pending_count":
            if not value.isdigit():
                (target_device.findings if target_device else result.findings).append(Finding("Estado das atualizações não pôde ser interpretado", "Informativa",
                    f"Valor retornado: {evidence.value}", "Revise o log técnico e confirme as atualizações disponíveis.",
                    "Postura Windows", risk_score=10, confidence=0.5, context={"collection_source": evidence.source}))
                continue
            insecure = value.isdigit() and int(value) > 0
            observed = f"Atualizações de software pendentes detectadas: {evidence.value}"
        else:
            if value not in ("true", "false", "1", "0"):
                (target_device.findings if target_device else result.findings).append(Finding("Estado do UAC não pôde ser interpretado", "Informativa",
                    f"Valor retornado: {evidence.value}", "Revise o log técnico e confirme a configuração de UAC.",
                    "Postura Windows", risk_score=10, confidence=0.5, context={"collection_source": evidence.source}))
                continue
            insecure = value in ("false", "0")
            observed = f"EnableLUA: {evidence.value}"
        if insecure:
            finding = Finding(
                title, "Informativa", observed, recommendation, "Postura Windows",
                risk_score=score, confidence=evidence.confidence,
                context={"collection_source": evidence.source},
            )
            (target_device.findings if target_device else result.findings).append(finding)
