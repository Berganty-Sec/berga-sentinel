# Relatório técnico — Berga Sentinel

**Data:** 28/09/2026
**Escopo:** estado atual da arquitetura e das verificações Windows locais.
**Modo de validação:** inspeção de código e teste de integração real configurado; nenhuma rede foi varrida nesta revisão.

## Resumo executivo

O Berga Sentinel possui um fluxo modular coerente para uma primeira versão: descoberta limitada, inventário, evidências, regras, pontuação contextual e relatórios por público. A coleta de firewall, Microsoft Defender, atualizações disponíveis e UAC é local ao notebook auditor. Não há coleta remota de configuração Windows nem solicitação de credenciais.

O produto continua sendo um scanner de inventário e verificações básicas, não um scanner abrangente de vulnerabilidades. Sua cobertura depende da resposta ICMP/TCP e dos vizinhos registrados na tabela local. Há um teste de integração real, protegido por variáveis de ambiente para CIDR, hosts conhecidos e confirmação de autorização; ele verifica cobertura das sondas e compara o inventário aos IPs fornecidos pelo operador.

## Arquitetura atual

```text
Interface Tkinter
    └── Pipeline
        ├── Scanner ICMP/TCP + tabela de vizinhos local
        ├── Inventário + fabricante OUI local
        ├── Evidências de rede + fingerprints não autenticados
        ├── Coleta Windows local no notebook auditor
        ├── Regras de interpretação
        ├── Motor heurístico de risco
        └── Relatórios HTML/PDF, JSON e CSV por público
```

Os módulos de coleta produzem evidências; as regras geram achados; o motor ajusta score/severidade por confiança e contexto; os relatórios técnicos, operacionais e de cliente são gravados em diretórios próprios por auditoria.

## Verificações Windows

As consultas de firewall, Defender, Windows Update e UAC executam localmente no notebook auditor por PowerShell, em modo somente de leitura. A ferramenta não pede credenciais e não consulta os computadores Windows da rede para esses estados. A coleta remota permanece fora do escopo atual; resultados dos endpoints precisam ser obtidos por um mecanismo gerenciado e autorizado pelo cliente.

## Pontos fortes

1. O limite de escopo CIDR é validado estritamente e limitado a 256 endereços.
2. A descoberta e as sondas TCP têm limites de concorrência global e por host.
3. A base de fabricantes é local; endereços MAC não são enviados a serviços externos.
4. Exposição de porta é separada de vulnerabilidade confirmada; TCP/445 não gera achado apenas por estar aberto.
5. Evidências registram origem e confiança, e os nomes de apresentação não substituem o hostname técnico.
6. A interface confirma autorização e mantém os artefatos de cada execução em uma única pasta.
7. Não há remediação automática, exploração, tentativa de login em protocolos de serviço ou varredura UDP.
8. Os relatórios HTML/PDF não incluem o bloco de observações brutas; a trilha detalhada continua no JSON técnico interno.

## Riscos e limitações que permanecem

### Descoberta e identificação

- ICMP filtrado, portas fora do catálogo, firewalls e MAC aleatório podem omitir dispositivos. A tabela ARP/neighbor pode conter entradas antigas.
- Tipo e sistema operacional são estimativas. TTL, hostname, OUI e conjunto de portas não identificam com certeza Windows, Android ou impressora.
- A base OUI embutida é parcial. O fabricante da interface não prova a marca/modelo do ativo.
- A contagem de atualizações inclui software disponível segundo o Windows Update Agent e não determina criticidade, idade, aplicabilidade ou presença de CVEs.
- `AntivirusEnabled=False` pode refletir antivírus de terceiros ou política local; o achado pede confirmação da solução aprovada e não comprova ausência de proteção.

### Regras, risco e relatórios

- A severidade e o score são heurísticas próprias, não CVSS, e devem ser apresentados como priorização para validação.
- A coleta de serviço é seletiva e não substitui verificação autenticada de versões, configuração completa ou correlação com inventário de vulnerabilidades.
- Os relatórios incluem dados sensíveis de rede. Controle de acesso, retenção e compartilhamento da pasta `output/` dependem do operador.
- Os testes verificam a geração de PDF, mas a revisão visual de layout e o comportamento completo da GUI em Windows ainda precisam de validação manual.

## Escalabilidade e desempenho

Para a faixa atual de até 256 endereços, a concorrência limitada do scanner evita criar conexões simultâneas irrestritas. O volume de tarefas TCP cresce com o número de endereços multiplicado pelo catálogo de portas; timeouts e hosts filtrados são os principais fatores de duração. Ao crescer para escopos maiores, recomenda-se introduzir fila de trabalho limitada, cancelamento, orçamento global de tempo, progresso por fase e persistência incremental. Esses aumentos exigem reavaliar autorização/escopo.

## Recomendações de evolução

### Antes de uso recorrente com clientes

1. Executar o teste de integração real apenas em um escopo autorizado e controlado, informando IPs conhecidos para comparar a descoberta.
2. Confirmar o comportamento local com diferentes perfis de firewall, antivírus de terceiros e Windows Update indisponível.
3. Adicionar testes de integração para as regras locais de firewall, Defender, atualizações e UAC em uma VM Windows de teste.
4. Definir política de retenção e controle de acesso para os artefatos técnicos.

### Versões futuras

- Descoberta complementar via protocolos de inventário autorizados e integrações com fontes do cliente.
- OUI completo mantido localmente, com versão/data de atualização e validação de origem.
- Correlação de versões e configurações com advisories/CVEs, mantendo separado o fato observado da inferência de vulnerabilidade.
- Exportação estruturada, histórico/diff de auditorias e controles de retenção, depois de requisitos de privacidade definidos.

## Conclusão

A arquitetura e os limites atuais são adequados para uma primeira ferramenta de inventário e triagem autorizada em redes pequenas. As verificações de postura Windows cobrem somente o notebook auditor. A descoberta permanece best-effort; o teste real depende de escopo e IPs de referência fornecidos pelo operador e não pode garantir visibilidade de dispositivos que bloqueiem as sondas. Achados heurísticos devem ser revisados por analista.
