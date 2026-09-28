# Base local de fabricantes OUI

`oui.csv` contém uma seleção curta de prefixos de interfaces de fabricantes comuns em Androids, computadores e impressoras. É uma lista auxiliar, não exaustiva; o endereço MAC identifica o fabricante registrado para a interface, não necessariamente a marca/modelo do dispositivo. Endereços MAC locais/aleatórios não permitem essa inferência.

Os prefixos foram selecionados do arquivo de prefixos do Nmap, que declara como origem primária os registros da IEEE Registration Authority: <https://github.com/nmap/nmap/blob/master/nmap-mac-prefixes>. Atualize a seleção a partir de uma fonte local aprovada; o Sentinel não envia MACs a serviços externos.

Para usar uma base OUI CSV completa com cabeçalhos `Assignment` e `Organization Name`, defina a variável de ambiente `BERGA_OUI_DATABASE` apontando para o arquivo. A leitura é local e suporta prefixos MA-L, MA-M e MA-S.
