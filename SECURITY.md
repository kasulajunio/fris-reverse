# Modelo de segurança

## Fronteiras

Código do host e cliente MCP são confiáveis; APK, arquivos extraídos, nomes, strings e código decompilado são hostis. As ferramentas externas são componentes de terceiros que podem ter vulnerabilidades. Não há sandbox de SO, análise dinâmica nem garantia contra execução de código causada por falha em parser.

## Controles implementados

- Caminhos resolvidos dentro de workspace/job, sem shell arbitrário.
- ZIP com limites de contagem/tamanho declarado; bloqueio de traversal, links, criptografia, nomes duplicados, colisões por caixa, NUL, barras invertidas e nomes reservados do Windows. A validação considera orig_filename antes da normalização de ZipInfo.
- TAR com contagem/tamanho limitados, rejeição de arquivos especiais e links externos; links internos de arquivo são materializados como cópias, sem criar symlinks.
- HTTPS oficial com validação de redirecionamento, versões/checksums de motores fixados e checksum oficial do JRE resolvido. Verificação de inventário de arquivos instalados.
- subprocessos com argumentos separados, stdin fechado e ambiente reduzido, sem herança indiscriminada de segredos. JAVA_HOME/PATH e o próprio host continuam confiáveis.
- Timeout, heap JVM limitado, monitoramento de logs, leitura paginada e busca com orçamentos.
- MCP sem downloads implícitos e com autorização dupla para instalação.

## Limitações relevantes

Não há quota rígida de disco nem limite global de CPU. O monitoramento de logs é periódico e pode ultrapassar brevemente o orçamento. Validações de caminhos não resistem a um processo local malicioso alterando o mesmo diretório entre verificações. No Windows, timeout encerra o processo principal sem garantia de matar todos os descendentes.

Manifests são analisados após decodificação: DTD e entidades são recusados; pontos de revisão não constituem auditoria completa. Cabeçalhos DEX/ELF são observações não autenticadas. Assinaturas de APK, criptografia, malware, integridade semântica e exploração não são verificados.

Checksums não comprovam ausência de malware e não substituem assinatura independente/auditoria. A integridade do registro de instalação pressupõe diretório do usuário confiável. Java do sistema é reutilizado como componente confiável; o host pode estar comprometido.

## Implantação recomendada

VM/container descartável, usuário sem privilégios, workspace dedicada, sem credenciais, rede bloqueada durante análise, quotas externas de CPU/RAM/disco e cópia dos resultados revisada antes de sair do isolamento. O projeto não configura isso automaticamente. Não compartilhe a workspace com outros processos não confiáveis e não exponha o servidor pela rede.

## Divulgação de falhas

Prefira GitHub Private Vulnerability Reporting, se disponível, ou contato privado com o mantenedor pelo perfil. Não publique segredos, APKs proprietários ou prova de conceito que ataque terceiros. Informe commit, plataforma, passos mínimos autorizados, resultado esperado/observado e impacto. Nenhum endereço de e-mail de segurança ou SLA é prometido.
