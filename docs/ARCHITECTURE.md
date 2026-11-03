# Arquitetura e decisões

## Módulos

- safety.py: confinamento de caminhos, validação/extração de arquivos e subprocessos supervisionados.
- install.py: catálogo oficial, HTTPS/redirects, SHA-256, registro de instalação, Java e diagnóstico.
- inspection.py: funções puras para manifesto XML decodificado e metadados de cabeçalhos DEX/ELF.
- insights.py: busca limitada, comparação de APKs, revisão de manifesto e resumo de job.
- app.py: workspace, inventário, cópia de entrada, execução de motores, status e leitura paginada.
- server.py: descoberta das 12 ferramentas, validação de argumentos e MCP stdio.
- __main__.py: CLI e entry point do pacote.
- tests/test_core.py: regressões offline, inclusive nomes ZIP maliciosos antes de normalização no Windows.
- scripts/integration.py: fixture Android original, instalação real e evidências.
- scripts/metrics.py: contagem reprodutível de arquivos/linhas/métodos de teste, sem confundir volume com qualidade.

## Fluxo de confiança

Cliente confiável → validação MCP → App → path/resource policies → motores em host isolado pelo operador → artefatos não confiáveis → leitura em páginas → cliente. O programa não oferece shell genérico e não transforma conteúdo do alvo em argumentos livres de execução. O host e suas ferramentas permanecem na base de confiança.

## Jobs

Identificador aleatório UUID hexadecimal, cópia independente input.apk, inventário/SHA-256, resultados por motor e report.json com schema_version=1. A cópia é comparada ao hash inicial. Não há banco de dados, conta, telemetria, upload ou cache compartilhado de APKs. Não há gerenciamento automático de retenção; remova resultados manualmente no host após encerrar processos.

## Estados

complete: todos os motores solicitados retornaram zero. partial: ao menos um retornou zero e outro falhou. failed: nenhum retornou zero. Mesmo complete não prova que toda classe foi recuperada, que o alvo é seguro ou que o código compila.

## Por que stdlib

Reduz dependências Python de execução e simplifica auditoria. O build usa setuptools. A implementação MCP é pequena e intencionalmente limitada a ferramentas stdio; não é uma implementação integral de cada recurso do protocolo. O projeto não é instalador universal de engenharia reversa.

## Fora do escopo atual

Instrumentação dinâmica, execução do APK, assinatura/reempacotamento, integração com contas de jogos, ADB, Frida, Ghidra, bypass de DRM, inferência de segurança por heurísticas e reconstrução automática do projeto original.
