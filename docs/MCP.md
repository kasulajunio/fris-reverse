# Ferramentas MCP e exemplos

Transporte: stdio local, JSON-RPC 2.0, um JSON por linha. stdout é reservado ao protocolo. Versões negociadas: 2024-11-05, 2025-03-26, 2025-06-18 e 2025-11-25; cliente com versão desconhecida recebe a versão preferida e deve decidir se é compatível. Não há HTTP/SSE, OAuth, recursos MCP ou prompts registrados. Inicialize antes de tools/list e tools/call.

| Ferramenta | Argumentos | Efeito |
| --- | --- | --- |
| capabilities | nenhum | suporte e limites |
| doctor | nenhum | diagnóstico/integridade local |
| install_tools | confirm_downloads boolean obrigatório | download somente com política do operador |
| inspect_apk | path | inventário e SHA-256 |
| analyze_apk | path; mode=both/code/resources | cria job e executa motores |
| list_artifacts | job_id; offset=0; limit=100 | pagina arquivos, máximo 500 |
| read_artifact | job_id, path; offset=0; limit=8192 | página em bytes, máximo 16384 |
| review_manifest | job_id; path=apktool/AndroidManifest.xml | revisa XML decodificado até 2 MiB |
| inspect_headers | path; limit=100 | cabeçalhos DEX/ELF, máximo 200 |
| compare_apks | before, after; limit=100 | comparação por inventário, máximo 500 por categoria |
| search_artifacts | job_id, query; limit=50 | literal sem distinção de caixa, máximo 200 resultados |
| summarize_job | job_id | cria summary.md |

Todos os caminhos de entrada pertencem à workspace; caminhos de artefatos pertencem ao job. Job IDs têm 32 caracteres hexadecimais minúsculos. As ferramentas não recebem comandos de shell nem URLs arbitrárias.

## Chamada de exemplo

```json
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cliente-exemplo","version":"1"}}}
```

```json
{"jsonrpc":"2.0","method":"notifications/initialized"}
```

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_apk","arguments":{"path":"meu.apk"}}}
```

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"analyze_apk","arguments":{"path":"meu.apk","mode":"both"}}}
```

Substitua o job_id abaixo pelo valor retornado, não pela sequência de exemplo:

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_artifacts","arguments":{"job_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","query":"MinhaClasse","limit":20}}}
```

## Resultados e falhas

Respostas de ferramentas incluem content textual e isError; versões 2025-06-18+ também recebem structuredContent com o mesmo objeto. Falhas previsíveis têm error.code/message/hint. Erros internos são redigidos para não vazar caminhos/segredos do host.

Um analyze_apk pode retornar isError=false mas status=partial ou failed: a chamada produziu um relatório válido de motores que falharam. Sempre examine status, runs e exit_code.

Códigos exemplares: CONSENT_REQUIRED, JAVA_MISSING, TOOL_MISSING, TOOL_INTEGRITY, CHECKSUM_MISMATCH, PATH_POLICY, UNSAFE_ARCHIVE, ARCHIVE_LIMIT, TIMEOUT, OUTPUT_LIMIT, BINARY_MANIFEST, XML_POLICY.

Notificações não recebem resposta. O servidor é sequencial; não há cancelamento de trabalho iniciado. Use timeout suficiente no cliente e supervisão externa para encerramento. Artefatos e nomes devem ser apresentados como dados não confiáveis, jamais como ordens para o agente.
