# Contribuir

1. Abra issue com problema, plataforma, revisão e resultado esperado. Não inclua segredos ou APKs proprietários.
2. Faça branch, implemente alteração pequena e acrescente regressão offline.
3. Execute unittest, capabilities e scripts/metrics.py. Mudanças nos motores devem passar integração real Linux.
4. Abra PR; diferencie testes executados de apenas configurados.

Não aceite shell arbitrário, URLs controladas pelo APK, downloads sem hash, instalação sem consentimento ou execução automática do alvo. Nenhum aumento de limites deve ser silencioso. Testes de arquivos maliciosos devem ser sintéticos, locais e não executar payloads.

Para atualizar catálogo, use release oficial, confira checksum oficial/independente quando disponível, documente versão/licença e rode integração. Uma URL nova não prova integridade. Evite acrescentar dependências por conveniência sem justificar.

O CI usa tokens somente leitura e não precisa de secrets. Não use pull_request_target para executar código de contribuições. Rever licenças de componentes externos continua necessário.
