# Segurança

Os scripts gerados pelo Radar rodam como root em servidores. Se você achar um problema que possa causar dano, não abra issue pública. São exemplos:
- um comando perigoso num script;
- uma forma de alterar o conteúdo publicado;
- uma falha na verificação de integridade.

Use **Report a vulnerability**, na aba **Security** do repositório, para falar em particular com os mantenedores. Respondemos assim que possível e combinamos a divulgação com você.

## Como o projeto se protege

- A coleta só usa fontes oficiais. O conteúdo de avisos e feeds é tratado como dado, nunca como instrução.
- Antes de publicar, a coleta confere a sintaxe dos scripts, o `SHA256SUMS` e, quando a chave está configurada, a assinatura `SHA256SUMS.asc`. Se algo falhar, nada é publicado.
- O painel não usa cookies, rastreamento nem scripts de terceiros. A política de conteúdo só permite recursos do próprio site.
- Mudanças em `itens.json` e no código entram por pull request com revisão obrigatória.
