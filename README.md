# Radar de Vulnerabilidades

Painel público e gratuito com as falhas de segurança **exploradas ou urgentes** em software comum em instituições de ensino e pesquisa: Debian e Ubuntu, PHP, servidores web, e-mail, bancos de dados, Moodle, WordPress, Drupal, GLPI, OJS, DSpace, GitLab, VPN, virtualização e outros.

**Painel:** https://edcarllos.github.io/radar-vulnerabilidades/

Para cada falha, o painel mostra:
- gravidade, versões afetadas e correção em cada distro (Debian 12/13, Ubuntu 22.04/24.04/26.04);
- mitigação e referências oficiais;
- uma decisão com prazo: Agir agora, Agir em breve, Acompanhar de perto ou Acompanhar.

Também gera scripts para verificar e corrigir servidores, com ponto de restauração e rollback.

## Como funciona

- **Coleta:** roda todo dia por volta das 06:40 (horário de Brasília) no GitHub Actions ([`.github/workflows/coleta.yml`](.github/workflows/coleta.yml)). Mantenedores também podem rodá-la quando quiserem: **Actions → Coleta → Run workflow**, ou `gh workflow run coleta.yml`.
- **Fontes:** só oficiais:
  - CISA KEV, NVD e FIRST EPSS;
  - Debian Security Tracker (DSA/DLA) e Ubuntu Security (CVE Tracker, OVAL, USN);
  - alertas do CAIS/RNP (título, data e link, com a conferência da assinatura PGP);
  - avisos dos fornecedores.
- **Publicação:** a coleta valida tudo antes de publicar (sintaxe dos scripts, `SHA256SUMS` e assinatura). Só então publica no GitHub Pages.
- **Estado:** o estado de uma coleta para a outra (datas de primeira coleta e histórico) fica no branch `dados`. Sem ele, a coleta para em vez de recomeçar do zero.
- **Meu contexto:** cada visitante marca as tecnologias que usa e a importância de cada uma. A decisão e os prazos são recalculados no navegador e nada é enviado para fora.

## Verificar os scripts antes de rodar

Os scripts completos ficam em `https://edcarllos.github.io/radar-vulnerabilidades/scripts/`.

```bash
curl -fsSO https://edcarllos.github.io/radar-vulnerabilidades/chave-radar.asc
gpg --import chave-radar.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Impressão digital da chave do projeto (Radar de Vulnerabilidades (scripts), ed25519, válida até 26/11/2028):

```
58EC 76D9 3AC9 5E0C 5CB3  B930 3ACB C8D1 F007 CB83
```

Ela fica aqui, fora do site que a chave protege. Depois de importar, confira com `gpg --fingerprint`.

Rode sempre a verificação primeiro, depois a correção com `--simular`, e só então corrija, com backup ou snapshot.

## Rodar na sua máquina

Precisa de bash, curl, git, python3, Node.js 18+ e gpg.

```bash
bash ferramentas/coletar.sh                     # coleta e constrói site/ e scripts/
RADAR_PUBLICO=1 node ferramentas/build.mjs      # painel em modo público
bash ferramentas/montar-publico.sh /tmp/radar   # monta o site como no GitHub Pages
```

Para servir o painel na intranet, com coleta no servidor da instituição e envio de resultados dos servidores, veja [`implantacao/LEIA-ME.md`](implantacao/LEIA-ME.md). Para treinar quem está começando, veja [`laboratorio/LEIA-ME.md`](laboratorio/LEIA-ME.md).

## Contribuir

- **Falso positivo ou produto que falta:** abra uma issue (há modelos prontos).
- **Itens novos:** entram por pull request em `itens.json`. Os candidatos do dia ficam na issue com o rótulo `candidatos`, que a coleta mantém.
- **Detalhes:** veja [CONTRIBUTING.md](CONTRIBUTING.md).
- **Problemas de segurança nos scripts:** siga [SECURITY.md](SECURITY.md).

## Créditos e limites

- Os dados pertencem às fontes citadas. O Radar resume e aponta para o aviso original.
- This product uses the NVD API but is not endorsed or certified by the NVD.
- O EPSS é do FIRST (https://www.first.org/epss/).
- O catálogo KEV da CISA é de domínio público (CC0).
- Os estados por distro, os `indices/` e o `historico.json` derivam do Debian Security Tracker e do Ubuntu Security (CVE Tracker, OVAL © Canonical Ltd., USN). São usados com atribuição, para fins educacionais e não comerciais.
- Os alertas do CAIS/RNP aparecem só com título, data, CVEs e link para o original.
- O Radar é um projeto comunitário oferecido **sem garantia**: ajuda a priorizar, mas não substitui os avisos oficiais nem o julgamento da sua equipe.

## Licença

- **Código:** licença MIT (veja [LICENSE](LICENSE)).
- **Textos dos itens em `itens.json`:** resumos, mitigações e orientações, sob [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/deed.pt_BR).
- **Dados das fontes:** não são cobertos por essas licenças e seguem os termos de cada fonte.
