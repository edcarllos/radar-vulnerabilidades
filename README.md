# Radar de Vulnerabilidades

Painel público e gratuito com as falhas de segurança **exploradas ou urgentes** em software comum em instituições de ensino e pesquisa: Debian e Ubuntu, PHP, servidores web, e-mail, bancos de dados, Moodle, WordPress, Drupal, GLPI, OJS, DSpace, GitLab, VPN, virtualização e outros.

**Painel:** https://edcarllos.github.io/radar-vulnerabilidades/

O painel tem estas abas:
- **Hoje:** o que mudou desde a coleta anterior (falhas que entraram no catálogo de exploradas, alertas do CTIR Gov e do CAIS, itens novos) e a situação de cada fonte.
- **Exploradas:** o catálogo KEV inteiro da CISA, de qualquer ano, com a situação da correção no Debian e na Ubuntu. Por padrão, só categorias de servidor e rede.
- **Novas:** itens curados, com gravidade, versões afetadas, correção por distro (Debian 12/13, Ubuntu 20.04/22.04/24.04/26.04), mitigação, referências e uma decisão com prazo sugerido. Antes de 01/11/2026 só entram falhas exploradas; a partir dessa data, todas as dos produtos acompanhados.
- **Por sistema:** as falhas exploradas e o histórico completo de CVEs de uma versão de distro, e o que fazer com Debian 11 (sem suporte), Ubuntu 20.04 (só Ubuntu Pro), Proxmox VE e TrueNAS.
- **Scripts:** verificação, correção com ponto de restauração, rollback e playbook Ansible. No Proxmox VE, a correção faz a atualização completa guiada (com snapshot ZFS ou backup antes); no TrueNAS e no Debian 11 só há verificação.
- **Relatório:** boletim mensal com números gerais e o uso no PPSI.
- **Aprender:** como usar, prazos e normas (PPSI, CTIR Gov, ANPD), glossário e laboratório.

## Como funciona

- **Coleta:** roda todo dia por volta das 06:40 (horário de Brasília) no GitHub Actions ([`.github/workflows/coleta.yml`](.github/workflows/coleta.yml)). Mantenedores também podem rodá-la quando quiserem: **Actions → Coleta → Run workflow**, ou `gh workflow run coleta.yml`.
- **Fontes:** só oficiais:
  - CISA KEV, NVD e FIRST EPSS;
  - Debian Security Tracker (DSA/DLA) e Ubuntu Security (CVE Tracker, OVAL, USN);
  - alertas do CTIR Gov e do CAIS/RNP (só título, data, CVEs e link);
  - avisos dos fornecedores.
- **Publicação:** a coleta valida tudo antes de publicar (sintaxe dos scripts, `SHA256SUMS` e assinatura). Só então publica no GitHub Pages.
- **Estado:** o estado de uma coleta para a outra (datas de primeira coleta e histórico) fica no branch `dados`. Sem ele, a coleta para em vez de recomeçar do zero.
- **Privacidade:** o Radar nunca pede que a instituição informe os sistemas que usa e não coleta inventário, IPs ou resultados de verificação. A importância de cada tecnologia é um padrão do projeto (`criticidade.json`), revisado pela comunidade.
- **Prazos:** 1, 7, 30 e 90 dias são sugestão do Radar (método SSVC). A referência oficial é o PPSI (controle 7.7: correção no ciclo mensal ou menor) e, para órgãos federais, o Decreto 10.748/2021 (art. 12, IX) nos alertas do CTIR Gov.

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
