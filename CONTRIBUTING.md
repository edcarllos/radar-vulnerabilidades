# Como contribuir

Obrigado por ajudar. Os scripts do Radar rodam como root em servidores de outras pessoas. Por isso:
- toda mudança passa por pull request;
- todo pull request precisa da revisão de um mantenedor;
- só entram fontes oficiais.

## Reportar sem programar

- **Falso positivo:** no painel, use **Reportar falso positivo** na tabela de CVEs do item. Ou abra uma issue com o modelo "Falso positivo".
- **Produto que falta:** abra uma issue com o modelo "Produto novo".
- **Candidatos a item novo:** a coleta diária mantém uma issue com o rótulo `candidatos`, listando as entradas recentes do KEV e os alertas do CAIS que ainda não estão em nenhum item. Comente ali se algum importa para instituições de ensino.

## Editar `itens.json`

`itens.json` é o único arquivo curado à mão. O resto (`site/`, `scripts/`, o painel) é gerado pela coleta.

1. Siga o formato dos itens existentes. Use um `id` novo, estável e em kebab-case. Nunca renomeie nem remova ids existentes.
2. `tecnologia` precisa ser uma chave de `tecnologias`. Se criar uma nova, acrescente também em `criticidade.json` a importância sugerida (`alta`, `media` ou `baixa`).
3. `tipo` é um destes:
   - `pacote`: tem `fontes` por versão (`deb12`, `deb13`, `u2204`, `u2404`, `u2604`), com os nomes dos pacotes-fonte;
   - `kernel`;
   - `app`: Drupal, WordPress, GitLab ou FreeSWITCH, com as versões mínimas;
   - `manual`: equipamentos e sistemas fora do Debian/Ubuntu, com `como_verificar`.
4. **Campos do item:**
   - Preencha `cves` e/ou `cves_de` (ids de DSA, DLA ou USN).
   - `situacao` é `explorado` se o CVE está no KEV ou o fornecedor declara exploração; senão, `urgente`.
   - Escreva resumo, versões afetadas, softwares que usam a tecnologia e mitigação, em português.
   - Em `referencias`, só URLs `https` oficiais.
5. **Produtos sem pacote na distro**, como Moodle, GLPI e Fortinet: use um item `nvd-<produto>` com `"nvd": {"cpe": [...], "palavra": "...", ...}`. Ele se atualiza sozinho pela NVD. Para tirar um falso positivo, ponha o CVE em `cves_excluir` do item.
6. **Para conferir na sua máquina:**
   ```bash
   bash ferramentas/coletar.sh
   for f in scripts/*.sh; do bash -n "$f"; done
   ```
   A construção não pode imprimir `ERRO:` nem linhas descartadas. O workflow **Verificar** repete essa conferência no pull request.

A decisão (Agir agora, Agir em breve…) é calculada sozinha a partir do KEV, do EPSS, do CVSS e da importância: não a escreva à mão.

## Código

Mudanças em `ferramentas/` (coleta, gerador de scripts, painel) seguem a mesma regra: um pull request, uma revisão e o workflow **Verificar** passando. Teste os scripts gerados num contêiner ou VM descartável, nunca em produção.
