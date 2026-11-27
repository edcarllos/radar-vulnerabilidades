# Radar de Vulnerabilidades: implantação

Duas partes, independentes:

| Parte | Onde roda | O que faz |
| --- | --- | --- |
| `coletor/` | 1 servidor institucional (Debian 12/13 ou Ubuntu 22.04+) | Coleta as fontes oficiais 2 vezes por dia, reconstrói painel e scripts, assina e publica numa pasta servida pelo nginx |
| `servidores/` | cada servidor monitorado | Roda a verificação de hora em hora (só leitura), entrega o resultado ao Zabbix e ao Wazuh e, opcionalmente, ao coletor |

Nada aqui corrige servidores sozinho. A correção continua com `radar-corrigir.sh`, que pergunta antes de cada ação, ou com o playbook `radar-ansible.yml` (seção 5), que você roda quando decidir.

## 1. Coletor institucional (F2)

```bash
sudo bash implantacao/coletor/instalar-coletor.sh --publicar /var/www/radar
sudoedit /etc/radar/radar.env          # NVD_API_KEY e, depois do passo 2, RADAR_GPG_CHAVE
sudo -u radar-coletor gpg --quick-gen-key 'Radar <seguranca@SUA-INSTITUICAO>' ed25519 sign 2y
sudo systemctl start radar-coleta.service && journalctl -u radar-coleta -f
```

- Requisitos: curl, git, python3, Node.js 18+, gpg. O instalador instala o que faltar.
- Disco: cerca de 1 GB de cache em `/var/lib/radar-coletor/cache`.
- Primeira coleta: de 5 a 10 minutos com a chave da NVD; depois, de 1 a 3 minutos.
- Publicação: `index.html` (painel), `vulns.json`, `historico.json`, `indices/`, `scripts/` (com `SHA256SUMS` e `SHA256SUMS.asc`), `servidores/`, `chave-radar.asc`, `novidades.xml` (feed RSS) e, com servidores enviando resultados, `inventario.json`.
- nginx: use `coletor/nginx-radar.conf`. O painel é um mapa de vulnerabilidades da instituição e deve ficar restrito à rede interna.
- Curadoria: a coleta atualiza sozinha os itens existentes. Itens novos (entradas recentes do KEV e alertas do CAIS sem item) aparecem em **Coletas > Candidatos a item novo**; alguém da equipe, ou a tarefa do Claude, decide se viram item em `itens.json`.
- Criticidade: ajuste `criticidade.json` com a gestão de TI. Ela define a importância de cada tecnologia na decisão SSVC.
- Botão **Atualizar agora** (topo do painel): pede uma coleta completa sem terminal. O receptor grava `/var/lib/radar-coletor/pedido-coleta` e a unidade `radar-coleta-pedido.path` inicia `radar-coleta.service`; o painel mostra o andamento e recarrega sozinho ao terminar. Regras: uma coleta por vez e no máximo uma a cada 15 minutos (mude com `RADAR_INTERVALO_MIN` no `radar.env` e reinicie o receptor). Quem vê o painel pode pedir, então use no bloco `location = /radar/api/coleta` do nginx o mesmo controle de acesso do painel. Com `auth_basic`, o log do receptor registra quem pediu (`journalctl -u radar-receptor`). O painel publicado no claude.ai não tem o botão: lá a página não consegue disparar a coleta, que continua pela tarefa agendada (Executar agora).
- Falsos positivos da NVD (F11): nos itens `nvd-*`, CVEs achados só pela palavra-chave e que a NVD já analisou como de outro fornecedor e outro produto saem sozinhos; a lista fica em **Coletas > Descartados da busca por palavra na NVD**. Para tirar um CVE à mão, use o botão **Não é deste produto** no detalhe do item e cole a linha `"cves_excluir": [...]` no item de `itens.json`.

## 2. Servidores monitorados (F1 e F5)

Em cada servidor, copie a pasta publicada `scripts/` (e, para a verificação completa diária, o índice da distro) e rode:

```bash
curl -fsSO https://SEU-COLETOR/radar/chave-radar.asc && gpg --import chave-radar.asc   # uma vez, como root
sudo bash instalar-verificacao.sh ./scripts --indice ./indices/idx-u2404.txt
```

O instalador recusa scripts cujo SHA-256 ou assinatura não conferem. Depois disso:

- `/var/lib/radar/verificacao.json`: resultado da última verificação (atualizado a cada hora).
- `/var/log/radar/verificacao.log`: um JSON por item (para o Wazuh), com rotação semanal.
- `/var/lib/radar/completo.json`: verificação completa diária com nota mínima 7 (se `--indice` foi usado).

### Zabbix

1. Copie `servidores/zabbix/userparameter_radar.conf` para `/etc/zabbix/zabbix_agent2.d/` e reinicie o agente.
2. Importe `servidores/zabbix/template_radar.yaml` (Zabbix 7.0) e vincule o template aos hosts.
3. Alarmes: itens para agir agora (alta), vulneráveis com correção (média), reinício pendente, dados velhos e falta de resultado há 3 horas.

### Wazuh

1. No agente: acrescente `servidores/wazuh/radar_localfile.xml` ao `ossec.conf`.
2. No gerenciador: copie `servidores/wazuh/radar_rules.xml` para `/var/ossec/etc/rules/` e reinicie.
3. Regras 100700 a 100704: "agir agora" gera alerta de nível 12.

## 3. Inventário e exposição (F7 e F8)

Os servidores podem enviar cada resultado ao coletor. O painel ganha a aba **Servidores**, o filtro "Só o que afeta nossos servidores" e a decisão sobe um nível nos itens que afetam servidor exposto à internet.

```bash
# no coletor (uma vez por servidor): imprime o token uma única vez; guarda só o SHA-256
sudo python3 /opt/radar/ferramentas/inventario.py token-novo moodle01
# no servidor monitorado
sudo bash instalar-verificacao.sh ./scripts --indice ./indices/idx-u2404.txt --enviar https://SEU-COLETOR/radar --token TOKEN
```

- O receptor (`radar-receptor.service`) escuta só em 127.0.0.1:8790; o nginx publica `/radar/api/` com HTTPS (exemplo em `coletor/nginx-radar.conf`). O token viaja num arquivo de cabeçalho legível só pelo usuário `radar` e não aparece em `ps`.
- O nome do servidor vem do token, nunca do corpo enviado. Resultados ficam em SQLite (`/var/lib/radar-coletor/inventario.db`, 60 por servidor).
- Exposição: liste em `/etc/radar/exposicao.json` os servidores expostos à internet (`"servidores": ["moodle01"]`) e, se quiser a confirmação de portas abertas, o IP público em `"ips"`. Só esses IPs são consultados no Shodan InternetDB, uma vez por coleta.
- Revogar um servidor: `sudo python3 /opt/radar/ferramentas/inventario.py token-remover moodle01`.

## 4. Notificações e feed (F9)

```bash
sudo cp /etc/radar/notificacoes.exemplo.json /etc/radar/notificacoes.json && sudoedit /etc/radar/notificacoes.json
read -rsp 'Token do bot: ' t; printf '%s\n' "$t" | sudo install -m 0640 -o root -g radar-coletor /dev/stdin /etc/radar/telegram.token; unset t   # um arquivo por segredo, fora do histórico
sudo -u radar-coletor python3 /opt/radar/ferramentas/notificar.py testar --site /var/www/radar
```

- Canais: e-mail (SMTP, com STARTTLS ou SSL), Telegram, Mattermost (serve também para Slack e Rocket.Chat) e Microsoft Teams (webhook de Workflows, cartão adaptável). Webhooks só por HTTPS.
- Aviso imediato, a cada coleta: item que passou a "Agir agora", entrada recente no KEV, EPSS acima de `epss_minimo` (padrão 10%) ou CVE novo com KEV ou nota 9+. Cada aviso sai uma vez (estado em `/var/lib/radar-coletor/notificados.json`). Na primeira execução, o que já existe é só registrado, para não inundar os canais.
- Resumo diário: na primeira coleta da manhã, com contagem por decisão, prazos, novidades das últimas 24 h e situação dos servidores.
- Feed RSS: `https://SEU-COLETOR/radar/novidades.xml`, gerado a cada coleta, mesmo sem notificações configuradas.

## 5. Correção em lote com Ansible (F10)

O painel (aba Scripts > **Ansible (lote)**) e a coleta (`scripts/radar-ansible.yml`, no `SHA256SUMS`) geram um playbook que embute o script de verificação da mesma seleção.

```bash
sha256sum -c --ignore-missing SHA256SUMS
ansible-playbook -i inventario radar-ansible.yml --check          # simula
ansible-playbook -i inventario radar-ansible.yml -e radar_lote=1  # aplica, um servidor por vez
```

- Em cada servidor: verifica (só leitura), guarda as versões instaladas em `/var/backups/radar-vuln/ansible-<data>.json`, atualiza com `apt` (`only_upgrade`) só os pacotes binários instalados dos itens vulneráveis com decisão "Agir agora" ou "Agir em breve", verifica de novo e mostra antes e depois.
- Não reinicia sem `-e radar_reiniciar=true`. Kernel e aplicações web aparecem como "fora do Ansible".
- Outras variáveis: `radar_decisoes`, `radar_itens` (ids do painel), `radar_hosts`. Requer ansible-core 2.14 ou mais novo (testado com 2.20).

## 6. Imagens de contêiner (F12)

```bash
bash radar-verificar.sh --imagem moodle-campus:4.5            # itens do Radar
bash radar-verificar.sh --imagem moodle-campus:4.5 --completo --dados idx-u2404.txt --nota-minima 7
```

- Lê só `/var/lib/dpkg/status` e o `os-release` da imagem: o contêiner é criado e apagado sem ser iniciado. Precisa de Docker ou Podman e de um host Debian ou Ubuntu (a comparação de versões usa o dpkg).
- Cobre imagens Debian e Ubuntu suportadas pelo Radar. Alpine, distroless e imagens RPM são recusadas com aviso. Kernel, aplicações web e processos não se aplicam a imagens.
- Corrigir é reconstruir: `docker build --pull --no-cache` a partir de uma base atualizada.

## 7. Relatório gerencial mensal (F14)

A cada coleta, `relatorio.py` regrava `https://SEU-COLETOR/radar/relatorios/AAAA-MM.html` (o mês corrente; os anteriores ficam como estavam no fim de cada mês). É uma página imprimível: Ctrl+P gera o PDF para a gestão.

- Indicadores: servidores monitorados e sem verificação recente, tempo de exposição a itens do KEV, aderência aos prazos da decisão SSVC, servidores com correção pendente por dia, itens que mais expõem o parque e CVEs confirmados sem correção por distro.
- Correspondência com o controle de gestão contínua de vulnerabilidades do Framework do PPSI (baseado no CIS Controls v8; confira a numeração na versão vigente).
- O histórico vem de duas tabelas pequenas do inventário (`episodios` e `diario`), alimentadas a cada resultado recebido. Os números começam a existir a partir da implantação do receptor.
- Contém nomes de servidores: fica só na intranet.

## 8. Formação

- Laboratório de treino (F15): `laboratorio/LEIA-ME.md`. Cinco exercícios num contêiner descartável: ler a verificação, simular, corrigir, desfazer e lidar com item sem correção, com conferência automática e gabarito.
- No painel publicado no claude.ai, cada item tem o botão **Explicar para o meu contexto** (F16): o Claude explica em linguagem simples usando só os dados daquele item, na conta de quem clica, que autoriza o uso na primeira vez. O painel servido na intranet não tem esse botão.

## Limites conhecidos

- Os modelos de Zabbix e Wazuh foram validados quanto à sintaxe (YAML e XML), mas não importados num Zabbix ou Wazuh reais.
- CTIR Gov: o portal estava em manutenção quando a fonte foi implementada; o leitor dessa fonte está pendente.
- Notificações: testadas contra servidores SMTP e webhook locais; o formato aceito por Telegram, Mattermost e Teams segue a documentação de cada um, mas não foi enviado a contas reais.
- Botão Atualizar agora: o receptor, o arquivo de estado, o intervalo e o recarregamento do painel foram testados em contêiner com nginx, simulando a unidade `.path` (o contêiner não tem systemd; a unidade passou no `systemd-analyze verify`).
- Rocky Linux e AlmaLinux (F13) ficaram de fora por decisão da equipe, até o inventário mostrar servidores dessas distros.
- O relatório mensal foi testado com histórico sintético de um mês; os indicadores reais dependem dos servidores enviando resultados.
- O playbook Ansible foi testado em contêiner Ubuntu 26.04 (`--check` e aplicação real); não foi testado em Debian nem com reinício.
- A versão mínima das aplicações web (Moodle, GLPI, OJS, Nextcloud, Keycloak, DSpace) é derivada das descrições da NVD; confira o aviso do projeto antes de agir.
