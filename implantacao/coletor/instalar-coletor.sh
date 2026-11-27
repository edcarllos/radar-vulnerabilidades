#!/usr/bin/env bash
# Radar de Vulnerabilidades: instala a COLETA INSTITUCIONAL num servidor Debian 12/13 ou Ubuntu 22.04+.
# Uso: sudo bash implantacao/coletor/instalar-coletor.sh [--publicar /var/www/radar] [--sem-systemd]
#   - cria o usuário de sistema radar-coletor;
#   - copia o projeto para /opt/radar e usa /var/lib/radar-coletor/cache como cache;
#   - instala radar-coleta.service + radar-coleta.timer (07:40 e 13:40, com atraso aleatório);
#   - cada coleta reconstrói dados, painel e scripts e publica em --publicar (padrão /var/www/radar);
#   - configuração em /etc/radar/radar.env (chave da NVD, chave GPG para assinar SHA256SUMS).
# Idempotente: rodar de novo atualiza o código em /opt/radar sem apagar cache nem configuração.
set -euo pipefail

PROJ_ORIG="$(cd "$(dirname "$0")/../.." && pwd)"
PUB=/var/www/radar
SEM_SYSTEMD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --publicar) PUB="${2:?informe a pasta}"; shift ;;
    --sem-systemd) SEM_SYSTEMD=1 ;;
  esac
  shift
done
[ "$(id -u)" = 0 ] || { echo "Rode como root (sudo)."; exit 2; }
case "$PUB" in /*) ;; *) echo "--publicar precisa ser um caminho absoluto."; exit 2 ;; esac

# 1. Dependências
faltam=""
for c in curl git python3 node gpg sha256sum; do command -v "$c" >/dev/null 2>&1 || faltam="$faltam $c"; done
if [ -n "$faltam" ]; then
  echo "Instalando dependências:$faltam"
  apt-get update -qq
  apt-get install -y -qq curl git python3 nodejs gpg coreutils >/dev/null
fi
v=$(node -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)
[ "$v" -ge 18 ] || { echo "Node.js 18 ou mais novo é necessário (encontrado: $v)."; exit 2; }

# 2. Usuário, pastas e código
id radar-coletor >/dev/null 2>&1 || useradd --system --home-dir /var/lib/radar-coletor --create-home --shell /usr/sbin/nologin radar-coletor
install -d -m 0750 -o radar-coletor -g radar-coletor /var/lib/radar-coletor /var/lib/radar-coletor/cache
install -d -m 0755 -o radar-coletor -g radar-coletor /opt/radar "$PUB"
install -d -m 0750 -o root -g radar-coletor /etc/radar
chgrp radar-coletor /etc/radar && chmod 0750 /etc/radar  # o receptor e a coleta (radar-coletor) leem tokens.json e exposicao.json
tar -C "$PROJ_ORIG" --exclude=./site --exclude=./scripts --exclude=./.git -cf - . | tar -C /opt/radar -xf -
install -d -o radar-coletor -g radar-coletor /opt/radar/site /opt/radar/scripts
[ -d "$PROJ_ORIG/site" ] && cp -a "$PROJ_ORIG/site/." /opt/radar/site/ 2>/dev/null || true
chown -R radar-coletor:radar-coletor /opt/radar
chmod 0755 /opt/radar/ferramentas/*.sh /opt/radar/implantacao/coletor/*.sh 2>/dev/null || true

# 3. Configuração (não sobrescreve)
if [ ! -f /etc/radar/radar.env ]; then
  cat > /etc/radar/radar.env <<EOF
# Radar de Vulnerabilidades: configuração da coleta institucional
RADAR_CACHE=/var/lib/radar-coletor/cache
RADAR_PUBLICAR=$PUB
# Chave da API da NVD (https://nvd.nist.gov/developers/request-an-api-key); deixe vazio para o modo lento.
NVD_API_KEY=
# E-mail ou id da chave GPG do usuário radar-coletor para assinar scripts/SHA256SUMS (vazio = sem assinatura).
RADAR_GPG_CHAVE=
EOF
fi
chown root:radar-coletor /etc/radar/radar.env
chmod 0640 /etc/radar/radar.env
# F7/F8: tokens dos servidores e lista de exposição (não sobrescreve)
[ -f /etc/radar/tokens.json ] || echo '{}' > /etc/radar/tokens.json
[ -f /etc/radar/exposicao.json ] || printf '%s\n' '{"_sobre": "servidores: nomes expostos à internet; ips: nome -> IP público para consulta ao Shodan InternetDB", "servidores": [], "ips": {}}' > /etc/radar/exposicao.json
chown root:radar-coletor /etc/radar/tokens.json /etc/radar/exposicao.json
chmod 0640 /etc/radar/tokens.json /etc/radar/exposicao.json
# F9: modelo de notificações (só passa a valer quando copiado para /etc/radar/notificacoes.json)
install -m 0640 -o root -g radar-coletor "$PROJ_ORIG/implantacao/coletor/notificacoes.exemplo.json" /etc/radar/notificacoes.exemplo.json

# 4. systemd
if [ "$SEM_SYSTEMD" = 0 ] && [ -d /run/systemd/system ]; then
  install -m 0644 "$PROJ_ORIG/implantacao/coletor/radar-coleta.service" /etc/systemd/system/radar-coleta.service
  install -m 0644 "$PROJ_ORIG/implantacao/coletor/radar-coleta.timer" /etc/systemd/system/radar-coleta.timer
  install -m 0644 "$PROJ_ORIG/implantacao/coletor/radar-receptor.service" /etc/systemd/system/radar-receptor.service
  install -m 0644 "$PROJ_ORIG/implantacao/coletor/radar-coleta-pedido.path" /etc/systemd/system/radar-coleta-pedido.path
  sed -i "s#@@PUBLICAR@@#$PUB#g" /etc/systemd/system/radar-coleta.service /etc/systemd/system/radar-receptor.service
  systemctl daemon-reload
  systemctl try-restart radar-receptor.service  # carrega o código novo do receptor numa reinstalação
  systemctl enable --now radar-coleta.timer radar-receptor.service radar-coleta-pedido.path
  echo "Timer ativo: systemctl list-timers radar-coleta.timer"
else
  echo "systemd indisponível: agende /opt/radar/implantacao/coletor/rodar-coleta.sh como radar-coletor (cron) ou rode-o à mão."
fi

echo
echo "Pronto. Próximos passos:"
echo "  1. Ponha a chave da NVD em /etc/radar/radar.env."
echo "  2. (Recomendado) Crie a chave de assinatura: sudo -u radar-coletor gpg --quick-gen-key 'Radar <seguranca@SUA-INSTITUICAO>' ed25519 sign 2y"
echo "     e informe o e-mail em RADAR_GPG_CHAVE. A chave pública vai para $PUB/chave-radar.asc."
echo "  3. Primeira coleta: sudo systemctl start radar-coleta.service (ou sudo -u radar-coletor /opt/radar/implantacao/coletor/rodar-coleta.sh)"
echo "  4. Sirva $PUB com o exemplo implantacao/coletor/nginx-radar.conf (acesso restrito à rede interna)."
echo "  5. Para cada servidor monitorado: sudo python3 /opt/radar/ferramentas/inventario.py token-novo NOME"
echo "     e no servidor: sudo bash instalar-verificacao.sh ./scripts --enviar https://ESTE-SERVIDOR/radar --token TOKEN"
echo "  6. Avisos por e-mail/Telegram/Mattermost/Teams: copie /etc/radar/notificacoes.exemplo.json para notificacoes.json,"
echo "     ajuste e teste: sudo -u radar-coletor python3 /opt/radar/ferramentas/notificar.py testar --site $PUB"
echo "     O feed RSS fica em $PUB/novidades.xml."
