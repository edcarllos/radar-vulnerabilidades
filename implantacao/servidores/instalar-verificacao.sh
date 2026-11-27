#!/usr/bin/env bash
# Radar de Vulnerabilidades: instala a verificação automática num servidor monitorado.
# Uso: sudo bash instalar-verificacao.sh <pasta-com-os-scripts> [--indice idx-<distro>.txt] [--enviar https://COLETOR/radar --token TOKEN] [--remover]
#   A pasta deve conter radar-verificar.sh e SHA256SUMS (e, de preferência, SHA256SUMS.asc).
#   O que faz:
#     - confere o SHA-256 (e a assinatura GPG, se SHA256SUMS.asc existir e a chave da equipe estiver importada);
#     - instala o script em /usr/local/lib/radar/ e cria o usuário de sistema "radar" (sem login);
#     - agenda (cron) de hora em hora: /var/lib/radar/verificacao.json (Zabbix) e /var/log/radar/verificacao.log (Wazuh);
#     - com --indice, roda também a verificação completa uma vez por dia (/var/lib/radar/completo.json).
#     - com --enviar e --token, envia cada resultado ao receptor do coletor (F7), autenticado por token deste servidor
#       (gere no coletor: sudo python3 /opt/radar/ferramentas/inventario.py token-novo NOME-DO-SERVIDOR).
#   Nada é corrigido automaticamente. --remover desfaz tudo.
set -euo pipefail

DEST=/usr/local/lib/radar
DADOS=/var/lib/radar
LOGS=/var/log/radar
CRON=/etc/cron.d/radar-verificacao
ROTATE=/etc/logrotate.d/radar

[ "$(id -u)" = 0 ] || { echo "Rode como root (sudo)."; exit 2; }

if [ "${1:-}" = "--remover" ]; then
  rm -f "$CRON" "$ROTATE"
  [ -d /etc/radar-cliente ] && rm -r -- /etc/radar-cliente
  [ -d "$DEST" ] && rm -r -- "$DEST"
  echo "Removido. $DADOS e $LOGS foram mantidos; apague-os à mão se quiser."
  exit 0
fi

ORIG="${1:-}"; shift || true
INDICE=""; ENVIAR=""; TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --indice) INDICE="${2:-}"; shift ;;
    --enviar) ENVIAR="${2:-}"; shift ;;
    --token) TOKEN="${2:-}"; shift ;;
  esac
  shift
done
if [ -n "$ENVIAR" ]; then
  case "$ENVIAR" in https://*) ;; http://127.0.0.1*|http://localhost*) ;; *) echo "--enviar precisa ser https:// (o token não pode trafegar em texto claro)."; exit 2 ;; esac
  [[ "$TOKEN" =~ ^[A-Za-z0-9_-]{20,100}$ ]] || { echo "Informe --token com o token gerado no coletor."; exit 2; }
fi
[ -n "$ORIG" ] && [ -f "$ORIG/radar-verificar.sh" ] || { echo "Informe a pasta que contém radar-verificar.sh e SHA256SUMS."; exit 2; }

# 1. Integridade
if [ -f "$ORIG/SHA256SUMS" ]; then
  esperado=$(awk '$2=="radar-verificar.sh" {print $1}' "$ORIG/SHA256SUMS")
  obtido=$(sha256sum "$ORIG/radar-verificar.sh" | awk '{print $1}')
  if [ -z "$esperado" ] || [ "$esperado" != "$obtido" ]; then
    echo "FALHA: o SHA-256 de radar-verificar.sh não confere com SHA256SUMS. Não instalado."; exit 1
  fi
  echo "SHA-256 confere."
  if [ -f "$ORIG/SHA256SUMS.asc" ]; then
    if command -v gpg >/dev/null 2>&1 && gpg --batch --verify "$ORIG/SHA256SUMS.asc" "$ORIG/SHA256SUMS" >/dev/null 2>&1; then
      echo "Assinatura GPG de SHA256SUMS válida."
    else
      echo "FALHA: assinatura GPG ausente, inválida ou chave da equipe não importada (gpg --import chave-radar.asc). Não instalado."; exit 1
    fi
  else
    echo "Aviso: sem SHA256SUMS.asc; a integridade foi conferida só pelo hash."
  fi
else
  echo "FALHA: falta SHA256SUMS na pasta. Gere-o com o build ou baixe-o junto com o script."; exit 1
fi

# 2. Instalação
id radar >/dev/null 2>&1 || useradd --system --home-dir "$DADOS" --shell /usr/sbin/nologin radar
install -d -m 0755 "$DEST"
install -d -m 0755 -o radar -g radar "$DADOS" "$LOGS"
install -m 0755 "$ORIG/radar-verificar.sh" "$DEST/radar-verificar.sh"
if [ -n "$INDICE" ]; then
  [ -r "$INDICE" ] || { echo "Índice não encontrado: $INDICE"; exit 2; }
  install -m 0644 "$INDICE" "$DADOS/indice.txt"
fi

# Envio ao coletor: o token fica num arquivo de cabeçalho legível só pelo usuário radar (não aparece em ps).
ENVIO=""
if [ -n "$ENVIAR" ]; then
  install -d -m 0700 -o radar -g radar /etc/radar-cliente
  ( umask 077; printf 'Authorization: Bearer %s\n' "$TOKEN" > /etc/radar-cliente/cabecalho )
  chown radar:radar /etc/radar-cliente/cabecalho
  URL="${ENVIAR%/}/api/relatorio"
  ENVIO="curl -fsS -m 60 -H @/etc/radar-cliente/cabecalho -H 'Content-Type: application/json' --data-binary @$DADOS/verificacao.json $URL >/dev/null 2>>$LOGS/envio.log;"
  ENVIO_COMPLETO="curl -fsS -m 60 -H @/etc/radar-cliente/cabecalho -H 'Content-Type: application/json' --data-binary @$DADOS/completo.json $URL >/dev/null 2>>$LOGS/envio.log;"
fi

# 3. Agendamento (como usuário radar; leitura apenas)
{
  echo "# Radar de Vulnerabilidades (instalado em $(date -I))"
  echo "SHELL=/bin/bash"
  echo "17 * * * * radar $DEST/radar-verificar.sh --json > $DADOS/verificacao.json.tmp 2>/dev/null; mv $DADOS/verificacao.json.tmp $DADOS/verificacao.json; $ENVIO $DEST/radar-verificar.sh --json-linhas >> $LOGS/verificacao.log 2>/dev/null; true"
  if [ -n "$INDICE" ]; then
    echo "43 3 * * * radar $DEST/radar-verificar.sh --completo --dados $DADOS/indice.txt --json --nota-minima 7 > $DADOS/completo.json.tmp 2>/dev/null; mv $DADOS/completo.json.tmp $DADOS/completo.json; ${ENVIO_COMPLETO:-} true"
  fi
} > "$CRON"
chmod 0644 "$CRON"
cat > "$ROTATE" <<EOF
$LOGS/verificacao.log {
  weekly
  rotate 8
  compress
  missingok
  notifempty
  create 0644 radar radar
}
EOF

# 4. Primeira execução
if command -v runuser >/dev/null 2>&1; then
  runuser -u radar -- "$DEST/radar-verificar.sh" --json > "$DADOS/verificacao.json" 2>/dev/null || true
  if [ -n "$ENVIAR" ]; then
    if runuser -u radar -- curl -fsS -m 60 -H @/etc/radar-cliente/cabecalho -H 'Content-Type: application/json' --data-binary @"$DADOS/verificacao.json" "$URL"; then
      echo; echo "Primeiro envio ao coletor: OK."
    else
      echo "Aviso: o primeiro envio ao coletor falhou; veja $LOGS/envio.log e a conectividade com $ENVIAR."
    fi
  fi
fi
echo "Instalado. Resultado atual: $DADOS/verificacao.json"
echo "Zabbix: copie zabbix/userparameter_radar.conf para o agente e importe zabbix/template_radar.yaml."
echo "Wazuh: acrescente wazuh/radar_localfile.xml ao ossec.conf do agente e wazuh/radar_rules.xml ao gerenciador."
