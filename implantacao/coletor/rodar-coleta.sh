#!/usr/bin/env bash
# Radar de Vulnerabilidades: uma coleta institucional completa (chamada pelo systemd ou pelo cron).
# Lê /etc/radar/radar.env, roda ferramentas/coletar.sh e publica painel, dados e scripts em RADAR_PUBLICAR.
# Opções: --sem-rede (reconstrói só com o cache; útil para testes).
set -euo pipefail
[ -r /etc/radar/radar.env ] && set -a && . /etc/radar/radar.env && set +a
PROJ="$(cd "$(dirname "$0")/../.." && pwd)"
PUB="${RADAR_PUBLICAR:-/var/www/radar}"
export RADAR_CACHE="${RADAR_CACHE:-$HOME/.cache/radar-vulnerabilidades}"
export NVD_API_KEY="${NVD_API_KEY:-}" RADAR_GPG_CHAVE="${RADAR_GPG_CHAVE:-}"

inicio=$(date +%s)
# Estado para o botão "Atualizar agora" do painel (lido pelo receptor em GET /api/coleta).
ESTADO_DIR="${RADAR_ESTADO_DIR:-/var/lib/radar-coletor}"
rm -f "$ESTADO_DIR/pedido-coleta" 2>/dev/null || true   # consome o pedido (senão a unidade .path dispararia de novo)
INICIO_ISO=$(date -Iseconds)
gravar_estado() {
  [ -d "$ESTADO_DIR" ] && [ -w "$ESTADO_DIR" ] || return 0
  printf '%s\n' "$1" > "$ESTADO_DIR/coleta-estado.json.tmp" && mv -f "$ESTADO_DIR/coleta-estado.json.tmp" "$ESTADO_DIR/coleta-estado.json"
}
gravar_estado "{\"inicio\": \"$INICIO_ISO\"}"
trap 'rc=$?; gravar_estado "{\"inicio\": \"$INICIO_ISO\", \"fim\": \"$(date -Iseconds)\", \"ok\": $([ $rc = 0 ] && echo true || echo false)}"' EXIT
# F7/F8: consolida o inventário (e a exposição, com consulta diária ao InternetDB) antes de construir os dados.
DB="${RADAR_INVENTARIO_DB:-/var/lib/radar-coletor/inventario.db}"
if [ -f "$DB" ]; then
  python3 -I "$PROJ/ferramentas/inventario.py" consolidar --db "$DB" --publicar "$PUB" --exposicao "${RADAR_EXPOSICAO:-/etc/radar/exposicao.json}" --internetdb || echo "Aviso: falha ao consolidar o inventário."
fi
export RADAR_INVENTARIO="$PUB/inventario.json"
bash "$PROJ/ferramentas/coletar.sh" "$@"

# Validação antes de publicar: nada é publicado se algo falhar.
for f in "$PROJ"/scripts/*.sh; do bash -n "$f" || { echo "FALHA de sintaxe em $f; nada publicado."; exit 1; }; done
(cd "$PROJ/scripts" && sha256sum -c --quiet SHA256SUMS) || { echo "FALHA: SHA256SUMS não confere; nada publicado."; exit 1; }

# Publicação: monta numa pasta temporária dentro de PUB e troca cada entrada com mv (atômico por arquivo).
mkdir -p "$PUB"
novo="$PUB/.novo.$$"
mkdir -p "$novo/indices" "$novo/scripts"
{ printf '<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Radar de Vulnerabilidades</title></head><body>'; cat "$PROJ/site/painel.html"; printf '</body></html>\n'; } > "$novo/index.html"
cp "$PROJ/site/vulns.json" "$PROJ/site/coletas.json" "$PROJ/site/historico.json" "$PROJ/site/exploradas.json" "$novo/"
cp "$PROJ"/site/indices/*.txt "$novo/indices/"
cp "$PROJ"/scripts/radar-*.sh "$PROJ"/scripts/radar-*.yml "$PROJ/scripts/SHA256SUMS" "$novo/scripts/"
[ -f "$PROJ/scripts/SHA256SUMS.asc" ] && cp "$PROJ/scripts/SHA256SUMS.asc" "$novo/scripts/"
cp -r "$PROJ/implantacao/servidores" "$novo/servidores"
if [ -n "$RADAR_GPG_CHAVE" ] && command -v gpg >/dev/null 2>&1; then
  gpg --batch --armor --export "$RADAR_GPG_CHAVE" > "$novo/chave-radar.asc" 2>/dev/null || true
fi
chmod -R a+rX "$novo"
for x in vulns.json coletas.json historico.json exploradas.json indices scripts servidores chave-radar.asc index.html; do
  [ -e "$novo/$x" ] || continue
  [ -e "$PUB/$x.antigo" ] && rm -r -- "$PUB/$x.antigo"
  [ -e "$PUB/$x" ] && mv -T "$PUB/$x" "$PUB/$x.antigo"
  mv -T "$novo/$x" "$PUB/$x"
  [ -e "$PUB/$x.antigo" ] && rm -r -- "$PUB/$x.antigo"
done
rmdir "$novo" 2>/dev/null || rm -r -- "$novo"
echo "Coleta publicada em $PUB em $(( $(date +%s) - inicio )) s."

# F14: relatório gerencial do mês corrente (atualizado a cada coleta; o do mês anterior fica como estava no fim dele).
if [ -f "$DB" ]; then
  python3 -I "$PROJ/ferramentas/relatorio.py" --db "$DB" --site "$PUB" --saida "$PUB/relatorios" >/dev/null && chmod -R a+rX "$PUB/relatorios" || echo "Aviso: falha ao gerar o relatório mensal."
fi

# F9: feed RSS (sempre) e notificações (se /etc/radar/notificacoes.json existir). Falha aqui não desfaz a publicação.
NOTIF="${RADAR_NOTIFICACOES:-/etc/radar/notificacoes.json}"
ESTADO="${RADAR_NOTIF_ESTADO:-/var/lib/radar-coletor/notificados.json}"
python3 -I "$PROJ/ferramentas/notificar.py" feed --site "$PUB" --config "$NOTIF" || echo "Aviso: falha ao gerar o feed RSS."
[ -f "$PUB/novidades.xml" ] && chmod a+r "$PUB/novidades.xml"
if [ -r "$NOTIF" ]; then
  python3 -I "$PROJ/ferramentas/notificar.py" enviar --site "$PUB" --config "$NOTIF" --estado "$ESTADO" || echo "Aviso: falha ao enviar avisos imediatos."
  # Resumo diário: na primeira coleta da manhã (antes do meio-dia), uma vez por dia.
  marca="$(dirname "$ESTADO")/resumo.data"
  if [ "$(date +%H)" -lt 12 ] && [ "$(cat "$marca" 2>/dev/null)" != "$(date +%F)" ]; then
    python3 -I "$PROJ/ferramentas/notificar.py" resumo --site "$PUB" --config "$NOTIF" && date +%F > "$marca" || echo "Aviso: falha ao enviar o resumo diário."
  fi
fi
