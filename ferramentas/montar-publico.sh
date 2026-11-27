#!/usr/bin/env bash
# Radar de Vulnerabilidades: monta o site PÚBLICO (GitHub Pages) a partir de site/ e scripts/ já construídos.
# Uso: RADAR_PUBLICO=1 RADAR_REPO=dono/nome node ferramentas/build.mjs   (ou ferramentas/coletar.sh com essas variáveis)
#      bash ferramentas/montar-publico.sh SAIDA [URL_DO_SITE]
# Publica: index.html, vulns.json, coletas.json, historico.json, indices/, scripts/ (com SHA256SUMS e, se houver,
# SHA256SUMS.asc), chave-radar.asc (se RADAR_GPG_CHAVE estiver definida) e novidades.xml (RSS).
# Nunca publica inventario.json, relatórios nem nada da implantação institucional.
set -euo pipefail
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
SAIDA="${1:?informe a pasta de saída}"
URL="${2:-}"
case "$URL" in ""|https://*) ;; *) echo "URL do site precisa começar com https://"; exit 2 ;; esac

falha() { echo "FALHA: $*" >&2; exit 1; }
[ -s "$PROJ/site/painel.html" ] || falha "site/painel.html ausente; rode o build antes."
grep -q '"publico":true' "$PROJ/site/painel.html" || falha "site/painel.html não foi construído em modo público (RADAR_PUBLICO=1)."
for f in vulns.json coletas.json historico.json exploradas.json; do [ -s "$PROJ/site/$f" ] || falha "site/$f ausente."; done
ls "$PROJ"/site/indices/*.txt >/dev/null 2>&1 || falha "site/indices/ vazio."

# Mesmas conferências da coleta institucional: nada é publicado se algo falhar.
for f in "$PROJ"/scripts/*.sh; do bash -n "$f" || falha "sintaxe em $f"; done
(cd "$PROJ/scripts" && sha256sum -c --quiet SHA256SUMS) || falha "SHA256SUMS não confere."
if [ -n "${RADAR_GPG_CHAVE:-}" ]; then
  [ -s "$PROJ/scripts/SHA256SUMS.asc" ] || falha "a chave de assinatura está configurada, mas SHA256SUMS.asc não foi gerado."
  gpg --batch --verify "$PROJ/scripts/SHA256SUMS.asc" "$PROJ/scripts/SHA256SUMS" 2>/dev/null || falha "assinatura de SHA256SUMS inválida."
fi

rm -rf "$SAIDA"
mkdir -p "$SAIDA/indices" "$SAIDA/scripts"

# Documento completo: o painel é um fragmento; a cabeça leva viewport, descrição e a política de conteúdo.
{
  printf '%s\n' '<!doctype html>' '<html lang="pt-BR">' '<head>' \
    '<meta charset="utf-8">' \
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">' \
    '<title>Radar de Vulnerabilidades</title>' \
    '<meta name="description" content="Falhas de segurança exploradas ou urgentes em software comum em instituições de ensino e pesquisa, com correção por distro, mitigação e scripts de verificação. Atualizado todo dia a partir de fontes oficiais.">' \
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'\">" \
    '<meta name="referrer" content="no-referrer">' \
    '</head>' '<body>'
  cat "$PROJ/site/painel.html"
  printf '%s\n' '</body>' '</html>'
} > "$SAIDA/index.html"

cp "$PROJ/site/vulns.json" "$PROJ/site/coletas.json" "$PROJ/site/historico.json" "$PROJ/site/exploradas.json" "$SAIDA/"
# Alertas do CAIS/RNP: o site deles reserva os direitos do texto. No site público ficam só título, data, CVEs e link.
python3 -I - "$SAIDA/vulns.json" "$SAIDA/coletas.json" <<'PY'
import json, sys
def limpar(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == "alertas_nacionais" and isinstance(v, list):
                for a in v:
                    if isinstance(a, dict):
                        a.pop("resumo", None)
            else:
                limpar(v)
    elif isinstance(o, list):
        for v in o:
            limpar(v)
for arq in sys.argv[1:]:
    d = json.load(open(arq, encoding="utf-8"))
    limpar(d)
    json.dump(d, open(arq, "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
PY
cp "$PROJ"/site/indices/*.txt "$SAIDA/indices/"
cp "$PROJ"/scripts/radar-*.sh "$PROJ"/scripts/radar-*.yml "$PROJ/scripts/SHA256SUMS" "$SAIDA/scripts/"
[ -s "$PROJ/scripts/SHA256SUMS.asc" ] && cp "$PROJ/scripts/SHA256SUMS.asc" "$SAIDA/scripts/"
if [ -n "${RADAR_GPG_CHAVE:-}" ]; then
  gpg --batch --armor --export "$RADAR_GPG_CHAVE" > "$SAIDA/chave-radar.asc"
  [ -s "$SAIDA/chave-radar.asc" ] || falha "não foi possível exportar a chave pública."
  cp "$SAIDA/chave-radar.asc" "$SAIDA/scripts/chave-radar.asc"
fi

# Feed RSS (o mesmo da coleta institucional), apontando para o endereço público.
cfg="$(mktemp)"; trap 'rm -f "$cfg"' EXIT
python3 -I -c 'import json,sys; json.dump({"painel_url": sys.argv[1]}, open(sys.argv[2], "w"))' "$URL" "$cfg"
python3 -I "$PROJ/ferramentas/notificar.py" feed --site "$SAIDA" --config "$cfg" --saida "$SAIDA/novidades.xml"

touch "$SAIDA/.nojekyll"
# Garantia final: nada de inventário nem de relatórios no que vai ao ar.
for proibido in inventario.json relatorios servidores; do
  [ ! -e "$SAIDA/$proibido" ] || falha "$proibido não pode ser publicado."
done
grep -q '"inventario": *{' "$SAIDA/vulns.json" && falha "vulns.json traz dados de inventário."
echo "Site público montado em $SAIDA ($(du -sh "$SAIDA" | cut -f1))."
