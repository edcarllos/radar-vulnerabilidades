#!/usr/bin/env bash
# Radar de Vulnerabilidades: curadoria pela comunidade (F20).
# Mantém UMA issue aberta, com o rótulo "candidatos", listando os candidatos a item novo da última coleta
# (entradas recentes do KEV e alertas do CAIS cujo CVE ainda não está em nenhum item). Fecha a issue quando a lista zera.
# Uso (GitHub Actions): GH_TOKEN=... RADAR_SITE_URL=... bash ferramentas/ci-candidatos.sh [site/vulns.json]
set -euo pipefail
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
VULNS="${1:-$PROJ/site/vulns.json}"
[ -n "${GH_TOKEN:-}" ] || { echo "GH_TOKEN ausente: issue de candidatos não atualizada."; exit 0; }
command -v gh >/dev/null || { echo "gh ausente: issue de candidatos não atualizada."; exit 0; }

corpo="$(mktemp)"; trap 'rm -f "$corpo"' EXIT
n="$(python3 -I - "$VULNS" "${RADAR_SITE_URL:-}" "$corpo" <<'PY'
import json, re, sys, urllib.parse
vulns, site, saida = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.load(open(vulns, encoding="utf-8"))
cand = d.get("candidatos") or []

def md(t):
    # Texto vindo de feeds externos: escapa markdown, quebra menções (@) e referências (#123).
    t = re.sub(r"\s+", " ", str(t or "")).strip()[:200]
    t = re.sub(r"([\\`*_{}\[\]()<>#+!|~])", r"\\\1", t)
    return t.replace("@", "@​")

def url(u):
    u = str(u or "")
    if not u.startswith("https://"):
        return ""
    return urllib.parse.quote(u, safe=":/?&=%#.-_~")

linhas = ["Lista mantida pela coleta diária (%s). Cada linha é uma entrada recente do CISA KEV ou um alerta do CAIS/RNP cujo CVE ainda não está em nenhum item do Radar." % md((d.get("coleta") or {}).get("id", "")),
          "",
          "Para transformar um candidato em item, abra um pull request em `itens.json` seguindo o formato dos itens existentes (veja CONTRIBUTING.md). Candidatos sem relação com TI de instituições de ensino e pesquisa podem ser ignorados.",
          ""]
if site.startswith("https://"):
    linhas += ["Painel: " + url(site), ""]
for c in cand[:60]:
    cves = ", ".join(x for x in (c.get("cves") or []) if re.fullmatch(r"CVE-\d{4}-\d{4,7}", x)) or "sem CVE"
    u = url(c.get("url"))
    tit = md(c.get("titulo"))
    linhas.append("- [ ] %s · %s · %s · %s" % (md(c.get("data")), md(c.get("fonte")), cves, ("[%s](%s)" % (tit, u)) if u else tit))
if not cand:
    linhas.append("Nenhum candidato pendente.")
open(saida, "w", encoding="utf-8").write("\n".join(linhas) + "\n")
print(len(cand))
PY
)"

gh label create candidatos --color FBCA04 --description "Candidatos a item novo, listados pela coleta" >/dev/null 2>&1 || true
num="$(gh issue list --label candidatos --state open --limit 1 --json number --jq '.[0].number // empty')"
if [ -z "$num" ]; then
  if [ "$n" -gt 0 ]; then
    gh issue create --title "Candidatos a item novo" --label candidatos --body-file "$corpo" >/dev/null
    echo "Issue de candidatos criada ($n candidatos)."
  else
    echo "Nenhum candidato; nenhuma issue aberta."
  fi
elif [ "$n" -gt 0 ]; then
  gh issue edit "$num" --body-file "$corpo" >/dev/null
  echo "Issue #$num atualizada ($n candidatos)."
else
  gh issue edit "$num" --body-file "$corpo" >/dev/null
  gh issue close "$num" --comment "Nenhum candidato pendente na coleta mais recente." >/dev/null
  echo "Issue #$num fechada: nenhum candidato pendente."
fi
