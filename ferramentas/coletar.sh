#!/usr/bin/env bash
# Baixa os dados oficiais usados pelo Radar e reconstrói site/vulns.json.
# Uso: ferramentas/coletar.sh [--sem-rede | --so-baixar]
#   --sem-rede   reconstrói só com o cache, sem baixar nada (registra a coleta no histórico como as demais)
#   --so-baixar  baixa as fontes e sai, sem construir nem registrar coleta
#   RADAR_CACHE  diretório de cache (padrão: ~/.cache/radar-vulnerabilidades)
#   Chave da API da NVD (opcional; aumenta o limite de 5 para 50 consultas a cada 30 s):
#     variável NVD_API_KEY ou arquivo ~/.config/radar-vulnerabilidades/nvd-api-key (permissão 600).
#     A chave nunca é impressa nem passada na linha de comando.
# Só acessa fontes oficiais: cisa.gov, debian.org, salsa.debian.org, ubuntu.com, nist.gov.
set -euo pipefail
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="${RADAR_CACHE:-$HOME/.cache/radar-vulnerabilidades}"
mkdir -p "$CACHE/usn" "$CACHE/ubuntu" "$CACHE/nvd" "$CACHE/nvd-produtos" "$CACHE/oval"
baixar() { curl -fsSL --compressed -m 120 -o "$1.tmp" "$2" && mv "$1.tmp" "$1"; }

# NVD: usa a chave de API se existir; o cabeçalho vai pela entrada padrão do curl (não aparece em ps).
NVD_CHAVE_ARQ="${RADAR_NVD_CHAVE_ARQ:-$HOME/.config/radar-vulnerabilidades/nvd-api-key}"
NVD_CHAVE="${NVD_API_KEY:-}"
if [ -z "$NVD_CHAVE" ] && [ -r "$NVD_CHAVE_ARQ" ]; then NVD_CHAVE=$(tr -d ' \r\n' < "$NVD_CHAVE_ARQ"); fi
if [ -n "$NVD_CHAVE" ] && ! [[ "$NVD_CHAVE" =~ ^[A-Za-z0-9-]{20,64}$ ]]; then
  echo "AVISO: chave da NVD em formato inesperado; seguindo sem chave."; NVD_CHAVE=""
fi
if [ -n "$NVD_CHAVE" ]; then NVD_PAUSA=0.7; echo "== NVD: usando chave de API (limite maior)"; else NVD_PAUSA=6.5; fi
baixar_nvd() {
  local cod
  if [ -n "$NVD_CHAVE" ]; then
    local cab
    cab=$(printf 'apiKey: %s\n' "$NVD_CHAVE" | curl -sS --compressed -m 120 -H @- -o "$1.tmp" -D - "$2" 2>/dev/null) || true
    cod=$(printf '%s\n' "$cab" | awk 'toupper($1) ~ /^HTTP/ {c=$2} END {print c+0}')
    # A NVD responde 404 com "message: Invalid apiKey." para chave inválida.
    if [ "$cod" = 403 ] || [ "$cod" = 401 ] || printf '%s' "$cab" | grep -qi '^message: *invalid apikey'; then
      echo "AVISO: a NVD recusou a chave (HTTP $cod); seguindo sem chave."; NVD_CHAVE=""; NVD_PAUSA=6.5
      sleep 6.5; baixar "$1" "$2"; return
    fi
    if [ "$cod" = 200 ]; then mv "$1.tmp" "$1"; return 0; fi
    return 1
  fi
  baixar "$1" "$2"
}

if [ "${1:-}" != "--sem-rede" ]; then
  # Fontes que falharam nesta coleta (a página mostra "falhou nesta coleta; usando a cópia de ...").
  : > "$CACHE/falhas.txt"
  echo "== CISA KEV"
  baixar "$CACHE/kev.json" https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  echo "== Debian"
  baixar "$CACHE/deb.json" https://security-tracker.debian.org/tracker/data/json
  baixar "$CACHE/dsa-list.txt" https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DSA/list
  baixar "$CACHE/dla-list.txt" https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data/DLA/list
  echo "== Ubuntu OVAL (histórico completo; uma vez por dia)"
  for cod in focal jammy noble resolute; do
    f="$CACHE/oval/com.ubuntu.$cod.cve.oval.xml.bz2"
    if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +1380 2>/dev/null)" ]; then
      baixar "$f" "https://security-metadata.canonical.com/oval/com.ubuntu.$cod.cve.oval.xml.bz2" || echo "falhou OVAL $cod"
    fi
  done
  echo "== EPSS (FIRST; uma vez por dia)"
  f="$CACHE/epss.csv.gz"
  if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +1380 2>/dev/null)" ]; then
    baixar "$f" https://epss.empiricalsecurity.com/epss_scores-current.csv.gz || echo "falhou EPSS"
  fi
  echo "== Ubuntu CVE Tracker (estados de triagem; uma vez por dia)"
  if [ ! -d "$CACHE/uct.git" ]; then
    git clone -q --bare --depth 1 https://git.launchpad.net/ubuntu-cve-tracker "$CACHE/uct.git" || echo "falhou clone do Ubuntu CVE Tracker"
    rm -f "$CACHE/uct.tsv"
  elif [ -n "$(find "$CACHE/uct.tsv" -mmin +1380 2>/dev/null)" ] || [ ! -s "$CACHE/uct.tsv" ]; then
    git -C "$CACHE/uct.git" fetch -q --depth 1 origin +refs/heads/master:refs/heads/master || echo "falhou atualização do Ubuntu CVE Tracker"
    rm -f "$CACHE/uct.tsv"
  fi
  if [ -d "$CACHE/uct.git" ] && [ ! -s "$CACHE/uct.tsv" ]; then
    git -C "$CACHE/uct.git" archive HEAD active | python3 -I "$PROJ/ferramentas/completo.py" uct --saida "$CACHE/uct.tsv" || echo "falhou leitura do Ubuntu CVE Tracker"
  fi
  echo "== CAIS/RNP (alertas assinados com PGP)"
  mkdir -p "$CACHE/cais"
  baixar "$CACHE/cais/pagina1.html" https://www.rnp.br/servicos/cais/ || { echo "falhou página do CAIS"; echo "CAIS/RNP" >> "$CACHE/falhas.txt"; }
  baixar "$CACHE/cais/pagina2.html" https://www.rnp.br/servicos/cais/page/2/ || true
  cat "$CACHE"/cais/pagina*.html 2>/dev/null | python3 -I "$PROJ/ferramentas/nacionais.py" links /dev/stdin > "$CACHE/cais/links.txt" || : > "$CACHE/cais/links.txt"
  GPG_CAIS=""
  if command -v gpg >/dev/null 2>&1; then
    GPG_CAIS="$CACHE/cais/gnupg"; mkdir -p "$GPG_CAIS"; chmod 700 "$GPG_CAIS"
    if [ ! -s "$CACHE/cais/cais-pgp.key" ]; then
      baixar "$CACHE/cais/cais-pgp.key" https://plataforma.rnp.br/cais/cais-pgp.key && GNUPGHOME="$GPG_CAIS" gpg --batch --quiet --import "$CACHE/cais/cais-pgp.key" 2>/dev/null || echo "falhou importar a chave do CAIS"
    fi
  fi
  while read -r u; do
    case "$u" in https://plataforma.rnp.br/arquivos/documents/CAIS-Alerta*.txt*) ;; *) continue ;; esac
    id=$(printf '%s' "${u%%\?*}" | sha256sum | cut -c1-16)
    f="$CACHE/cais/$id.txt"
    [ -s "$f" ] || baixar "$f" "$u" || continue
    printf '%s\n' "$u" > "$f.url"
    if [ ! -s "$f.verif" ]; then
      if [ -n "$GPG_CAIS" ]; then
        if GNUPGHOME="$GPG_CAIS" gpg --batch --verify "$f" >/dev/null 2>&1; then echo ok > "$f.verif"; else echo falha > "$f.verif"; fi
      else
        echo sem-gpg > "$f.verif"
      fi
    fi
  done < "$CACHE/cais/links.txt"
  echo "== CTIR Gov (alertas; páginas do GSI, sem feed)"
  # Lista do ano corrente (20 por página) e cada alerta novo; os da primeira página são relidos uma vez por dia
  # (o CTIR atualiza alertas). Pausa de 1 s entre pedidos; na primeira falha segue com o cache.
  mkdir -p "$CACHE/ctir"
  ano=$(date +%Y)
  : > "$CACHE/ctir/links.tmp"
  for off in 0 20 40 60 80 100 120 140 160 180; do
    pag="$CACHE/ctir/lista-$ano-$off.html"
    if ! curl -fsSL --compressed -m 30 -A "radar-vulnerabilidades (+https://github.com/edcarllos/radar-vulnerabilidades)" \
         -o "$pag.tmp" "https://www.gov.br/gsi/pt-br/assuntos/ctir/alertas/$ano?b_start:int=$off" 2>/dev/null; then
      rm -f "$pag.tmp"; echo "AVISO: lista de alertas do CTIR Gov indisponível agora (página $off); seguindo com o cache."; echo "CTIR Gov" >> "$CACHE/falhas.txt"; break
    fi
    mv "$pag.tmp" "$pag"
    novos=$(python3 -I "$PROJ/ferramentas/nacionais.py" links-ctir "$pag" | grep -vxF -f "$CACHE/ctir/links.tmp" || true)
    [ -n "$novos" ] || break
    printf '%s\n' "$novos" >> "$CACHE/ctir/links.tmp"
    sleep 1
  done
  [ -s "$CACHE/ctir/links.tmp" ] && mv "$CACHE/ctir/links.tmp" "$CACHE/ctir/links.txt" || rm -f "$CACHE/ctir/links.tmp"
  n=0; falhas=0
  while read -r u; do
    [[ "$u" =~ ^https://www\.gov\.br/gsi/pt-br/assuntos/ctir/alertas/[0-9]{4}/alerta-[0-9]{1,4}-[0-9]{4}$ ]] || continue
    n=$((n + 1))
    f="$CACHE/ctir/$(basename "$u").html"
    # Link quebrado na lista do GSI (404): tenta de novo só no dia seguinte.
    [ -e "$f.falhou" ] && [ -z "$(find "$f.falhou" -mmin +1380 2>/dev/null)" ] && continue
    if [ ! -s "$f" ] || { [ "$n" -le 20 ] && [ -n "$(find "$f" -mmin +1380 2>/dev/null)" ]; }; then
      if curl -fsSL --compressed -m 30 -A "radar-vulnerabilidades (+https://github.com/edcarllos/radar-vulnerabilidades)" -o "$f.tmp" "$u" 2>/dev/null; then
        mv "$f.tmp" "$f"; printf '%s\n' "$u" > "$f.url"; rm -f "$f.falhou"; falhas=0
      else
        rm -f "$f.tmp"; touch "$f.falhou"; falhas=$((falhas + 1))
        echo "AVISO: alerta do CTIR Gov indisponível: $u"
        if [ "$falhas" -ge 3 ]; then echo "AVISO: o site do CTIR Gov parece fora do ar; seguindo com o cache."; echo "CTIR Gov" >> "$CACHE/falhas.txt"; break; fi
      fi
      sleep 1
    fi
  done < <(cat "$CACHE/ctir/links.txt" 2>/dev/null)
  echo "== TrueNAS (avisos de segurança, RSS; uma vez por dia)"
  f="$CACHE/truenas.xml"
  if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +1380 2>/dev/null)" ]; then
    curl -fsSL --compressed -m 30 -o "$f.tmp" https://security.truenas.com/index.xml 2>/dev/null && mv "$f.tmp" "$f" \
      || { rm -f "$f.tmp"; echo "AVISO: avisos do TrueNAS indisponíveis agora; seguindo com o cache."; echo "TrueNAS (avisos)" >> "$CACHE/falhas.txt"; }
  fi
  echo "== Ubuntu (USNs recentes)"
  # Se o site da Ubuntu falhar (504, lentidão), para na primeira falha e segue com o cache: não trava a coleta.
  for off in $(seq 0 20 300); do
    if ! curl -fsSL --compressed -m 30 -o "$CACHE/usn/p$off.json.tmp" "https://ubuntu.com/security/notices.json?limit=20&offset=$off&order=newest" 2>/dev/null; then
      rm -f "$CACHE/usn/p$off.json.tmp"
      echo "AVISO: avisos USN da Ubuntu indisponíveis agora (página $off); seguindo com o cache."; echo "Avisos USN" >> "$CACHE/falhas.txt"
      break
    fi
    mv "$CACHE/usn/p$off.json.tmp" "$CACHE/usn/p$off.json"
  done
  echo "== NVD por produto (janela móvel de 90 dias; pausa de ${NVD_PAUSA} s entre consultas)"
  python3 -I "$PROJ/ferramentas/construir_dados.py" --cache "$CACHE" --projeto "$PROJ" --listar-consultas > "$CACHE/consultas-nvd.tsv"
  while IFS=$'\t' read -r arq url; do
    [[ "$arq" =~ ^[a-z0-9-]+__(cpe[0-9]+|palavra)\.json$ ]] || continue
    f="$CACHE/nvd-produtos/$arq"
    if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +600 2>/dev/null)" ]; then
      baixar_nvd "$f" "$url" || echo "falhou consulta NVD: $arq"
      sleep "$NVD_PAUSA"
    fi
  done < "$CACHE/consultas-nvd.tsv"
  echo "== Ubuntu e NVD por CVE"
  python3 -I "$PROJ/ferramentas/construir_dados.py" --cache "$CACHE" --projeto "$PROJ" --listar-cves > "$CACHE/cves.txt"
  # Ubuntu: rebaixa arquivos com mais de 1 dia (8 downloads em paralelo). Antes, testa o site: se não responder,
  # segue com o cache em vez de esperar o tempo limite de centenas de pedidos.
  mkdir -p "$CACHE/ubuntu"
  pend_u="$(while read -r c; do
    [[ "$c" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || continue
    f="$CACHE/ubuntu/$c.json"
    if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +1440 2>/dev/null)" ]; then echo "$c"; fi
  done < "$CACHE/cves.txt")"
  n_u=$(printf '%s' "$pend_u" | grep -c . || true)
  if [ "$n_u" -gt 0 ]; then
    # Teste com um CVE da própria lista (um CVE famoso viria do CDN mesmo com o site fora do ar).
    teste="$(printf '%s\n' "$pend_u" | head -1)"
    if curl -fsS --compressed -m 20 -o /dev/null "https://ubuntu.com/security/cves/$teste.json" 2>/dev/null; then
      echo "Ubuntu por CVE: $n_u a baixar (8 em paralelo, no máximo 10 minutos)."
      printf '%s\n' "$pend_u" | timeout 600 xargs -r -P8 -I{} sh -c 'curl -fsSL --compressed -m 30 -o "$0/ubuntu/{}.json.tmp" "https://ubuntu.com/security/cves/{}.json" 2>/dev/null && mv "$0/ubuntu/{}.json.tmp" "$0/ubuntu/{}.json"; rm -f "$0/ubuntu/{}.json.tmp"' "$CACHE" \
        || echo "AVISO: a Ubuntu demorou demais; os CVEs que faltaram seguem com a cópia do cache."
    else
      echo "AVISO: o site da Ubuntu não respondeu; $n_u CVEs seguem com a cópia do cache (ou sem dados da Ubuntu)."; echo "Ubuntu (páginas de CVE)" >> "$CACHE/falhas.txt"
    fi
  fi
  # NVD: só CVEs ainda sem arquivo ou com mais de 3 dias; limite de 5 req/30 s sem chave. Mostra o progresso.
  mkdir -p "$CACHE/nvd"
  pend_n=()
  while read -r c; do
    [[ "$c" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || continue
    f="$CACHE/nvd/$c.json"
    if [ ! -s "$f" ] || [ -n "$(find "$f" -mmin +4320 2>/dev/null)" ]; then pend_n+=("$c"); fi
  done < <(RADAR_NVD_TODOS="${NVD_CHAVE:+1}" python3 -I - "$CACHE/cves.txt" <<'PY'
import sys
# Prioriza CVEs de itens explorados não cobertos pelo Ubuntu (produtos de fornecedores).
import json, os
cache = os.path.dirname(sys.argv[1])
import glob
ja = set()
for f in glob.glob(os.path.join(cache, "nvd-produtos", "*.json")):
    try:
        for v in json.load(open(f)).get("vulnerabilities", []):
            ja.add(v["cve"]["id"])
    except Exception:
        pass
todos = os.environ.get("RADAR_NVD_TODOS") == "1"  # com chave da NVD: todos (traz o SSVC da CISA)
for c in open(sys.argv[1]).read().split():
    if c in ja:
        continue
    if todos:
        print(c)
        continue
    u = os.path.join(cache, "ubuntu", c + ".json")
    try:
        d = json.load(open(u)); tem = isinstance(d.get("cvss3"), (int, float))
    except Exception:
        tem = False
    if not tem:
        print(c)
PY
)
  echo "NVD por CVE: ${#pend_n[@]} a baixar."
  i=0
  for c in "${pend_n[@]}"; do
    baixar_nvd "$CACHE/nvd/$c.json" "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$c" || true
    sleep "$NVD_PAUSA"
    i=$((i + 1))
    if [ $((i % 100)) = 0 ]; then echo "NVD por CVE: $i de ${#pend_n[@]}"; fi
  done
  # Aba Exploradas: a nota CVSS dos CVEs do KEV vem da NVD. Baixa aos poucos (até 200 por coleta com chave, 20 sem),
  # dos mais recentes para os mais antigos; em poucos dias o catálogo inteiro está no cache.
  lote=$([ -n "$NVD_CHAVE" ] && echo 200 || echo 20)
  mapfile -t pend_k < <(python3 -I - "$CACHE" "$lote" <<'PY'
import json, os, re, sys
cache, lote = sys.argv[1], int(sys.argv[2])
try:
    k = json.load(open(os.path.join(cache, "kev.json")))["vulnerabilities"]
except Exception:
    k = []
k.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
n = 0
for v in k:
    c = v.get("cveID", "")
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", c) and not os.path.exists(os.path.join(cache, "nvd", c + ".json")):
        print(c)
        n += 1
        if n >= lote:
            break
PY
)
  if [ "${#pend_k[@]}" -gt 0 ]; then
    echo "== NVD para o catálogo KEV: ${#pend_k[@]} nesta coleta"
    for c in "${pend_k[@]}"; do
      baixar_nvd "$CACHE/nvd/$c.json" "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$c" || true
      sleep "$NVD_PAUSA"
    done
  fi
fi

if [ "${1:-}" = "--so-baixar" ]; then echo "== Download concluído (sem construir)"; exit 0; fi
echo "== Construindo site/vulns.json"
python3 -I "$PROJ/ferramentas/construir_dados.py" --cache "$CACHE" --projeto "$PROJ"
echo "== Gerando painel e scripts"
node "$PROJ/ferramentas/build.mjs"
