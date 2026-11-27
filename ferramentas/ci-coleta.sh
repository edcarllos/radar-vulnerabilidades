#!/usr/bin/env bash
# Radar de Vulnerabilidades: coleta pública (F19), chamada pelo GitHub Actions (.github/workflows/coleta.yml).
# Pode rodar também num contêiner ou na sua máquina, dentro de um clone do repositório.
#
# Uso: bash ferramentas/ci-coleta.sh SAIDA
#   1. restaura o estado (vulns.json e coletas.json da coleta anterior) do branch "dados" do remoto origin;
#      sem estado, PARA com erro, a menos que PRIMEIRA_COLETA=1 (assim nenhuma falha zera as datas e o histórico);
#   2. coleta as fontes oficiais e constrói o painel em modo público (RADAR_PUBLICO=1);
#   3. monta o site em SAIDA (ferramentas/montar-publico.sh, que valida sintaxe, somas e assinatura);
#   4. grava o novo estado no branch "dados" (um commit por coleta).
#
# Variáveis:
#   RADAR_REPO        dono/nome no GitHub (links da página)        RADAR_SITE_URL  endereço público (feed RSS)
#   NVD_API_KEY       chave da API da NVD (segredo; opcional, mas sem ela a coleta é muito mais lenta)
#   RADAR_GPG_PRIVADA chave privada (armored, sem senha) que assina scripts/SHA256SUMS (segredo; opcional)
#   PRIMEIRA_COLETA=1 começar sem estado anterior (só na primeira vez)
#   RENOVAR_CACHE=1   apagar antes as cópias que o cache reaproveita (OVAL, EPSS, Ubuntu CVE Tracker, NVD por produto)
#   ESTADO_BRANCH     branch do estado (padrão: dados)          SALVAR_ESTADO=0  não grava o estado (testes)
#   CI_SEM_REDE=1     só para testes: reconstrói com o cache, sem baixar nada
set -euo pipefail
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
SAIDA="${1:?informe a pasta de saída do site}"
cd "$PROJ"
export RADAR_CACHE="${RADAR_CACHE:-$HOME/.cache/radar-vulnerabilidades}"
export RADAR_PUBLICO=1 RADAR_REPO="${RADAR_REPO:-}"
BRANCH="${ESTADO_BRANCH:-dados}"
falha() { echo "::error::$*" >&2; echo "FALHA: $*" >&2; exit 1; }
valido() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if isinstance(d,(dict,list)) and d else 1)' "$1" 2>/dev/null; }

# 1. Estado anterior
mkdir -p site
rm -f site/vulns.json site/coletas.json
PAI=""
if git fetch -q --depth 1 origin "refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" 2>/dev/null; then
  PAI="$(git rev-parse "refs/remotes/origin/$BRANCH")"
  git show "$PAI:vulns.json" > site/vulns.json && git show "$PAI:coletas.json" > site/coletas.json \
    || falha "o branch $BRANCH não tem vulns.json e coletas.json."
  valido site/vulns.json && valido site/coletas.json || falha "estado do branch $BRANCH inválido (JSON)."
  echo "Estado restaurado de $BRANCH (${PAI:0:12}): $(python3 -I -c 'import json;print(len(json.load(open("site/coletas.json"))))') coletas anteriores."
elif [ "${PRIMEIRA_COLETA:-0}" = 1 ]; then
  rm -f site/vulns.json site/coletas.json
  echo "Primeira coleta: começando sem estado anterior."
else
  falha "não foi possível ler o branch '$BRANCH' com o estado da coleta anterior. Se esta é a primeira coleta, rode com PRIMEIRA_COLETA=1 (no GitHub: Run workflow, marcando 'Primeira coleta')."
fi

# 2. Cache e assinatura
mkdir -p "$RADAR_CACHE"
if [ "${RENOVAR_CACHE:-0}" = 1 ]; then
  rm -rf "$RADAR_CACHE/oval" "$RADAR_CACHE/epss.csv.gz" "$RADAR_CACHE/uct.tsv" "$RADAR_CACHE/nvd-produtos"
  echo "Cache renovado: OVAL, EPSS, Ubuntu CVE Tracker e NVD por produto serão baixados de novo."
fi
if [ -n "${RADAR_GPG_PRIVADA:-}" ]; then
  GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; chmod 700 "$GNUPGHOME"
  printf '%s\n' "$RADAR_GPG_PRIVADA" | gpg --batch --quiet --import 2>/dev/null || falha "não foi possível importar RADAR_GPG_PRIVADA."
  RADAR_GPG_CHAVE="$(gpg --batch --list-secret-keys --with-colons | awk -F: '$1=="fpr"{print $10; exit}')"
  [ -n "$RADAR_GPG_CHAVE" ] || falha "RADAR_GPG_PRIVADA não tem chave secreta."
  export RADAR_GPG_CHAVE
  echo "Assinatura com a chave $RADAR_GPG_CHAVE."
fi
unset RADAR_GPG_PRIVADA

# 3. Coleta, construção e montagem
log="$(mktemp)"
if [ "${CI_SEM_REDE:-0}" = 1 ]; then
  bash ferramentas/coletar.sh --sem-rede 2>&1 | tee "$log"
else
  bash ferramentas/coletar.sh 2>&1 | tee "$log"
fi
grep -q "^ERRO:" "$log" && falha "construir_dados.py informou ERRO (veja o log acima)."
grep -Eq "[1-9][0-9]* descartadas|AVISO: linha descartada" "$log" && falha "o gerador descartou linhas de dados."
grep -q "modo público" "$log" || falha "o painel não foi construído em modo público."
bash ferramentas/montar-publico.sh "$SAIDA" "${RADAR_SITE_URL:-}"

# 4. Novo estado no branch de dados (um commit por coleta, sem mexer no branch principal)
if [ "${SALVAR_ESTADO:-1}" = 1 ]; then
  export GIT_AUTHOR_NAME="github-actions[bot]" GIT_AUTHOR_EMAIL="41898282+github-actions[bot]@users.noreply.github.com"
  export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
  leia="$(mktemp)"
  printf '%s\n' "Estado da coleta pública do Radar, gravado pelo GitHub Actions a cada coleta." \
    "vulns.json e coletas.json da última coleta: guardam as datas de primeira coleta e o histórico." \
    "Não edite à mão." > "$leia"
  arvore="$(printf '100644 blob %s\tLEIA-ME.txt\n100644 blob %s\tcoletas.json\n100644 blob %s\tvulns.json\n' \
    "$(git hash-object -w "$leia")" "$(git hash-object -w site/coletas.json)" "$(git hash-object -w site/vulns.json)" | git mktree)"
  commit="$(git commit-tree "$arvore" ${PAI:+-p "$PAI"} -m "Coleta $(python3 -I -c 'import json;print(json.load(open("site/vulns.json"))["coleta"]["id"])')")"
  git push -q origin "$commit:refs/heads/$BRANCH" || falha "não foi possível gravar o estado no branch $BRANCH."
  echo "Estado gravado em $BRANCH (${commit:0:12})."
fi
