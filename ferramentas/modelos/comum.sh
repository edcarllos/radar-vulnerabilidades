# ---------------------------------------------------------------------------
# Radar de Vulnerabilidades: funções comuns
# Dados coletados em @@COLETA@@ (catálogo KEV @@KEV@@). Script gerado em @@GERADO@@.
# Distros cobertas: @@RELEASES_ROTULOS@@
# Itens incluídos: @@QTD_ITENS@@
# ---------------------------------------------------------------------------
RADAR_COLETA='@@COLETA@@'
RADAR_GERADO='@@GERADO@@'
RADAR_RELEASES='@@RELEASES@@'
export LC_ALL=C.UTF-8 2>/dev/null || export LC_ALL=C

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_VERM=$'\e[31m'; C_AMAR=$'\e[33m'; C_VERD=$'\e[32m'; C_AZUL=$'\e[36m'; C_NEG=$'\e[1m'; C_FIM=$'\e[0m'
else
  C_VERM=''; C_AMAR=''; C_VERD=''; C_AZUL=''; C_NEG=''; C_FIM=''
fi

radar_release() {
  local id="" ver=""
  local osr="${RADAR_OS_RELEASE:-/etc/os-release}"
  if [ -r "$osr" ]; then
    id=$(awk -F= '$1=="ID" {gsub(/"/, "", $2); print $2; exit}' "$osr")
    ver=$(awk -F= '$1=="VERSION_ID" {gsub(/"/, "", $2); print $2; exit}' "$osr")
  fi
  case "$id:$ver" in
    debian:12) echo deb12 ;;
    debian:13) echo deb13 ;;
    ubuntu:22.04) echo u2204 ;;
    ubuntu:24.04) echo u2404 ;;
    ubuntu:26.04) echo u2604 ;;
    *) echo "" ;;
  esac
}

radar_rotulo() {
  case "$1" in
    deb12) echo "Debian 12 (bookworm)" ;;
    deb13) echo "Debian 13 (trixie)" ;;
    u2204) echo "Ubuntu 22.04 LTS (jammy)" ;;
    u2404) echo "Ubuntu 24.04 LTS (noble)" ;;
    u2604) echo "Ubuntu 26.04 LTS (resolute)" ;;
    *) echo "$1" ;;
  esac
}

radar_codinome() {
  case "$1" in deb12) echo bookworm ;; deb13) echo trixie ;; u2204) echo jammy ;; u2404) echo noble ;; u2604) echo resolute ;; esac
}

radar_checar_release() {
  REL=$(radar_release)
  if [ -z "$REL" ]; then
    echo "${C_VERM}Distribuição não suportada.${C_FIM} Este script cobre Debian 12/13 e Ubuntu 22.04/24.04/26.04."
    exit 2
  fi
  case " $RADAR_RELEASES " in
    *" $REL "*) ;;
    *)
      echo "${C_VERM}Este script foi gerado para:${C_FIM} $RADAR_RELEASES"
      echo "Este host é $(radar_rotulo "$REL"). Gere o script de novo no painel incluindo esta versão."
      exit 2 ;;
  esac
}

radar_idade_dados() {
  local agora coleta
  agora=$(date +%s)
  coleta=$(date -d "$RADAR_COLETA" +%s 2>/dev/null || echo "$agora")
  RADAR_IDADE=$(( (agora - coleta) / 86400 ))
  if [ "$RADAR_IDADE" -gt 7 ]; then
    echo "${C_AMAR}Atenção: os dados deste script foram coletados há $RADAR_IDADE dias ($RADAR_COLETA). Gere de novo no painel para ter avisos recentes.${C_FIM}"
  fi
}

radar_em_conteiner() {
  if [ -f /.dockerenv ] || [ -f /run/.containerenv ]; then return 0; fi
  if command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt -cq 2>/dev/null; then return 0; fi
  return 1
}

# Lista de pacotes instalados: pacote<TAB>versão<TAB>fonte<TAB>versão-da-fonte
radar_carregar_dpkg() {
  if [ -n "${RADAR_DPKG_STATUS:-}" ]; then RADAR_DPKG=$(radar_dpkg_de_status "$RADAR_DPKG_STATUS"); return; fi
  # shellcheck disable=SC2016
  RADAR_DPKG=$(dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' 2>/dev/null \
    | awk -F'\t' '$1 ~ /^ii/ {print $2"\t"$3"\t"$4"\t"$5}')
}

# F12: mesma lista, lida do /var/lib/dpkg/status de uma imagem (sem executar nada dela).
radar_dpkg_de_status() {
  awk '
    function fim() {
      if (p != "" && st ~ /install ok installed/) {
        b = (ma == "same" && ar != "") ? p ":" ar : p
        s = (src == "") ? p : src; sv = (srcv == "") ? v : srcv
        print b "\t" v "\t" s "\t" sv
      }
      p = st = ar = ma = v = src = srcv = ""
    }
    /^$/ { fim(); next }
    /^Package: / { p = $2 }
    /^Status: / { st = substr($0, 9) }
    /^Architecture: / { ar = $2 }
    /^Multi-Arch: / { ma = $2 }
    /^Version: / { v = $2 }
    /^Source: / { src = $2; if (match($0, /\(([^)]+)\)/)) srcv = substr($0, RSTART + 1, RLENGTH - 2) }
    END { fim() }
  ' "$1"
}

# F12: extrai status do dpkg e os-release de uma imagem Docker/Podman. O contêiner é só criado, nunca iniciado.
radar_extrair_imagem() { # imagem pasta
  local img="$1" dir="$2" eng="" cid
  if command -v docker >/dev/null 2>&1; then eng=docker; elif command -v podman >/dev/null 2>&1; then eng=podman; fi
  [ -n "$eng" ] || { echo "Nem docker nem podman encontrados."; return 2; }
  cid=$("$eng" create --entrypoint /radar-nao-executa "$img" 2>/dev/null) || { echo "Não foi possível usar a imagem $img (nome certo? precisa de permissão no $eng)."; return 2; }
  "$eng" cp "$cid:/var/lib/dpkg/status" "$dir/status" >/dev/null 2>&1
  "$eng" cp "$cid:/usr/lib/os-release" "$dir/os-release" >/dev/null 2>&1 || "$eng" cp "$cid:/etc/os-release" "$dir/os-release" >/dev/null 2>&1
  [ -L "$dir/os-release" ] && rm -f "$dir/os-release" && "$eng" cp "$cid:/etc/os-release" "$dir/os-release" >/dev/null 2>&1
  "$eng" rm "$cid" >/dev/null 2>&1
  [ -s "$dir/os-release" ] && [ ! -L "$dir/os-release" ] || { echo "A imagem $img não tem os-release legível."; return 2; }
  [ -s "$dir/status" ] || { echo "A imagem $img não usa dpkg (Alpine, distroless ou RPM): fora do escopo do Radar."; return 2; }
  return 0
}

radar_nome() { if [ -n "${RADAR_IMAGEM:-}" ]; then printf 'imagem:%s' "$RADAR_IMAGEM"; else hostname; fi; }

# Binários instalados de um pacote-fonte: pacote<TAB>versão<TAB>versão-da-fonte
radar_binarios_da_fonte() {
  printf '%s\n' "$RADAR_DPKG" | awk -F'\t' -v s="$1" 'NF>=4 && $3==s {print $1"\t"$2"\t"$4}'
}

radar_versao_instalada() { # aceita nome com ou sem :arquitetura
  printf '%s\n' "$RADAR_DPKG" | awk -F'\t' -v p="$1" '$1==p || index($1, p":")==1 {print $2; exit}'
}
RS=$'\x1f'   # separador de campos interno (não é espaço, então campos vazios não somem)

# Build de repositório de terceiros (Sury, PPA, nginx.org, backports): a tabela da distro não vale.
radar_externo() {
  case "$1" in
    *sury*|*+debian1[0-9]~*|*~bpo*|*ppa*) return 0 ;;
    *~bookworm|*~trixie|*~jammy|*~noble|*~resolute) return 0 ;;
  esac
  return 1
}

radar_upstream() {
  local v="${1#*:}"
  printf '%s' "${v%%-*}"
}

radar_ramo() { printf '%s' "$1" | cut -d. -f1,2; }

# Compara versão de aplicação com mínimos por ramo. Saída: OK | VULNERAVEL | VERIFICAR
radar_cmp_ramo() {
  local v="$1" lista="$2" estrito="$3" m menor="" maior="" ramo_v
  local -a mins
  ramo_v=$(radar_ramo "$v")
  IFS=',' read -r -a mins <<< "$lista"
  for m in "${mins[@]}"; do
    if [ "$(radar_ramo "$m")" = "$ramo_v" ]; then
      if dpkg --compare-versions "$v" lt "$m"; then echo VULNERAVEL; else echo OK; fi
      return
    fi
    if [ -z "$menor" ] || dpkg --compare-versions "$m" lt "$menor"; then menor="$m"; fi
    if [ -z "$maior" ] || dpkg --compare-versions "$m" gt "$maior"; then maior="$m"; fi
  done
  if [ -n "$maior" ] && dpkg --compare-versions "$v" gt "$maior"; then echo OK; return; fi
  if [ "$estrito" = "derivado" ]; then
    # Projetos que numeram correções no segundo dígito (DSpace 8.1 -> 8.4): compara pela mesma versão major.
    local major="${v%%.*}" alvo=""
    for m in "${mins[@]}"; do
      [ "${m%%.*}" = "$major" ] || continue
      if [ -z "$alvo" ] || dpkg --compare-versions "$m" lt "$alvo"; then alvo="$m"; fi
    done
    if [ -n "$alvo" ]; then
      if dpkg --compare-versions "$v" lt "$alvo"; then echo VULNERAVEL; else echo OK; fi
      return
    fi
  fi
  if [ "$estrito" = "estrito" ]; then echo VULNERAVEL; else echo VERIFICAR; fi
}

radar_dados() {
  cat <<'RADAR_DADOS_FIM'
@@DADOS@@
RADAR_DADOS_FIM
}

radar_textos() {
  cat <<'RADAR_TEXTOS_FIM'
@@TEXTOS@@
RADAR_TEXTOS_FIM
}

# Linhas de dados desta versão (e as válidas para todas: REL='*')
radar_linhas() {
  radar_dados | awk -F'|' -v r="$REL" '$1==r || $1=="*"'
}

radar_texto() { # id tipo -> texto
  radar_textos | awk -F'|' -v i="$1" -v t="$2" '$1==i && $2==t {sub(/^[^|]*\|[^|]*\|/, ""); print; exit}'
}

# Kernel: compara o pacote do kernel em execução com a versão corrigida.
# Saída: STATUS<TAB>instalado<TAB>nota
radar_checar_kernel() {
  local fixo="$1" run pv novo
  run=$(uname -r)
  if radar_em_conteiner; then
    printf 'VERIFICAR%s%s%s%s\n' "$RS" "$run" "$RS" "contêiner: o kernel é o do host"
    return
  fi
  pv=$(radar_versao_instalada "linux-image-$run")
  if [ -z "$pv" ]; then
    printf 'VERIFICAR%s%s%s%s\n' "$RS" "$run" "$RS" "kernel em execução não veio de pacote da distro"
    return
  fi
  if [ "$(radar_ramo "$pv")" != "$(radar_ramo "$fixo")" ]; then
    printf 'VERIFICAR%s%s%s%s\n' "$RS" "$pv" "$RS" "série de kernel diferente (HWE/backport): consulte o aviso"
    return
  fi
  if dpkg --compare-versions "$pv" ge "$fixo"; then
    printf 'OK%s%s%s\n' "$RS" "$pv" "$RS"
    return
  fi
  novo=$(printf '%s\n' "$RADAR_DPKG" | awk -F'\t' '$1 ~ /^linux-image-[0-9]/ {print $2}' | sort -V | tail -n1)
  if [ -n "$novo" ] && dpkg --compare-versions "$novo" ge "$fixo"; then
    printf 'REINICIAR%s%s%s%s\n' "$RS" "$pv" "$RS" "kernel $novo já instalado: falta reiniciar"
  else
    printf 'VULNERAVEL%s%s%s\n' "$RS" "$pv" "$RS"
  fi
}

# Pacote-fonte: avalia todos os binários instalados daquela fonte.
# Saída: STATUS<TAB>instalado<TAB>nota<TAB>binários
radar_checar_fonte() {
  local fonte="$1" estado="$2" fixo="$3" ups="$4" linhas bins="" pior="OK" nota="" p v sv st u sv_ult=""
  linhas=$(radar_binarios_da_fonte "$fonte")
  if [ -z "$linhas" ]; then
    printf 'AUSENTE%s-%s%s\n' "$RS" "$RS" "$RS"
    return
  fi
  while IFS=$'\t' read -r p v sv; do
    [ -z "$p" ] && continue
    case " $bins " in *" $p "*) ;; *) bins="$bins $p" ;; esac
    st=OK
    if radar_externo "$v"; then
      if [ "$ups" != "-" ] && [ -n "$ups" ]; then
        u=$(radar_upstream "$sv")
        st=$(radar_cmp_ramo "$u" "$ups" estrito)
        nota="repositório externo ($v): comparado com o upstream"
      else
        st=VERIFICAR
        nota="repositório externo ($v): a tabela da distro não se aplica"
      fi
    else
      case "$estado" in
        corrigido|pro)
          if dpkg --compare-versions "$sv" lt "$fixo"; then st=VULNERAVEL; fi
          [ "$estado" = pro ] && [ "$st" = VULNERAVEL ] && nota="correção só no Ubuntu Pro (ESM)" ;;
        parcial)
          if dpkg --compare-versions "$sv" lt "$fixo"; then st=VULNERAVEL; else st=ATENCAO; nota="atualizado, mas há CVEs ainda sem correção na distro"; fi ;;
        sem_correcao) st=SEM_CORRECAO; nota="distro ainda sem correção: aplique a mitigação" ;;
        em_triagem) st=VERIFICAR; nota="a distro ainda está avaliando estes CVEs (sem correção publicada)" ;;
        nao_afetado) st=NAO_AFETADO ;;
        nao_empacotado) st=VERIFICAR; nota="pacote não rastreado nesta versão da distro" ;;
        *) st=VERIFICAR; nota="sem dados oficiais para esta versão na coleta" ;;
      esac
    fi
    pior=$(radar_pior "$pior" "$st")
    sv_ult="$sv"
  done <<< "$linhas"
  printf '%s%s%s%s%s%s%s\n' "$pior" "$RS" "${sv_ult:-?}" "$RS" "$nota" "$RS" "${bins# }"
}

# PHP instalado de outra fonte (pacote de outra versão da distro, PPA/Sury) que não tem linha para esta versão.
# Saída por fonte: fonte RS status RS instalado RS nota RS binários RS mínimo
radar_php_extras() {
  local id="$1" ups="$2" principal fonte refv refaviso linhas st sv v nota bins p
  principal=$(radar_linhas | awk -F'|' -v i="$id" '$2==i && $3=="src" {print $4; exit}')
  for fonte in $(printf '%s\n' "$RADAR_DPKG" | awk -F'\t' '$3 ~ /^php[0-9]+\.[0-9]+$/ {print $3}' | sort -u); do
    [ "$fonte" = "$principal" ] && continue
    linhas=$(radar_binarios_da_fonte "$fonte")
    [ -z "$linhas" ] && continue
    IFS=$'\t' read -r p v sv <<< "$(printf '%s\n' "$linhas" | head -n1)"
    bins=$(printf '%s\n' "$linhas" | awk -F'\t' '{print $1}' | sort -u | tr '\n' ' ')
    refv=$(radar_dados | awk -F'|' -v i="$id" -v f="$fonte" '$2==i && $3=="ref" && $4==f {print $6; exit}')
    refaviso=$(radar_dados | awk -F'|' -v i="$id" -v f="$fonte" '$2==i && $3=="ref" && $4==f {print $8; exit}')
    if [ -n "$refv" ] && ! radar_externo "$v"; then
      if dpkg --compare-versions "$sv" lt "$refv"; then st=VULNERAVEL; else st=OK; fi
      nota="$fonte veio de outra versão da distro; comparado com ${refaviso:-a correção} daquela versão"
    else
      st=$(radar_cmp_ramo "$(radar_upstream "$sv")" "$ups" estrito)
      refv="upstream $ups"
      nota="$fonte de repositório externo ou sem pacote oficial correspondente: comparado com o upstream"
    fi
    printf '%s%s%s%s%s%s%s%s%s%s%s\n' "$fonte" "$RS" "$st" "$RS" "$sv" "$RS" "$nota" "$RS" "${bins% }" "$RS" "$refv"
  done
}

radar_rot_decisao() {
  case "$1" in
    agir_agora) echo "Agir agora" ;; agir_em_breve) echo "Agir em breve" ;; acompanhar_de_perto) echo "Acompanhar de perto" ;;
    acompanhar) echo "Acompanhar" ;; nao_se_aplica) echo "Não se aplica" ;; *) echo "$1" ;;
  esac
}

# Texto seguro dentro de aspas JSON (os campos já vêm sem quebras de linha).
radar_json_txt() {
  local s="$1"
  s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\t'/ }; s=${s//$'\r'/ }; s=${s//$'\n'/ }
  printf '"%s"' "$s"
}

radar_peso() {
  case "$1" in
    VULNERAVEL) echo 7 ;; SEM_CORRECAO) echo 6 ;; REINICIAR) echo 5 ;; VERIFICAR) echo 4 ;;
    ATENCAO) echo 3 ;; OK) echo 2 ;; NAO_AFETADO) echo 1 ;; *) echo 0 ;;
  esac
}
radar_pior() { if [ "$(radar_peso "$2")" -gt "$(radar_peso "$1")" ]; then echo "$2"; else echo "$1"; fi; }

radar_cor() {
  case "$1" in
    VULNERAVEL|SEM_CORRECAO) printf '%s' "$C_VERM" ;;
    REINICIAR|VERIFICAR|ATENCAO) printf '%s' "$C_AMAR" ;;
    OK|NAO_AFETADO) printf '%s' "$C_VERD" ;;
    *) printf '' ;;
  esac
}
radar_rot_status() {
  case "$1" in
    VULNERAVEL) echo "VULNERÁVEL" ;; SEM_CORRECAO) echo "SEM CORREÇÃO" ;; REINICIAR) echo "REINICIAR" ;;
    VERIFICAR) echo "VERIFICAR" ;; ATENCAO) echo "ATENÇÃO" ;; OK) echo "OK" ;; NAO_AFETADO) echo "NÃO AFETADO" ;;
    AUSENTE) echo "NÃO INSTALADO" ;; *) echo "$1" ;;
  esac
}

# Aplicações web: procura instalações e lê a versão.
RADAR_DIRS_WEB="${RADAR_DIRS_WEB:-/var/www /srv /opt /usr/share}"
radar_achar_app() { # tipo -> linhas "caminho<TAB>versão"
  local tipo="$1" d f v
  case "$tipo" in
    drupal)
      for d in $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 7 -path '*/core/lib/Drupal.php' 2>/dev/null
      done | while read -r f; do
        v=$(grep -oE "const VERSION = '[0-9][0-9.]*'" "$f" 2>/dev/null | grep -oE "[0-9][0-9.]*" | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "${f%/core/lib/Drupal.php}" "$v"
      done ;;
    wordpress)
      for d in $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 6 -path '*/wp-includes/version.php' 2>/dev/null
      done | while read -r f; do
        v=$(grep -oE "^\\\$wp_version = '[0-9][0-9.]*'" "$f" 2>/dev/null | grep -oE "[0-9][0-9.]*" | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "${f%/wp-includes/version.php}" "$v"
      done ;;
    gitlab)
      f=/opt/gitlab/embedded/service/gitlab-rails/VERSION
      if [ -r "$f" ]; then printf '%s\t%s\n' "/opt/gitlab" "$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' "$f" | head -n1)"; fi ;;
    moodle)
      for d in $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 7 -path '*/lib/moodlelib.php' 2>/dev/null
      done | while read -r f; do
        r="${f%/lib/moodlelib.php}"
        v=$(grep -oE "^\\\$release *= *'[0-9]+(\.[0-9]+){1,3}" "$r/version.php" 2>/dev/null | grep -oE "[0-9]+(\.[0-9]+){1,3}" | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "$r" "$v"
      done ;;
    glpi)
      for d in $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 6 -path '*/inc/define.php' 2>/dev/null
      done | while read -r f; do
        v=$(grep -oE "GLPI_VERSION'?\"?, *'[0-9]+(\.[0-9]+){1,3}" "$f" 2>/dev/null | grep -oE "[0-9]+(\.[0-9]+){1,3}" | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "${f%/inc/define.php}" "$v"
      done ;;
    ojs)
      for d in $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 7 -path '*/dbscripts/xml/version.xml' 2>/dev/null
      done | while read -r f; do
        grep -q '<application>ojs2</application>' "$f" 2>/dev/null || continue
        v=$(grep -oE '<release>[0-9.]+' "$f" | grep -oE '[0-9]+(\.[0-9]+){1,3}' | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "${f%/dbscripts/xml/version.xml}" "$v"
      done ;;
    nextcloud)
      for d in $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 6 -name occ -path '*/occ' 2>/dev/null
      done | while read -r f; do
        r="${f%/occ}"
        v=$(grep -oE "OC_VersionString *= *'[0-9]+(\.[0-9]+){1,3}" "$r/version.php" 2>/dev/null | grep -oE "[0-9]+(\.[0-9]+){1,3}" | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "$r" "$v"
      done ;;
    keycloak)
      for d in /opt $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 4 -name version.txt -path '*keycloak*' 2>/dev/null
      done | sort -u | while read -r f; do
        v=$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "$f" | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "${f%/version.txt}" "$v"
      done ;;
    dspace)
      for d in /dspace /opt $RADAR_DIRS_WEB; do
        [ -d "$d" ] || continue
        timeout 60 find "$d" -xdev -maxdepth 4 -name 'dspace-api-*.jar' 2>/dev/null
      done | sort -u | while read -r f; do
        v=$(basename "$f" | grep -oE '[0-9]+(\.[0-9]+){1,3}' | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "${f%/lib/*}" "$v"
      done ;;
    freeswitch)
      if command -v freeswitch >/dev/null 2>&1; then
        v=$(freeswitch -version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
        [ -n "$v" ] && printf '%s\t%s\n' "$(command -v freeswitch)" "$v"
      fi
      v=$(radar_versao_instalada bbb-freeswitch-core)
      [ -n "$v" ] && printf '%s\t%s\n' "bbb-freeswitch-core" "$(radar_upstream "$v")" ;;
  esac
}

# Plugin do Moodle instalado: caminho<TAB>release
radar_plugin_moodle() { # raiz componente
  local raiz="$1" comp="$2" tipo nome dir rel
  tipo="${comp%%_*}"; nome="${comp#*_}"
  case "$tipo" in
    block) dir=blocks ;; mod) dir=mod ;; local) dir=local ;; auth) dir=auth ;; tool) dir=admin/tool ;;
    report) dir=report ;; filter) dir=filter ;; theme) dir=theme ;; format) dir=course/format ;;
    qtype) dir=question/type ;; enrol) dir=enrol ;; qbank) dir=question/bank ;; availability) dir=availability/condition ;;
    atto) dir=lib/editor/atto/plugins ;; tiny) dir=lib/editor/tiny/plugins ;; repository) dir=repository ;;
    plagiarism) dir=plagiarism ;; logstore) dir=admin/tool/log/store ;; gradeexport) dir=grade/export ;; quizaccess) dir=mod/quiz/accessrule ;;
    *) return ;;
  esac
  [ -f "$raiz/$dir/$nome/version.php" ] || return
  rel=$(grep -oE "release *= *'[^']{1,40}'" "$raiz/$dir/$nome/version.php" 2>/dev/null | head -n1 | cut -d"'" -f2)
  printf '%s\t%s\n' "$raiz/$dir/$nome" "${rel:-?}"
}

# Processos que carregam arquivos de uma biblioteca (precisa de root para ver todos).
radar_processos_lib() {
  local bin="$1" arqs pid nome
  nome=$(printf '%s\n' "$RADAR_DPKG" | awk -F'\t' -v p="$bin" '$1==p || index($1, p":")==1 {print $1; exit}')
  arqs=$(dpkg -L "${nome:-$bin}" 2>/dev/null | grep -E '\.so(\.|$)' | grep -v '/usr/share/' || true)
  [ -z "$arqs" ] && return
  for pid in /proc/[0-9]*; do
    [ -r "$pid/maps" ] || continue
    if grep -qF -f <(printf '%s\n' "$arqs") "$pid/maps" 2>/dev/null; then
      printf '%s\n' "$(cat "$pid/comm" 2>/dev/null)"
    fi
  done | sort | uniq -c | sort -rn | head -n 12
}
# ---------------------------------------------------------------------------
