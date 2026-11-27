#!/usr/bin/env bash
# Radar de Vulnerabilidades: VERIFICAÇÃO (somente leitura)
# Não precisa de root nem de rede. Como root, também lista processos que usam bibliotecas vulneráveis.
# Uso: bash radar-verificar.sh [--todos] [--csv] [--completo [--dados ARQ] [--nota-minima N]]
#   --todos        mostra também itens OK e não instalados
#   --csv          saída em CSV (separador ;) para planilha ou inventário
#   --registro     CSV com os campos do modelo de norma de gestão de vulnerabilidades do PPSI (identificação, ativo,
#                  severidade, fonte, situação, responsável, prazo sugerido); fica neste servidor, nada é enviado
#   --json         um objeto JSON com resumo e itens (para Zabbix, scripts e a coleta institucional)
#   --json-linhas  um objeto JSON por item em cada linha (para Wazuh e coletores de log)
#   --completo     avalia TODOS os CVEs conhecidos da distro contra os pacotes instalados (precisa de python3).
#                  Sem --dados, baixa as fontes oficiais (Debian Security Tracker ou OVAL+USN da Ubuntu e KEV).
#   --dados ARQ    índice baixado do painel (aba Histórico completo), para servidores sem internet; traz notas CVSS
#   --nota-minima  no modo completo, mostra só CVEs com nota CVSS >= N (os do KEV aparecem sempre)
#   --epss-minimo  no modo completo, mostra só CVEs com probabilidade de exploração (EPSS) >= N% (os do KEV aparecem sempre)
#   --imagem NOME  verifica uma imagem Docker/Podman (Debian ou Ubuntu) em vez deste host: lê só a base do dpkg
#                  e o os-release da imagem, sem executá-la. Kernel, aplicações web e processos ficam de fora.
#                  Combina com --completo, --json e --csv. Precisa de permissão para usar o docker/podman.
#   Modo completo separa: correção disponível, só Ubuntu Pro, confirmado sem correção, adiado/ignorado e em triagem.
#   No Ubuntu, a separação entre confirmado e triagem exige o índice do painel (--dados); sem ele aparecem juntos.
# Saída: 0 = nada vulnerável; 1 = há itens VULNERÁVEL, SEM CORREÇÃO ou REINICIAR; 2 = distro não suportada.
set -u
@@COMUM@@

REGISTRO=0; TODOS=0; CSV=0; JSON=0; JSONL=0; COMPLETO=0; DADOS=""; NOTA_MIN=0; EPSS_MIN=0; RADAR_IMAGEM=""
while [ $# -gt 0 ]; do
  case "$1" in
    --todos) TODOS=1 ;;
    --csv) CSV=1 ;;
    --registro) REGISTRO=1 ;;
    --json) JSON=1 ;;
    --json-linhas) JSONL=1 ;;
    --completo) COMPLETO=1 ;;
    --dados) DADOS="${2:-}"; shift ;;
    --nota-minima) NOTA_MIN="${2:-0}"; shift ;;
    --epss-minimo) EPSS_MIN="${2:-0}"; shift ;;
    --imagem) RADAR_IMAGEM="${2:-}"; shift ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
  esac
  shift
done
[[ "$NOTA_MIN" =~ ^[0-9]+(\.[0-9]+)?$ ]] || NOTA_MIN=0
[[ "$EPSS_MIN" =~ ^[0-9]+(\.[0-9]+)?$ ]] || EPSS_MIN=0

if [ -n "$RADAR_IMAGEM" ]; then
  [[ "$RADAR_IMAGEM" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,200}$ ]] || { echo "Nome de imagem inválido: $RADAR_IMAGEM"; exit 2; }
  command -v dpkg >/dev/null 2>&1 || { echo "Rode --imagem num host Debian ou Ubuntu (a comparação de versões usa o dpkg)."; exit 2; }
  RADAR_TMPI=$(mktemp -d "${TMPDIR:-/tmp}/radar-imagem-XXXXXX")
  trap '[ -n "${RADAR_TMPI:-}" ] && [ -d "$RADAR_TMPI" ] && rm -r -- "$RADAR_TMPI"; [ -n "${TMPC:-}" ] && [ -d "$TMPC" ] && rm -r -- "$TMPC"' EXIT
  radar_extrair_imagem "$RADAR_IMAGEM" "$RADAR_TMPI" || exit 2
  RADAR_OS_RELEASE="$RADAR_TMPI/os-release"; RADAR_DPKG_STATUS="$RADAR_TMPI/status"
fi
QUIETO=0; { [ "$CSV" = 1 ] || [ "$JSON" = 1 ] || [ "$JSONL" = 1 ] || [ "$REGISTRO" = 1 ]; } && QUIETO=1
radar_checar_release
if [ -n "${RADAR_EOL:-}" ] && [ "$QUIETO" = 0 ]; then
  echo "${C_VERM}${C_NEG}Sistema sem suporte.${C_FIM} $RADAR_EOL"
  echo "Só as aplicações web e os itens que não dependem da distro serão conferidos."
  echo
fi
radar_carregar_dpkg
[ "$QUIETO" = 1 ] || {
  echo "${C_NEG}Radar de Vulnerabilidades: verificação${C_FIM}"
  if [ -n "$RADAR_IMAGEM" ]; then echo "Imagem: $RADAR_IMAGEM · $(radar_rotulo "$REL") (kernel, aplicações web e processos não se aplicam)"
  else echo "Host: $(hostname) · $(radar_rotulo "$REL") · kernel $(uname -r)"; fi
  case "$(radar_appliance)" in
    proxmox) echo "${C_AMAR}Proxmox VE: os pacotes Debian são conferidos; o kernel e os pacotes próprios do Proxmox não. Veja os avisos de segurança do Proxmox.${C_FIM}" ;;
    truenas) echo "${C_AMAR}TrueNAS $(head -c 40 /etc/version 2>/dev/null): resultado só informativo. Não corrija com apt; use o atualizador do TrueNAS e confira os avisos em https://security.truenas.com/${C_FIM}" ;;
  esac
  echo "Dados coletados em $RADAR_COLETA · script gerado em $RADAR_GERADO"
  radar_idade_dados
  echo
}

# ---------- modo completo: todo o histórico de CVEs da distro ----------
if [ "$COMPLETO" = 1 ] && [ -n "${RADAR_EOL:-}" ]; then
  echo "Modo completo indisponível: o Radar não tem dados por pacote de sistemas sem suporte. $RADAR_EOL"
  exit 1
fi
if [ "$COMPLETO" = 1 ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    echo "A verificação completa precisa do python3 (apt-get install python3-minimal)."; exit 2
  fi
  TMPC=$(mktemp -d "${TMPDIR:-/tmp}/radar-completo-XXXXXX")
  trap '[ -n "$TMPC" ] && [ -d "$TMPC" ] && rm -r -- "$TMPC"; [ -n "${RADAR_TMPI:-}" ] && [ -d "$RADAR_TMPI" ] && rm -r -- "$RADAR_TMPI"' EXIT
  cat > "$TMPC/completo.py" <<'RADAR_PY_FIM'
@@PY_COMPLETO@@
RADAR_PY_FIM
  COD=$(radar_codinome "$REL")
  if [ -n "$DADOS" ]; then
    [ -r "$DADOS" ] || { echo "Arquivo não encontrado: $DADOS"; exit 2; }
    rel_idx=$(head -n1 "$DADOS" | cut -d'|' -f3)
    if [ "$rel_idx" != "$REL" ]; then
      echo "O índice $DADOS é de $(radar_rotulo "$rel_idx"); este host é $(radar_rotulo "$REL")."; exit 2
    fi
    IDX="$DADOS"
  else
    command -v curl >/dev/null 2>&1 || { echo "Sem curl: use --dados com o índice baixado do painel."; exit 2; }
    [ "$QUIETO" = 1 ] || echo "Baixando dados oficiais de $(radar_rotulo "$REL") (pode levar alguns minutos)..."
    curl -fsSL -m 300 -o "$TMPC/kev.json" https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json || : > "$TMPC/kev.json"
    curl -fsSL -m 300 -o "$TMPC/epss.csv.gz" https://epss.empiricalsecurity.com/epss_scores-current.csv.gz || : > "$TMPC/epss.csv.gz"
    case "$REL" in
      deb*)
        curl -fsSL --compressed -m 600 -o "$TMPC/deb.json" https://security-tracker.debian.org/tracker/data/json || { echo "Falha ao baixar o Debian Security Tracker."; exit 2; }
        [ "$QUIETO" = 1 ] || echo "Processando (usa cerca de 400 MB de memória por alguns segundos)..."
        python3 -I "$TMPC/completo.py" indice --familia debian --codinome "$COD" --fonte "$TMPC/deb.json" --kev "$TMPC/kev.json" --epss "$TMPC/epss.csv.gz" --saida "$TMPC/indice.txt" || exit 2 ;;
      u*)
        curl -fsSL -m 600 -o "$TMPC/oval.xml.bz2" "https://security-metadata.canonical.com/oval/com.ubuntu.$COD.cve.oval.xml.bz2" || { echo "Falha ao baixar o OVAL da Ubuntu."; exit 2; }
        mkdir -p "$TMPC/usn"
        for off in $(seq 0 20 300); do
          curl -fsSL -m 120 -o "$TMPC/usn/p$off.json" "https://ubuntu.com/security/notices.json?limit=20&offset=$off&order=newest" || true
        done
        python3 -I "$TMPC/completo.py" indice --familia ubuntu --codinome "$COD" --fonte "$TMPC/oval.xml.bz2" --kev "$TMPC/kev.json" --epss "$TMPC/epss.csv.gz" --usn "$TMPC/usn" --saida "$TMPC/indice.txt" || exit 2 ;;
    esac
    IDX="$TMPC/indice.txt"
  fi
  KF=""; KV=""
  if [ -z "$RADAR_IMAGEM" ] && ! radar_em_conteiner; then
    KF=$(dpkg-query -W -f='${source:Package}' "linux-image-$(uname -r)" 2>/dev/null || true)
    KV=$(dpkg-query -W -f='${Version}' "linux-image-$(uname -r)" 2>/dev/null || true)
  fi
  OPC=(--indice "$IDX" --minimo-nota "$NOTA_MIN" --epss-minimo "$EPSS_MIN" --kernel-fonte "$KF" --kernel-versao "$KV")
  [ "$CSV" = 1 ] && OPC+=(--csv)
  [ "$JSON" = 1 ] && OPC+=(--json --host "$(radar_nome)")
  [ "$JSONL" = 1 ] && OPC+=(--json-linhas --host "$(radar_nome)")
  [ "$TODOS" = 1 ] && OPC+=(--limite 100000)
  # shellcheck disable=SC2016
  { if [ -n "$RADAR_IMAGEM" ]; then printf '%s\n' "$RADAR_DPKG" | awk -F'\t' 'NF>=4 {print "ii \t"$1"\t"$3"\t"$4}'
    else dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${source:Package}\t${source:Version}\n' 2>/dev/null; fi; } \
    | python3 -I "$TMPC/completo.py" avaliar "${OPC[@]}"
  saida=$?
  if [ "$QUIETO" = 0 ]; then
    echo
    if [ -n "$RADAR_IMAGEM" ]; then echo "Corrija reconstruindo a imagem a partir de uma base atualizada (docker build --pull --no-cache)."
    else echo "Corrija com: sudo apt-get update && sudo apt-get upgrade (ou o radar-corrigir.sh para os itens do Radar)."; fi
  fi
  exit $saida
fi

RESULTADOS=""
registrar() { # status cvss id alvo instalado minimo aviso cves titulo nota decisao binarios
  RESULTADOS="$RESULTADOS$(printf '%s|' "$@")"$'\n'
}

LIBS_ALERTA=""
while IFS='|' read -r rel id tipo alvo estado versao ups aviso cvss cves decisao titulo; do
  [ -z "$id" ] && continue
  if [ -n "$RADAR_IMAGEM" ]; then case "$tipo" in kernel|app|plugin|lib|manual) continue ;; esac; fi
  case "$tipo" in
    src)
      IFS="$RS" read -r st inst nota bins <<< "$(radar_checar_fonte "$alvo" "$estado" "$versao" "$ups")"
      [ "$estado" = nao_verificado ] && [ "$st" = VERIFICAR ] && versao="(sem dados)"
      [ "$estado" = sem_correcao ] && versao="(sem correção)"
      [ "$estado" = em_triagem ] && versao="(em triagem)"
      registrar "$st" "$cvss" "$id" "$alvo" "$inst" "${versao:--}" "$aviso" "$cves" "$titulo" "$nota" "$decisao" "$bins" ;;
    kernel)
      IFS="$RS" read -r st inst nota <<< "$(radar_checar_kernel "$versao")"
      registrar "$st" "$cvss" "$id" "linux" "$inst" "$versao" "$aviso" "$cves" "$titulo" "$nota" "$decisao" ;;
    app)
      achados=$(radar_achar_app "$alvo")
      if [ -z "$achados" ]; then
        registrar "AUSENTE" "$cvss" "$id" "$alvo" "-" "$versao" "" "$cves" "$titulo" "não encontrado em $RADAR_DIRS_WEB" "$decisao"
      else
        while IFS=$'\t' read -r caminho v; do
          [ -z "$v" ] && continue
          if [ "$estado" = info ]; then
            registrar VERIFICAR "$cvss" "$id" "$alvo" "$v" "-" "" "$cves" "$titulo" "$caminho: a NVD ainda não informa versões corrigidas; compare com os CVEs no painel" "$decisao"
            continue
          fi
          st=$(radar_cmp_ramo "$v" "$versao" "$estado")
          nota="$caminho"
          [ "$st" = VERIFICAR ] && nota="$caminho: ramo antigo, confira se é o último release do ramo"
          [ "$estado" = derivado ] && nota="$nota (mínimos derivados das descrições da NVD; confira o aviso do projeto)"
          registrar "$st" "$cvss" "$id" "$alvo" "$v" "$versao" "" "$cves" "$titulo" "$nota" "$decisao"
        done <<< "$achados"
      fi ;;
    plugin)
      [ -z "${RADAR_MOODLES+x}" ] && RADAR_MOODLES=$(radar_achar_app moodle)
      while IFS=$'\t' read -r raiz mv; do
        [ -z "$raiz" ] && continue
        achou=$(radar_plugin_moodle "$raiz" "$alvo")
        [ -z "$achou" ] && continue
        IFS=$'\t' read -r pdir prel <<< "$achou"
        registrar VERIFICAR "$cvss" "$id" "$alvo" "$prel" "-" "" "$cves" "Plugin do Moodle citado em CVE: $alvo" "$pdir: confira no aviso do CVE se a versão instalada é afetada" "$decisao"
      done <<< "$RADAR_MOODLES" ;;
    lib)
      LIBS_ALERTA="$LIBS_ALERTA$id|$alvo"$'\n' ;;
    manual) : ;;
  esac
  if [ "$tipo" = src ] && [ "$ups" != "-" ] && [[ "$alvo" =~ ^php[0-9]+\.[0-9]+$ ]]; then
    while IFS="$RS" read -r fonte st inst nota bins minimo; do
      [ -z "$fonte" ] && continue
      registrar "$st" "$cvss" "$id" "$fonte" "$inst" "$minimo" "" "$cves" "$titulo" "$nota" "$decisao" "$bins"
    done < <(radar_php_extras "$id" "$ups")
  fi
done < <(radar_linhas)

json_item() { # mesmos campos de registrar
  printf '{"status":%s,"decisao":%s,"cvss":%s,"item":%s,"alvo":%s,"instalado":%s,"minimo":%s,"aviso":%s,"cves":%s,"titulo":%s,"nota":%s,"binarios":%s}' \
    "$(radar_json_txt "$1")" "$(radar_json_txt "${11}")" "$(radar_json_txt "$2")" "$(radar_json_txt "$3")" "$(radar_json_txt "$4")" \
    "$(radar_json_txt "$5")" "$(radar_json_txt "$6")" "$(radar_json_txt "$7")" "$(radar_json_txt "$8")" "$(radar_json_txt "$9")" "$(radar_json_txt "${10}")" "$(radar_json_txt "${12:-}")"
}
conta() { printf '%s' "$RESULTADOS" | awk -F'|' -v g="$1" '$1==g {n++} END {print n+0}'; }

if [ "$JSONL" = 1 ]; then
  printf '%s' "$RESULTADOS" | while IFS='|' read -r st cvss id alvo inst minimo aviso cves titulo nota decisao bins; do
    [ -z "$st" ] && continue
    [ "$TODOS" = 0 ] && case "$st" in OK|AUSENTE|NAO_AFETADO) continue ;; esac
    printf '{"radar":"verificacao","host":%s,"distro":"%s","coleta":"%s",' "$(radar_json_txt "$(radar_nome)")" "$REL" "$RADAR_COLETA"
    json_item "$st" "$cvss" "$id" "$alvo" "$inst" "$minimo" "$aviso" "$cves" "$titulo" "$nota" "$decisao" "$bins" | sed 's/^{//'
    echo
  done
elif [ "$JSON" = 1 ]; then
  agir=$(printf '%s' "$RESULTADOS" | awk -F'|' '($1=="VULNERAVEL"||$1=="SEM_CORRECAO"||$1=="REINICIAR") && $11=="agir_agora" {n++} END {print n+0}')
  radar_idade_dados >/dev/null
  printf '{"radar":1,"host":%s,"distro":"%s","kernel":%s,"coleta":"%s","gerado":%s,"idade_dados_dias":%s,' \
    "$(radar_json_txt "$(radar_nome)")" "$REL" "$(radar_json_txt "$( [ -n "$RADAR_IMAGEM" ] && echo - || uname -r)")" "$RADAR_COLETA" "$(radar_json_txt "$RADAR_GERADO")" "${RADAR_IDADE:-0}"
  printf '"resumo":{"vulneravel":%s,"sem_correcao":%s,"reiniciar":%s,"verificar":%s,"atencao":%s,"ok":%s,"nao_afetado":%s,"ausente":%s,"agir_agora":%s},"itens":[' \
    "$(conta VULNERAVEL)" "$(conta SEM_CORRECAO)" "$(conta REINICIAR)" "$(conta VERIFICAR)" "$(conta ATENCAO)" "$(conta OK)" "$(conta NAO_AFETADO)" "$(conta AUSENTE)" "$agir"
  primeiro=1
  while IFS='|' read -r st cvss id alvo inst minimo aviso cves titulo nota decisao bins; do
    [ -z "$st" ] && continue
    [ "$TODOS" = 0 ] && case "$st" in AUSENTE) continue ;; esac
    [ "$primeiro" = 1 ] || printf ','
    primeiro=0
    json_item "$st" "$cvss" "$id" "$alvo" "$inst" "$minimo" "$aviso" "$cves" "$titulo" "$nota" "$decisao" "$bins"
  done <<< "$RESULTADOS"
  printf ']}\n'
elif [ "$REGISTRO" = 1 ]; then
  # Campos do modelo de norma de gestão de vulnerabilidades do PPSI. O prazo é a sugestão do Radar (SSVC), a partir de hoje;
  # ajuste ao prazo definido pelo processo de remediação da instituição (PPSI 7.2 e 7.7).
  hoje=$(date +%F); ativo=$(radar_nome)
  echo "identificacao;ativo;severidade;fonte;situacao;responsavel;prazo_sugerido;data_verificacao;descricao"
  printf '%s' "$RESULTADOS" | while IFS='|' read -r st cvss id alvo inst minimo aviso cves titulo nota decisao bins; do
    [ -z "$st" ] && continue
    [ "$TODOS" = 0 ] && case "$st" in OK|AUSENTE|NAO_AFETADO) continue ;; esac
    case "$st" in
      VULNERAVEL) sit="aberta: correção disponível" ;; SEM_CORRECAO) sit="aberta: sem correção, aplicar mitigação" ;;
      REINICIAR) sit="corrigida: falta reiniciar" ;; VERIFICAR) sit="verificar manualmente" ;; ATENCAO) sit="atenção: correção parcial" ;;
      OK) sit="corrigida" ;; NAO_AFETADO) sit="não afetada" ;; *) sit="$st" ;;
    esac
    case "$decisao" in agir_agora) d=1 ;; agir_em_breve) d=7 ;; acompanhar_de_perto) d=30 ;; acompanhar) d=90 ;; *) d="" ;; esac
    prazo=""; case "$st" in VULNERAVEL|SEM_CORRECAO|REINICIAR|ATENCAO) [ -n "$d" ] && prazo=$(date -d "+$d days" +%F 2>/dev/null || true) ;; esac
    printf '%s;%s;"CVSS %s; %s";%s;%s;;%s;%s;"%s"\n' "$id${cves:+ ($cves)}" "$ativo" "$cvss" "$(radar_rot_decisao "$decisao")" \
      "${aviso:-Radar de Vulnerabilidades, coleta $RADAR_COLETA}" "$sit" "$prazo" "$hoje" "${titulo//\"/\'}: $alvo instalado ${inst:--}, mínimo ${minimo:--}"
  done
elif [ "$CSV" = 1 ]; then
  echo "status;decisao;cvss;item;alvo;instalado;minimo;aviso;cves;titulo;nota"
  printf '%s' "$RESULTADOS" | while IFS='|' read -r st cvss id alvo inst minimo aviso cves titulo nota decisao bins; do
    [ -z "$st" ] && continue
    printf '%s;%s;%s;%s;%s;%s;%s;%s;%s;"%s";"%s"\n' "$st" "$decisao" "$cvss" "$id" "$alvo" "$inst" "$minimo" "$aviso" "$cves" "${titulo//\"/\'}" "${nota//\"/\'}"
  done
else
  for grupo in VULNERAVEL SEM_CORRECAO REINICIAR VERIFICAR ATENCAO OK NAO_AFETADO AUSENTE; do
    linhas=$(printf '%s' "$RESULTADOS" | awk -F'|' -v g="$grupo" '$1==g')
    [ -z "$linhas" ] && continue
    n=$(printf '%s\n' "$linhas" | grep -c .)
    if [ "$TODOS" = 0 ] && { [ "$grupo" = OK ] || [ "$grupo" = AUSENTE ] || [ "$grupo" = NAO_AFETADO ]; }; then
      echo "$(radar_cor "$grupo")$(radar_rot_status "$grupo")${C_FIM}: $n item(ns) (use --todos para listar)"
      continue
    fi
    echo "$(radar_cor "$grupo")${C_NEG}== $(radar_rot_status "$grupo") ($n)${C_FIM}"
    printf '%s\n' "$linhas" | sort -t'|' -k2,2 -gr | while IFS='|' read -r st cvss id alvo inst minimo aviso cves titulo nota decisao bins; do
      printf '  %s[%4s]%s %s%s\n' "$(radar_cor "$st")" "$cvss" "$C_FIM" "$( case "$st" in VULNERAVEL|SEM_CORRECAO|REINICIAR) printf '%s · ' "$(radar_rot_decisao "$decisao")" ;; esac )" "$titulo"
      printf '         %s: instalado %s · mínimo %s%s\n' "$alvo" "$inst" "$minimo" "${aviso:+ ($aviso)}"
      [ -n "$cves" ] && printf '         %s\n' "$cves"
      [ -n "$nota" ] && printf '         %s%s%s\n' "$C_AMAR" "$nota" "$C_FIM"
    done
    echo
  done

  # Bibliotecas: quem depende delas e quais processos as carregam.
  if [ -n "$LIBS_ALERTA" ]; then
    mostrou=0
    while IFS='|' read -r id lib; do
      [ -z "$lib" ] && continue
      st=$(printf '%s' "$RESULTADOS" | awk -F'|' -v i="$id" '$3==i {print $1; exit}')
      case "$st" in VULNERAVEL|SEM_CORRECAO|ATENCAO) ;; *) continue ;; esac
      [ -z "$(radar_versao_instalada "$lib")" ] && continue
      if [ "$mostrou" = 0 ]; then echo "${C_NEG}== Uso das bibliotecas afetadas${C_FIM}"; mostrou=1; fi
      echo "  $lib ($id)"
      deps=$(apt-cache rdepends --installed --no-recommends --no-suggests --no-enhances "$lib" 2>/dev/null | awk 'NR>2 {gsub(/[ |]/,""); print}' | sort -u | head -n 15 | tr '\n' ' ')
      [ -n "$deps" ] && echo "    pacotes que dependem: $deps"
      if [ "$(id -u)" = 0 ]; then
        procs=$(radar_processos_lib "$lib" | awk '{printf "%s(%s) ", $2, $1}')
        [ -n "$procs" ] && echo "    processos usando agora: $procs"
      else
        echo "    (rode como root para listar os processos que usam a biblioteca)"
      fi
    done <<< "$LIBS_ALERTA"
    [ "$mostrou" = 1 ] && echo
  fi

  manuais=""; [ -z "$RADAR_IMAGEM" ] && manuais=$(radar_linhas | awk -F'|' '$3=="manual"')
  if [ -n "$manuais" ]; then
    echo "${C_NEG}== Verificação manual (equipamentos e sistemas fora deste host)${C_FIM}"
    printf '%s\n' "$manuais" | while IFS='|' read -r rel id tipo alvo estado versao ups aviso cvss cves decisao titulo; do
      printf '  [%4s] %s · %s\n' "$cvss" "$(radar_rot_decisao "$decisao")" "$titulo"
      como=$(radar_texto "$id" verificar)
      [ -n "$como" ] && printf '         como verificar: %s\n' "$como"
    done
    echo
  fi

  if [ -z "$RADAR_IMAGEM" ] && command -v needrestart >/dev/null 2>&1 && [ "$(id -u)" = 0 ]; then
    echo "${C_NEG}== Serviços com bibliotecas antigas em memória (needrestart)${C_FIM}"
    needrestart -r l -b 2>/dev/null | grep -E '^NEEDRESTART-(SVC|KSTA)' | sed 's/^/  /'
    echo
  fi
  if [ -n "$RADAR_IMAGEM" ]; then echo "Próximo passo: reconstrua a imagem a partir de uma base atualizada (docker pull da base + docker build --pull --no-cache) e publique de novo."
  else echo "Próximo passo: sudo bash radar-corrigir.sh (pergunta antes de cada ação)."; fi
fi

if printf '%s' "$RESULTADOS" | awk -F'|' '$1=="VULNERAVEL"||$1=="SEM_CORRECAO"||$1=="REINICIAR"{f=1} END{exit !f}'; then
  exit 1
fi
exit 0
