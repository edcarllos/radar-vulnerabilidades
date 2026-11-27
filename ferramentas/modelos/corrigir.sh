#!/usr/bin/env bash
# Radar de Vulnerabilidades: CORREÇÃO PASSO A PASSO
# Pergunta antes de cada ação. Não reinicia o servidor nem serviços sem confirmação.
# Uso: sudo bash radar-corrigir.sh [--simular]
#   --simular  não altera nada: usa apt-get -s e só mostra os comandos (não precisa de root)
# Ao final grava um ponto de restauração em /var/backups/radar-vuln/<data>/ para o radar-rollback.sh.
set -u
@@COMUM@@

SIMULAR=0
for a in "$@"; do
  case "$a" in
    --simular) SIMULAR=1 ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
  esac
done

if [ "$SIMULAR" = 0 ] && [ "$(id -u)" != 0 ]; then
  echo "Rode como root: sudo bash $0   (ou --simular para só ver o que seria feito)"
  exit 2
fi

radar_checar_release
radar_carregar_dpkg

CARIMBO=$(date +%Y%m%d-%H%M%S)
if [ "$SIMULAR" = 1 ]; then
  BACKUP=$(mktemp -d "${TMPDIR:-/tmp}/radar-simulacao-XXXXXX")
else
  BACKUP="/var/backups/radar-vuln/$CARIMBO"
  mkdir -p "$BACKUP"
  chmod 700 "$BACKUP"
fi
LOG="$BACKUP/registro.log"
exec > >(tee -a "$LOG") 2>&1

perguntar() { # texto [padrão s|n] -> 0 se sim
  local r="" padrao="${2:-n}"
  if [ -r /dev/tty ] && { true </dev/tty; } 2>/dev/null; then
    read -r -p "$1 [$( [ "$padrao" = s ] && echo 'S/n' || echo 's/N')] " r </dev/tty || r=""
  elif [ "$SIMULAR" = 1 ] && [ -n "${RADAR_RESPOSTA:-}" ]; then
    r="$RADAR_RESPOSTA"; echo "$1 -> $r (automático, simulação)"
  fi
  [ -z "$r" ] && r="$padrao"
  case "$r" in s|S|sim|SIM|y|Y) return 0 ;; *) return 1 ;; esac
}

executar() { # executa ou, em simulação, só mostra
  echo "${C_AZUL}\$ $*${C_FIM}"
  if [ "$SIMULAR" = 1 ]; then return 0; fi
  "$@" </dev/null
}

passo() { echo; echo "${C_NEG}━━ $* ━━${C_FIM}"; }

echo "${C_NEG}Radar de Vulnerabilidades: correção passo a passo${C_FIM}"
[ "$SIMULAR" = 1 ] && echo "${C_AMAR}MODO SIMULAÇÃO: nada será alterado.${C_FIM}"
echo "Host: $(hostname) · $(radar_rotulo "$REL") · kernel $(uname -r)"
echo "Dados coletados em $RADAR_COLETA · registro em $LOG"
radar_idade_dados

# ---------- Passo 1: diagnóstico ----------
passo "Passo 1 de 7: diagnóstico"
PENDENTES=""   # id|tipo|alvo|versao|cvss|titulo|bins
SEM_FIX=""
while IFS='|' read -r rel id tipo alvo estado versao ups aviso cvss cves decisao titulo; do
  [ -z "$id" ] && continue
  case "$tipo" in
    src)
      IFS="$RS" read -r st inst nota bins <<< "$(radar_checar_fonte "$alvo" "$estado" "$versao" "$ups")"
      case "$st" in
        VULNERAVEL) PENDENTES="$PENDENTES$id|src|$alvo|$versao|$cvss|$titulo|$bins"$'\n'
          echo "  $(radar_cor VULNERAVEL)[$cvss] $titulo$C_FIM: $alvo $inst < $versao ${nota:+($nota)}" ;;
        SEM_CORRECAO) SEM_FIX="$SEM_FIX$id|$titulo"$'\n'
          echo "  $(radar_cor SEM_CORRECAO)[$cvss] $titulo$C_FIM: sem correção na distro" ;;
        VERIFICAR) echo "  $(radar_cor VERIFICAR)[$cvss] $titulo$C_FIM: $nota" ;;
      esac
      if [ "$ups" != "-" ] && [[ "$alvo" =~ ^php[0-9]+\.[0-9]+$ ]]; then
        while IFS="$RS" read -r fonte st2 inst2 nota2 bins2 minimo2; do
          [ -z "$fonte" ] && continue
          if [ "$st2" = VULNERAVEL ]; then
            PENDENTES="$PENDENTES$id|src|$fonte|${minimo2#upstream }|$cvss|$titulo ($fonte)|$bins2"$'\n'
            echo "  $(radar_cor VULNERAVEL)[$cvss] $titulo$C_FIM: $fonte $inst2 ($nota2)"
          fi
        done < <(radar_php_extras "$id" "$ups")
      fi ;;
    kernel)
      IFS="$RS" read -r st inst nota <<< "$(radar_checar_kernel "$versao")"
      case "$st" in
        VULNERAVEL) PENDENTES="$PENDENTES$id|kernel|linux|$versao|$cvss|$titulo|"$'\n'
          echo "  $(radar_cor VULNERAVEL)[$cvss] $titulo$C_FIM: kernel $inst < $versao" ;;
        REINICIAR) echo "  $(radar_cor REINICIAR)[$cvss] $titulo$C_FIM: $nota" ;;
        VERIFICAR) echo "  $(radar_cor VERIFICAR)[$cvss] $titulo$C_FIM: $nota" ;;
      esac ;;
    app)
      achados=$(radar_achar_app "$alvo")
      [ -z "$achados" ] && continue
      [ "$estado" = info ] && continue
      while IFS=$'\t' read -r caminho v; do
        st=$(radar_cmp_ramo "$v" "$versao" "$estado")
        if [ "$st" != OK ]; then
          PENDENTES="$PENDENTES$id|app|$alvo|$versao|$cvss|$titulo|$caminho"$'\n'
          echo "  $(radar_cor "$st")[$cvss] $titulo$C_FIM: $caminho versão $v (mínimos: $versao)"
        fi
      done <<< "$achados" ;;
  esac
done < <(radar_linhas)

if [ -z "$PENDENTES" ] && [ -z "$SEM_FIX" ]; then
  echo "${C_VERD}Nada a corrigir para os itens deste script.${C_FIM}"
  exit 0
fi

# ---------- Passo 2: ponto de restauração ----------
passo "Passo 2 de 7: ponto de restauração"
echo "Antes de alterar pacotes, recomenda-se um snapshot da VM ou do volume (LVM/ZFS/Btrfs)."
perguntar "Já fez (ou não precisa de) snapshot e quer continuar?" s || { echo "Encerrado sem alterações."; exit 0; }
printf '%s\n' "$RADAR_DPKG" | awk -F'\t' '{print $1"\t"$2}' > "$BACKUP/versoes-antes.tsv"
apt-mark showhold > "$BACKUP/hold-antes.txt" 2>/dev/null || true
: > "$BACKUP/aplicados.tsv"
: > "$BACKUP/mitigacoes.tsv"
echo "$REL" > "$BACKUP/release"
echo "Versões atuais salvas em $BACKUP/versoes-antes.tsv"
if perguntar "Salvar cópia de /etc (configurações) em $BACKUP/etc.tar.gz?" s; then
  executar tar -czf "$BACKUP/etc.tar.gz" -C / etc 2>/dev/null || echo "Aviso: cópia de /etc incompleta."
fi
mkdir -p "$BACKUP/debs"

# ---------- Passo 3: atualizar índices ----------
passo "Passo 3 de 7: atualizar a lista de pacotes"
if perguntar "Executar apt-get update?" s; then
  executar apt-get update
fi
if command -v dpkg-repack >/dev/null 2>&1; then
  REPACK=1
  echo "dpkg-repack encontrado: os pacotes atuais serão reempacotados antes de cada atualização (rollback sem rede)."
else
  REPACK=0
  if perguntar "Instalar dpkg-repack para guardar os .deb atuais (rollback mesmo sem a versão antiga no repositório)?" s; then
    executar apt-get install -y dpkg-repack && REPACK=1
  fi
fi

candidato() { apt-cache policy "$1" 2>/dev/null | awk '/Candidate:|Candidato:/ {print $2; exit}'; }

# ---------- Passo 4: aplicar correções ----------
passo "Passo 4 de 7: aplicar correções, uma por vez"
REINICIO=0
SERVICOS=""
while IFS='|' read -r -u 3 id tipo alvo versao cvss titulo extra; do
  [ -z "$id" ] && continue
  echo
  echo "${C_NEG}[$cvss] $titulo${C_FIM}  ($id)"
  case "$tipo" in
    src)
      read -r -a bins <<< "$extra"
      fonte_cand=""
      for b in "${bins[@]}"; do c=$(candidato "$b"); [ -n "$c" ] && [ "$c" != "(none)" ] && fonte_cand="$c" && break; done
      echo "  Pacotes instalados da fonte $alvo: ${bins[*]}"
      echo "  Versão mínima corrigida: $versao · candidata no repositório: ${fonte_cand:-desconhecida}"
      if [ -n "$fonte_cand" ] && dpkg --compare-versions "$fonte_cand" lt "$versao"; then
        echo "  ${C_AMAR}O repositório configurado ainda não oferece a versão corrigida. Confira se o repositório $(radar_codinome "$REL")-security está habilitado (ou Ubuntu Pro, se for ESM).${C_FIM}"
      fi
      echo "  Simulação:"
      sim=$(apt-get -s install --only-upgrade "${bins[@]}" 2>&1)
      printf '%s\n' "$sim" | grep -E '^(Inst|Remv|Conf) ' | sed 's/^/    /' | head -n 40
      if printf '%s\n' "$sim" | grep -q '^Remv '; then
        echo "  ${C_VERM}A simulação REMOVE pacotes. Revise antes de continuar.${C_FIM}"
        perguntar "  Tem certeza? Digite s apenas se revisou a lista acima" n || continue
      fi
      perguntar "  Aplicar esta correção?" n || { echo "  Pulado."; continue; }
      if [ "$REPACK" = 1 ]; then
        for b in "${bins[@]}"; do
          if ! ( cd "$BACKUP/debs" && executar dpkg-repack "$b" >"$BACKUP/debs/.repack.log" 2>&1 ); then
            echo "  ${C_AMAR}Aviso: não foi possível reempacotar $b (veja $BACKUP/debs/.repack.log); o rollback dependerá do repositório.${C_FIM}"
          fi
        done
      fi
      antes=()
      for b in "${bins[@]}"; do antes+=("$b=$(radar_versao_instalada "$b")"); done
      if executar apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold "${bins[@]}"; then
        radar_carregar_dpkg
        for par in "${antes[@]}"; do
          b="${par%%=*}"; va="${par#*=}"; vd=$(radar_versao_instalada "$b")
          [ "$SIMULAR" = 1 ] && vd="(simulação)"
          printf '%s\t%s\t%s\t%s\n' "$id" "$b" "$va" "$vd" >> "$BACKUP/aplicados.tsv"
        done
        echo "  ${C_VERD}Aplicado.${C_FIM}"
        case "$alvo" in
          php*) SERVICOS="$SERVICOS $(systemctl list-units --type=service --no-legend 'php*-fpm*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ') apache2" ;;
          nginx|apache2|haproxy|squid|exim4|postgresql-*|tomcat9|tomcat10) SERVICOS="$SERVICOS ${alvo/postgresql-*/postgresql}" ;;
          openssl|glibc|brotli|libzstd|expat|pcre2|curl|krb5|libgd2|libssh) SERVICOS="$SERVICOS needrestart" ;;
        esac
      else
        echo "  ${C_VERM}Falhou. Veja o registro em $LOG.${C_FIM}"
      fi ;;
    kernel)
      metas=$(printf '%s\n' "$RADAR_DPKG" | awk -F'\t' '{print $1}' | grep -E '^linux-(image-|headers-)?(generic|virtual|lowlatency|aws|azure|gcp|oracle|kvm|amd64|arm64|cloud-amd64|cloud-arm64|rt-amd64)(-hwe-[0-9.]+)?$' | tr '\n' ' ')
      if [ -z "$metas" ]; then
        echo "  ${C_AMAR}Nenhum metapacote de kernel encontrado. Instale o kernel corrigido ($versao) manualmente.${C_FIM}"
        continue
      fi
      echo "  Metapacotes de kernel: $metas"
      read -r -a mbins <<< "$metas"
      apt-get -s install --only-upgrade "${mbins[@]}" 2>&1 | grep -E '^(Inst|Remv) ' | sed 's/^/    /' | head -n 20
      perguntar "  Instalar o kernel novo? (o atual continua no GRUB para rollback)" n || { echo "  Pulado."; continue; }
      if executar apt-get install -y --only-upgrade "${mbins[@]}"; then
        printf '%s\t%s\t%s\t%s\n' "$id" "kernel" "$(uname -r)" "(novo kernel)" >> "$BACKUP/aplicados.tsv"
        REINICIO=1
        echo "  ${C_VERD}Kernel instalado. A correção só vale após reiniciar.${C_FIM}"
      fi ;;
    app)
      echo "  Instalação em: $extra"
      txt=$(radar_texto "$id" correcao)
      echo "  Esta é uma aplicação web; o script não altera o código dela. Comando sugerido (rode como o dono dos arquivos, no diretório da aplicação):"
      echo "    ${C_AZUL}$txt${C_FIM}"
      rb=$(radar_texto "$id" rollback)
      [ -n "$rb" ] && echo "  Rollback: $rb" ;;
  esac
done 3<<< "$PENDENTES"

# ---------- Passo 5: mitigações ----------
passo "Passo 5 de 7: mitigações"
if [ -n "$SEM_FIX" ]; then
  echo "Itens sem correção na distro (aplique a mitigação indicada no painel):"
  printf '%s' "$SEM_FIX" | while IFS='|' read -r id titulo; do
    [ -z "$id" ] && continue
    echo "  - $titulo"
    m=$(radar_texto "$id" mitigacao); [ -n "$m" ] && echo "      $m"
  done
fi
if radar_linhas | awk -F'|' '$2 ~ /^php-/' | grep -q . && ls -d /etc/php/*/ >/dev/null 2>&1; then
  echo "Mitigação do PHP: desativar session.upload_progress (reduz a superfície do PHP2Shell e do CVE-2026-115560)."
  if perguntar "Criar radar-mitigacao.ini e ativar com phpenmod em todas as versões do PHP?" n; then
    for d in /etc/php/*/; do
      d="${d%/}"
      v=$(basename "$d")
      [ -d "$d/mods-available" ] || continue
      if [ "$SIMULAR" = 1 ]; then
        echo "${C_AZUL}\$ (gravaria) $d/mods-available/radar-mitigacao.ini${C_FIM}"
      else
        printf '; Radar de Vulnerabilidades %s\nsession.upload_progress.enabled = 0\n' "$CARIMBO" > "$d/mods-available/radar-mitigacao.ini"
      fi
      executar phpenmod -v "$v" -s ALL radar-mitigacao
      printf 'php\t%s\t%s\n' "$v" "$d/mods-available/radar-mitigacao.ini" >> "$BACKUP/mitigacoes.tsv"
    done
    SERVICOS="$SERVICOS $(systemctl list-units --type=service --no-legend 'php*-fpm*' 2>/dev/null | awk '{print $1}' | tr '\n' ' ') apache2"
  fi
fi

# ---------- Passo 6: serviços ----------
passo "Passo 6 de 7: reiniciar serviços"
if printf '%s' "$SERVICOS" | grep -q needrestart && command -v needrestart >/dev/null 2>&1; then
  echo "Serviços que ainda usam bibliotecas antigas:"
  needrestart -r l -b 2>/dev/null | awk -F': ' '/^NEEDRESTART-SVC/ {print "  "$2}'
  SERVICOS="$SERVICOS $(needrestart -r l -b 2>/dev/null | awk -F': ' '/^NEEDRESTART-SVC/ {print $2}' | tr '\n' ' ')"
fi
for s in $(printf '%s\n' $SERVICOS | grep -v '^needrestart$' | sort -u); do
  s="${s%.service}"
  systemctl is-active --quiet "$s" 2>/dev/null || continue
  if perguntar "Reiniciar o serviço $s agora?" n; then
    executar systemctl restart "$s" && echo "  $s reiniciado." || echo "  ${C_VERM}Falha ao reiniciar $s${C_FIM}"
  fi
done

# ---------- Passo 7: conferência ----------
passo "Passo 7 de 7: conferência"
radar_carregar_dpkg
while IFS='|' read -r id tipo alvo versao cvss titulo extra; do
  [ -z "$id" ] && continue
  if [ "$tipo" = src ]; then
    estado=$(radar_linhas | awk -F'|' -v i="$id" -v a="$alvo" '$2==i && $4==a {print $5; exit}')
    IFS="$RS" read -r st inst nota bins <<< "$(radar_checar_fonte "$alvo" "$estado" "$versao" "-")"
    echo "  $(radar_cor "$st")$(radar_rot_status "$st")${C_FIM}  $titulo ($alvo $inst)"
  fi
done <<< "$PENDENTES"
if [ "$REINICIO" = 1 ] || [ -f /var/run/reboot-required ]; then
  echo "${C_AMAR}É preciso reiniciar o servidor para concluir (kernel ou bibliotecas do sistema). Agende a janela; este script não reinicia.${C_FIM}"
fi
echo
echo "Ponto de restauração: $BACKUP"
echo "Para desfazer: sudo bash radar-rollback.sh $BACKUP"
