#!/usr/bin/env bash
# Radar de Vulnerabilidades: ROLLBACK
# Desfaz, item por item, o que o radar-corrigir.sh aplicou. Voltar uma versão REEXPÕE o servidor às falhas corrigidas:
# use só para recuperar um serviço quebrado e planeje reaplicar a correção.
# Uso: sudo bash radar-rollback.sh [/var/backups/radar-vuln/<data>] [--simular]
set -u
@@COMUM@@

SIMULAR=0; BACKUP=""
for a in "$@"; do
  case "$a" in
    --simular) SIMULAR=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) BACKUP="$a" ;;
  esac
done
if [ "$SIMULAR" = 0 ] && [ "$(id -u)" != 0 ]; then
  echo "Rode como root: sudo bash $0 [ponto-de-restauração]   (ou --simular)"
  exit 2
fi

perguntar() {
  local r="" padrao="${2:-n}"
  if [ -r /dev/tty ] && { true </dev/tty; } 2>/dev/null; then
    read -r -p "$1 [$( [ "$padrao" = s ] && echo 'S/n' || echo 's/N')] " r </dev/tty || r=""
  elif [ "$SIMULAR" = 1 ] && [ -n "${RADAR_RESPOSTA:-}" ]; then
    r="$RADAR_RESPOSTA"; echo "$1 -> $r (automático, simulação)"
  fi
  [ -z "$r" ] && r="$padrao"
  case "$r" in s|S|sim|SIM|y|Y) return 0 ;; *) return 1 ;; esac
}
executar() {
  echo "${C_AZUL}\$ $*${C_FIM}"
  if [ "$SIMULAR" = 1 ]; then return 0; fi
  "$@" </dev/null
}

# Arquivo .deb salvo pelo dpkg-repack para "pacote" ou "pacote:arquitetura"
deb_salvo() {
  local nome="${1%%:*}" arq=""
  case "$1" in *:*) arq="${1##*:}" ;; esac
  if [ -n "$arq" ]; then
    ls "$BACKUP/debs/${nome}_"*"_${arq}.deb" "$BACKUP/debs/${nome}_"*"_all.deb" 2>/dev/null | head -n1
  else
    ls "$BACKUP/debs/${nome}_"*.deb 2>/dev/null | head -n1
  fi
}

radar_checar_release
radar_carregar_dpkg
echo "${C_NEG}Radar de Vulnerabilidades: rollback${C_FIM}"
[ "$SIMULAR" = 1 ] && echo "${C_AMAR}MODO SIMULAÇÃO: nada será alterado.${C_FIM}"
echo "${C_VERM}Voltar versões reexpõe o servidor às vulnerabilidades corrigidas.${C_FIM}"

# ---------- escolher o ponto de restauração ----------
if [ -z "$BACKUP" ]; then
  mapfile -t pontos < <(ls -1d /var/backups/radar-vuln/*/ 2>/dev/null | sort -r)
  if [ "${#pontos[@]}" = 0 ]; then
    echo "Nenhum ponto de restauração em /var/backups/radar-vuln/. Informe o caminho como argumento."
    exit 1
  fi
  echo "Pontos de restauração:"
  i=1
  for p in "${pontos[@]}"; do
    n=$(grep -c . "$p/aplicados.tsv" 2>/dev/null || echo 0)
    echo "  $i) $p ($n alteração(ões))"
    i=$((i+1))
  done
  escolha=1
  if [ -r /dev/tty ] && { true </dev/tty; } 2>/dev/null; then read -r -p "Número [1]: " escolha </dev/tty || escolha=1; fi
  [[ "$escolha" =~ ^[0-9]+$ ]] || escolha=1
  BACKUP="${pontos[$((escolha-1))]:-${pontos[0]}}"
fi
BACKUP="${BACKUP%/}"
if [ ! -r "$BACKUP/aplicados.tsv" ]; then
  echo "Ponto de restauração inválido: $BACKUP (falta aplicados.tsv)"
  exit 1
fi
if [ -r "$BACKUP/release" ] && [ "$(cat "$BACKUP/release")" != "$REL" ]; then
  echo "${C_VERM}Este ponto de restauração é de outra versão da distro ($(cat "$BACKUP/release")).${C_FIM}"
  exit 1
fi
echo "Usando $BACKUP"
LOG="$BACKUP/rollback-$(date +%Y%m%d-%H%M%S).log"
[ "$SIMULAR" = 1 ] && LOG=$(mktemp "${TMPDIR:-/tmp}/radar-rollback-XXXXXX.log")
exec > >(tee -a "$LOG") 2>&1

# ---------- pacotes, agrupados por item ----------
for item in $(awk -F'\t' '$2!="kernel" {print $1}' "$BACKUP/aplicados.tsv" | awk '!v[$0]++'); do
  echo
  echo "${C_NEG}Item: $item${C_FIM}"
  alvos=(); faltam_debs=0; no_repo=1
  while IFS=$'\t' read -r id pkg antes depois; do
    [ "$id" = "$item" ] || continue
    atual=$(radar_versao_instalada "$pkg")
    echo "  $pkg: antes $antes · depois $depois · agora ${atual:-não instalado}"
    alvos+=("$pkg=$antes")
    [ -n "$(deb_salvo "$pkg")" ] || faltam_debs=1
    apt-cache madison "$pkg" 2>/dev/null | awk -F'|' '{gsub(/ /,"",$2); print $2}' | grep -qxF "$antes" || no_repo=0
  done < "$BACKUP/aplicados.tsv"
  [ "${#alvos[@]}" = 0 ] && continue
  echo "  Opções:"
  [ "$faltam_debs" = 0 ] && echo "    d) reinstalar os .deb salvos no ponto de restauração (não precisa de rede)"
  [ "$no_repo" = 1 ] && echo "    a) instalar as versões anteriores pelo repositório (apt-get --allow-downgrades)"
  echo "    p) pular"
  op="p"
  if [ -r /dev/tty ] && { true </dev/tty; } 2>/dev/null; then read -r -p "  Escolha [p]: " op </dev/tty || op="p"; fi
  [ "$SIMULAR" = 1 ] && [ -n "${RADAR_RESPOSTA:-}" ] && op="${RADAR_OPCAO:-p}"
  case "$op" in
    d)
      [ "$faltam_debs" = 0 ] || { echo "  Não há todos os .deb salvos."; continue; }
      debs=()
      for par in "${alvos[@]}"; do debs+=("$(deb_salvo "${par%%=*}")"); done
      executar dpkg --dry-run -i "${debs[@]}" || true
      perguntar "  Confirmar a reinstalação das versões anteriores?" n && executar dpkg -i "${debs[@]}" ;;
    a)
      [ "$no_repo" = 1 ] || { echo "  Alguma versão anterior não está mais no repositório."; continue; }
      apt-get -s install --allow-downgrades "${alvos[@]}" 2>&1 | grep -E '^(Inst|Remv) ' | sed 's/^/    /'
      perguntar "  Confirmar o downgrade?" n && executar apt-get install -y --allow-downgrades -o Dpkg::Options::=--force-confold "${alvos[@]}" ;;
    *) echo "  Pulado."; continue ;;
  esac
  if perguntar "  Fixar (apt-mark hold) estes pacotes para não serem atualizados de novo? Isso mantém a vulnerabilidade." n; then
    executar apt-mark hold "${alvos[@]%%=*}"
    echo "  Lembre de liberar depois: apt-mark unhold ${alvos[*]%%=*}"
  fi
done

# ---------- kernel ----------
if awk -F'\t' '$2=="kernel"' "$BACKUP/aplicados.tsv" | grep -q .; then
  echo
  echo "${C_NEG}Kernel${C_FIM}"
  anterior=$(awk -F'\t' '$2=="kernel" {print $3; exit}' "$BACKUP/aplicados.tsv")
  echo "  Kernel anterior: $anterior (continua instalado). Em execução agora: $(uname -r)"
  cfg=/boot/grub/grub.cfg
  sub=$(grep -oE "submenu '[^']*' [^{]*\\\$menuentry_id_option '[^']+'" "$cfg" 2>/dev/null | grep -oE "'gnulinux-advanced-[^']+'" | tr -d "'" | head -n1)
  ent=$(grep -oE "\\\$menuentry_id_option '[^']+'" "$cfg" 2>/dev/null | tr -d "'" | awk '{print $2}' | grep -F -- "-$anterior-advanced-" | head -n1)
  if [ -n "$sub" ] && [ -n "$ent" ]; then
    echo "  Entrada do GRUB encontrada: $sub>$ent"
    if perguntar "  Inicializar UMA VEZ com o kernel anterior no próximo boot (grub-reboot)?" n; then
      executar grub-reboot "$sub>$ent"
      echo "  Pronto. Reinicie quando for conveniente; o boot seguinte volta ao kernel padrão."
    fi
  else
    echo "  Não encontrei a entrada no GRUB automaticamente. No boot, escolha 'Opções avançadas' e o kernel $anterior."
  fi
fi

# ---------- mitigações ----------
if [ -s "$BACKUP/mitigacoes.tsv" ]; then
  echo
  echo "${C_NEG}Mitigações aplicadas${C_FIM}"
  while IFS=$'\t' read -r tipo ver arquivo; do
    [ "$tipo" = php ] || continue
    if perguntar "  Remover a mitigação do PHP $ver ($arquivo)?" n; then
      executar phpdismod -v "$ver" -s ALL radar-mitigacao
      executar rm -f "$arquivo"
    fi
  done < "$BACKUP/mitigacoes.tsv"
fi

echo
echo "Configurações anteriores: $BACKUP/etc.tar.gz (se foi salvo). Compare antes de restaurar arquivos."
echo "Reinicie os serviços afetados (systemctl restart <serviço>) e rode o radar-verificar.sh para conferir o estado."
echo "Registro: $LOG"
