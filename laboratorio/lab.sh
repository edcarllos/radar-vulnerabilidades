#!/usr/bin/env bash
# Radar de Vulnerabilidades: LABORATÓRIO DE TREINO (F15)
# Um contêiner descartável com pacotes vulneráveis de verdade, para praticar verificar, corrigir e desfazer
# sem risco. Precisa de Docker (ou Podman) e de internet no contêiner. Nunca rode isto num servidor de produção.
#
# Uso: bash laboratorio/lab.sh <comando>
#   preparar        cria o contêiner radar-lab (Ubuntu 26.04) com Kerberos antigo e Node.js
#   entrar          abre um terminal dentro do contêiner, na pasta /radar com os scripts
#   conferir N      confere o exercício N (1 a 5) e faz as perguntas
#   gabarito N      mostra a resposta comentada do exercício N
#   limpar          apaga o contêiner (pode recomeçar com preparar)
# Os exercícios estão em laboratorio/LEIA-ME.md.
set -euo pipefail

NOME=radar-lab
IMAGEM="${RADAR_LAB_IMAGEM:-ubuntu:26.04}"
AQUI="$(cd "$(dirname "$0")" && pwd)"
SCRIPTS="${RADAR_LAB_SCRIPTS:-$AQUI/../scripts}"
ENG=""
if command -v docker >/dev/null 2>&1; then ENG=docker; elif command -v podman >/dev/null 2>&1; then ENG=podman; fi
[ -n "$ENG" ] || { echo "Instale o Docker ou o Podman para usar o laboratório."; exit 2; }

if [ -t 1 ]; then V=$'\e[32m'; E=$'\e[31m'; N=$'\e[1m'; F=$'\e[0m'; else V=""; E=""; N=""; F=""; fi
certo() { echo "${V}✔ $*${F}"; }
errado() { echo "${E}✘ $*${F}"; FALHAS=$((FALHAS + 1)); }
FALHAS=0

existe() { "$ENG" container inspect "$NOME" >/dev/null 2>&1; }
dentro() { "$ENG" exec "$NOME" bash -c "$1"; }
exigir() { existe || { echo "O contêiner ainda não existe: rode  bash $0 preparar"; exit 2; }; }

# Pacotes do Kerberos que o exercício deixa na versão antiga (a do lançamento da distro).
KRB="libkrb5-3 libgssapi-krb5-2 libk5crypto3 libkrb5support0 krb5-locales"

verif_json() { dentro "bash /radar/radar-verificar.sh --json --todos" 2>/dev/null || true; }
campo() { # json item alvo campo
  python3 -I -c '
import json, sys
d = json.loads(sys.argv[1])
for i in d.get("itens", []):
    if i["item"] == sys.argv[2] and i["alvo"] == sys.argv[3]:
        print(i.get(sys.argv[4], "")); break
' "$1" "$2" "$3" "$4"
}
perguntar() { # texto -> resposta em $R
  R=""; read -r -p "$1 " R </dev/tty || R=""
  R="$(printf '%s' "$R" | tr '[:upper:]' '[:lower:]' | sed 's/^ *//; s/ *$//')"
}

preparar() {
  if existe; then echo "O contêiner $NOME já existe. Use  bash $0 entrar  ou  bash $0 limpar  para recomeçar."; exit 0; fi
  [ -f "$SCRIPTS/radar-verificar.sh" ] || { echo "Scripts não encontrados em $SCRIPTS (gere com node ferramentas/build.mjs)."; exit 2; }
  echo "Criando o contêiner $NOME a partir de $IMAGEM..."
  "$ENG" run -d --name "$NOME" --hostname laboratorio -v "$(cd "$SCRIPTS" && pwd):/radar-original:ro" "$IMAGEM" sleep infinity >/dev/null
  echo "Instalando pacotes do exercício (1 a 3 minutos)..."
  dentro '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    mkdir -p /radar && cp /radar-original/radar-* /radar-original/SHA256SUMS /radar/
    apt-get update -qq >/dev/null
    apt-get install -y -qq python3-minimal nodejs less >/dev/null 2>&1
    cod=$(. /etc/os-release; echo "$VERSION_CODENAME")
    alvos=""
    for p in '"$KRB"'; do
      v=$(apt-cache madison "$p" | awk -F"|" -v c="$cod/" "index(\$3, \" \" c) {gsub(/ /, \"\", \$2); print \$2; exit}")
      [ -n "$v" ] && alvos="$alvos $p=$v"
    done
    apt-get install -y -qq --allow-downgrades $alvos >/dev/null 2>&1
    echo "$alvos" > /root/.lab-krb5-antigo
  '
  echo
  certo "Laboratório pronto. Abra o terminal com:  bash $0 entrar"
  echo "Depois siga laboratorio/LEIA-ME.md a partir do exercício 1."
}

entrar() {
  exigir
  echo "Você está no contêiner de treino (pode errar à vontade). Scripts em /radar. Para sair: exit"
  "$ENG" exec -it -w /radar "$NOME" bash
}

conferir() {
  exigir
  local j vk mk
  case "${1:-}" in
    1)
      echo "${N}Exercício 1: ler a verificação${F}"
      j=$(verif_json)
      vk=$(python3 -I -c 'import json,sys; print(json.loads(sys.argv[1])["resumo"]["vulneravel"])' "$j")
      mk=$(campo "$j" krb5-2026-11 krb5 minimo)
      perguntar "1) Quantos itens aparecem como VULNERÁVEL?"
      [ "$R" = "$vk" ] && certo "Isso: $vk." || errado "Não. Conte os itens no grupo '== VULNERÁVEL (n)'."
      perguntar "2) Qual a versão mínima (corrigida) do krb5 que o script pede?"
      [ "$R" = "$(printf '%s' "$mk" | tr '[:upper:]' '[:lower:]')" ] && certo "Isso: $mk." || errado "Não. Procure a linha 'krb5: instalado … · mínimo …'."
      perguntar "3) O script de verificação alterou alguma coisa no sistema? (s/n)"
      [ "$R" = n ] && certo "Correto: ele só lê." || errado "A verificação é somente leitura; ela nunca altera nada." ;;
    2)
      echo "${N}Exercício 2: simular a correção${F}"
      j=$(verif_json)
      [ "$(campo "$j" krb5-2026-11 krb5 status)" = VULNERAVEL ] && certo "O krb5 continua na versão antiga: a simulação não mudou nada." \
        || errado "O krb5 já não está vulnerável. Você rodou sem --simular? Recomece com limpar e preparar."
      perguntar "1) Na simulação, a correção do krb5 instalaria pacotes NOVOS ou só atualizaria os existentes? (novos/atualizar)"
      case "$R" in atualizar|atualiza|atualizaria|existentes) certo "Isso: só os binários já instalados (only-upgrade)." ;; *) errado "Veja a linha 'apt-get install --only-upgrade …' que o script mostrou." ;; esac
      perguntar "2) Antes de corrigir de verdade num servidor real, o que o script pede primeiro? (snapshot/reiniciar/nada)"
      [ "$R" = snapshot ] && certo "Correto: snapshot ou backup antes de tudo." || errado "O passo 2 pergunta pelo snapshot da VM e cria o ponto de restauração." ;;
    3)
      echo "${N}Exercício 3: corrigir de verdade${F}"
      j=$(verif_json)
      case "$(campo "$j" krb5-2026-11 krb5 status)" in OK|ATENCAO) true ;; *) false ;; esac && certo "krb5 atualizado: $(campo "$j" krb5-2026-11 krb5 instalado). Se aparecer ATENÇÃO, a correção está aplicada, mas a distro ainda tem CVEs do krb5 sem correção." \
        || errado "O krb5 ainda aparece como $(campo "$j" krb5-2026-11 krb5 status). Rode sudo bash radar-corrigir.sh e responda s na correção do Kerberos."
      if dentro 'ls -d /var/backups/radar-vuln/*/ >/dev/null 2>&1'; then certo "Ponto de restauração criado em $(dentro 'ls -d /var/backups/radar-vuln/*/ | tail -n1')."
      else errado "Não há ponto de restauração em /var/backups/radar-vuln. Sem ele, o exercício 4 não funciona."; fi
      perguntar "1) Depois de atualizar uma biblioteca, o que ainda falta para os serviços usarem a versão nova? (reiniciar/nada)"
      case "$R" in reiniciar*) certo "Isso: processos antigos continuam com a biblioteca velha na memória até reiniciar." ;; *) errado "Processos já abertos mantêm a versão antiga em memória; é preciso reiniciá-los (o passo 6 e o needrestart ajudam)." ;; esac ;;
    4)
      echo "${N}Exercício 4: desfazer (rollback)${F}"
      local antigo atual
      antigo=$(dentro 'cat /root/.lab-krb5-antigo' | tr ' ' '\n' | awk -F= '$1=="libkrb5-3" {print $2}')
      atual=$(dentro "dpkg-query -W -f='\${Version}' libkrb5-3" 2>/dev/null || true)
      [ -n "$antigo" ] && [ "$atual" = "$antigo" ] && certo "libkrb5-3 voltou para $antigo." || errado "libkrb5-3 está em $atual (esperado $antigo). Rode sudo bash radar-rollback.sh e escolha o ponto de restauração do exercício 3."
      perguntar "1) Depois do rollback, o servidor está seguro? (s/n)"
      [ "$R" = n ] && certo "Correto: voltar a versão reexpõe as falhas. Rollback é para recuperar serviço quebrado; reaplique a correção depois." || errado "Não: a versão antiga tem as falhas de novo." ;;
    5)
      echo "${N}Exercício 5: quando não há correção${F}"
      j=$(verif_json)
      local st dec
      st=$(campo "$j" nodejs-2026-10 nodejs status); dec=$(campo "$j" nodejs-2026-10 nodejs decisao)
      [ "$st" = SEM_CORRECAO ] && certo "O Node.js aparece como SEM CORREÇÃO na distro." || echo "Aviso: hoje o Node.js aparece como '${st:-ausente}' (a distro pode ter publicado a correção; o raciocínio vale igual)."
      perguntar "1) 'Sem correção' quer dizer que ninguém pode explorar a falha? (s/n)"
      [ "$R" = n ] && certo "Correto: a falha é conhecida e pode ser explorada; só falta o pacote corrigido." || errado "Não: sem correção significa exposição sem remédio oficial, por isso a mitigação importa."
      perguntar "2) O que fazer até sair a correção? (mitigar/esperar/remover-tudo)"
      [ "$R" = mitigar ] && certo "Isso: aplique a mitigação do painel e acompanhe o prazo da decisão." || errado "A resposta é mitigar: veja 'Mitigação' no detalhe do item no painel."
      perguntar "3) Qual a decisão do item (agir_agora, agir_em_breve, acompanhar_de_perto, acompanhar)?"
      [ -n "$dec" ] && [ "$R" = "$dec" ] && certo "Isso: $dec." || errado "O script mostra a decisão; neste dado ela é '${dec:-?}'." ;;
    *) echo "Informe o exercício: 1 a 5."; exit 2 ;;
  esac
  echo
  if [ "$FALHAS" = 0 ]; then certo "Exercício ${1} concluído."; else echo "Revise os pontos marcados e rode de novo. Dica: bash $0 gabarito ${1}"; fi
}

gabarito() {
  case "${1:-}" in
    1) cat <<'TXT'
Gabarito 1: rode  bash radar-verificar.sh  (sem sudo). Os grupos aparecem do mais grave ao menos grave.
VULNERÁVEL = existe correção na distro e o pacote instalado é mais antigo que ela. A linha do krb5 mostra a
versão instalada e a mínima corrigida, o aviso (USN) e os CVEs. A decisão (Agir agora, Agir em breve…) diz o prazo.
A verificação é somente leitura: pode rodar quantas vezes quiser, inclusive em produção.
TXT
    ;;
    2) cat <<'TXT'
Gabarito 2: rode  bash radar-corrigir.sh --simular . Nada é alterado: o apt roda em modo -s e os comandos aparecem
na tela. Repare que a correção usa  apt-get install --only-upgrade  só com os binários já instalados: não instala
nada novo. Num servidor real, o passo 2 pede snapshot da VM antes de qualquer mudança.
TXT
    ;;
    3) cat <<'TXT'
Gabarito 3: rode  bash radar-corrigir.sh  (no laboratório você já é root). Responda s ao snapshot, à cópia do /etc,
ao apt-get update e ao dpkg-repack; depois s só na correção do Kerberos. O script grava o ponto de restauração em
/var/backups/radar-vuln/<data>/ e, no fim, confere de novo. Bibliotecas atualizadas só valem para processos novos:
reinicie os serviços que as usam (o passo 6 lista quais).
TXT
    ;;
    4) cat <<'TXT'
Gabarito 4: rode  bash radar-rollback.sh , escolha o ponto de restauração do exercício 3 e, no item do Kerberos,
responda d (reinstala os .deb salvos pelo dpkg-repack, sem rede) ou a (baixa as versões antigas do repositório);
p pula o item (pule os outros itens). Ele faz um ensaio (dpkg --dry-run), pede confirmação (s) e pergunta se deve
fixar a versão com apt-mark hold (responda n no treino). Isso reabre as falhas:
use rollback só para recuperar um serviço quebrado e programe a correção de novo.
TXT
    ;;
    5) cat <<'TXT'
Gabarito 5: o Node.js aparece como SEM CORREÇÃO: a falha é conhecida e a distro ainda não publicou pacote. Não há
apt upgrade que resolva. Abra o item no painel, aplique a mitigação indicada (restringir acesso, desativar o
recurso afetado), registre a exceção e acompanhe: quando a correção sair, o item muda para VULNERÁVEL e o
radar-corrigir.sh passa a oferecê-la.
TXT
    ;;
    *) echo "Informe o exercício: 1 a 5."; exit 2 ;;
  esac
}

limpar() {
  if existe; then "$ENG" rm -f "$NOME" >/dev/null && certo "Contêiner $NOME apagado."; else echo "Nada para apagar."; fi
}

case "${1:-}" in
  preparar) preparar ;;
  entrar) entrar ;;
  conferir) conferir "${2:-}" ;;
  gabarito) gabarito "${2:-}" ;;
  limpar) limpar ;;
  *) sed -n '2,12p' "$0"; exit 2 ;;
esac
