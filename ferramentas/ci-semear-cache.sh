#!/usr/bin/env bash
# Radar de Vulnerabilidades: semente do cache das fontes para o GitHub Actions.
# Quando o cache do GitHub está vazio (primeira coleta, ou cache expirado após 7 dias sem uso), baixa o pacote
# radar-cache.tar.gz anexado a um release RASCUNHO chamado "cache-semente" (rascunho não é público; só quem tem
# acesso de escrita ao repositório o vê). Sem esse release, não faz nada e a coleta baixa tudo das fontes.
# Para criar o pacote numa máquina com o cache em dia:
#   tar -C ~/.cache/radar-vulnerabilidades -czf radar-cache.tar.gz nvd nvd-produtos ubuntu usn
#   gh release create cache-semente --draft --title cache-semente --notes "Semente temporária do cache" radar-cache.tar.gz
set -euo pipefail
R="${GITHUB_REPOSITORY:?defina GITHUB_REPOSITORY (dono/nome)}"
CACHE="${RADAR_CACHE:-$HOME/.cache/radar-vulnerabilidades}"
url="$(gh api "repos/$R/releases" --jq '[.[] | select(.draft and .name == "cache-semente")][0].assets[]? | select(.name == "radar-cache.tar.gz") | .url' 2>/dev/null | head -1 || true)"
if [ -z "$url" ]; then echo "Sem release rascunho cache-semente: a coleta baixa tudo das fontes."; exit 0; fi
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
gh api -H "Accept: application/octet-stream" "$url" > "$tmp"
# Só arquivos das pastas esperadas, com nomes simples (sem caminhos absolutos nem "..").
if tar -tzf "$tmp" | grep -Ev '^(nvd|nvd-produtos|ubuntu|usn)(/[A-Za-z0-9._-]+)?/?$' | grep -q .; then
  echo "::error::o pacote cache-semente tem caminhos inesperados; ignorado."; exit 1
fi
mkdir -p "$CACHE"
tar --no-same-owner -xzf "$tmp" -C "$CACHE"
echo "Cache semeado com $(tar -tzf "$tmp" | grep -vc '/$') arquivos do release cache-semente."
