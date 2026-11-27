#!/usr/bin/env python3
"""Fontes nacionais de alertas de segurança.

CAIS/RNP: a página https://www.rnp.br/servicos/cais/ lista os alertas como arquivos .txt
assinados com PGP em plataforma.rnp.br. Este módulo extrai os links da página e lê cada alerta.

CTIR Gov: portal em manutenção na data da implementação (26/11/2026); leitor pendente.
CERT.br: o RSS publica notícias institucionais, não alertas de vulnerabilidade; fora do escopo.

Uso:
  nacionais.py links ARQ.html          imprime as URLs de alertas do CAIS (uma por linha)
  nacionais.py ler ARQ.txt             imprime o alerta lido como JSON
"""
import datetime, html, json, re, sys
from urllib.parse import unquote, urlparse

RE_LINK = re.compile(r'https://plataforma\.rnp\.br/arquivos/documents/CAIS-Alerta[^"\'<>\s]+')
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def links_cais(pagina_html):
    vistos, out = set(), []
    for u in RE_LINK.findall(pagina_html):
        u = html.unescape(u)
        p = urlparse(u)
        if p.scheme != "https" or p.netloc != "plataforma.rnp.br" or not p.path.endswith(".txt"):
            continue
        if u not in vistos:
            vistos.add(u)
            out.append(u)
    return out


def _data(texto):
    m = re.search(r"(\d{2})[/_-](\d{2})[/_-](\d{4})", texto)
    if not m:
        return None
    try:
        return datetime.date(int(m.group(3)), int(m.group(2)), int(m.group(1))).isoformat()
    except ValueError:
        return None


def ler_cais(texto, url=""):
    """Extrai data, título, CVEs e resumo de um alerta do CAIS (texto assinado em PGP)."""
    linhas = [l.rstrip() for l in texto.replace("\r", "").split("\n")]
    corpo = []
    dentro = False
    for l in linhas:
        if l.startswith("-----BEGIN PGP SIGNATURE"):
            break
        if l.startswith("Hash:"):
            dentro = True
            continue
        if dentro or not l.startswith("-----BEGIN PGP SIGNED"):
            corpo.append(l)
    titulo_l = next((l for l in corpo if l.startswith("CAIS-Alerta")), "")
    titulo = re.sub(r"^CAIS-Alerta\s*[\d/_-]+\s*[:\-–]?\s*", "", titulo_l).strip()
    nome_arq = unquote(urlparse(url).path.rsplit("/", 1)[-1]) if url else ""
    data = _data(titulo_l) or _data(nome_arq)
    resumo = ""
    try:
        i = next(k for k, l in enumerate(corpo) if l.lower().startswith("prezados"))
        bloco = []
        for l in corpo[i + 1:]:
            if not l.strip():
                if bloco:
                    break
                continue
            bloco.append(l.strip())
        resumo = " ".join(bloco)
    except StopIteration:
        pass
    cves = sorted(set(RE_CVE.findall("\n".join(corpo))))
    limpar = lambda s, n: re.sub(r"\s+", " ", re.sub(r"[\x00-\x1f\x7f]", " ", s)).strip()[:n]
    return {"fonte": "CAIS/RNP", "data": data, "titulo": limpar(titulo or nome_arq, 200),
            "cves": cves, "resumo": limpar(resumo, 600), "url": url}


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "links":
        for u in links_cais(open(sys.argv[2], encoding="utf-8", errors="replace").read()):
            print(u)
    elif len(sys.argv) >= 3 and sys.argv[1] == "ler":
        print(json.dumps(ler_cais(open(sys.argv[2], encoding="utf-8", errors="replace").read(),
                                  sys.argv[3] if len(sys.argv) > 3 else ""), ensure_ascii=False))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
