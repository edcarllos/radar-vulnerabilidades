#!/usr/bin/env python3
"""Radar de Vulnerabilidades: dados de segurança da Microsoft para o Windows Server (F25).

Fonte: Microsoft Security Update Guide (API pública, sem chave):
  https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter=cveNumber eq '<CVE>'
Sem licença aberta declarada: o Radar usa só fatos (CVE, KB, build corrigido, link para o guia), com atribuição,
para fins educacionais e não comerciais.

As atualizações do Windows Server são cumulativas: o servidor está corrigido quando o build instalado
(10.0.<build>.<UBR>) é igual ou maior que o build corrigido do KB.

Nas entradas antigas (até 2021) o guia traz o KB mas não o build. O build desses KBs vem, por correspondência exata
de KB, das páginas de histórico de atualizações da Microsoft (support.microsoft.com, "update history"); KB sem
correspondência fica de fora, sem estimativa.

Uso:
  msrc.py compactar-pasta ENTRADA SAIDA   compacta todos os CVE-*.json de ENTRADA; os listados em ENTRADA/404.txt
                                          (ou sem nenhum Windows Server) viram "ausente"
  msrc.py builds MAPA HTML...             junta ao MAPA (JSON) os pares KB -> build das páginas de histórico;
                                          o mapa só cresce (um KB nunca muda de build)
"""
import glob, json, os, re, sys

VERSOES = {"2016": "14393", "2019": "17763", "2022": "20348", "2025": "26100"}
RE_PRODUTO = re.compile(r"^Windows Server (2016|2019|2022|2025)( \(Server Core installation\))?$")
RE_KB = re.compile(r"^\d{6,8}$")
RE_BUILD = re.compile(r"^10\.0\.(\d{5})\.(\d{1,6})$")
FORMATO = 2
RE_HIST = re.compile(r"KB(\d{6,8}) \(OS Builds? ([^)]{1,120})\)")
RE_NUM = re.compile(r"\b(\d{5})\.(\d{1,6})\b")


def compactar(d):
    """{'v':2,'ws':{'2022':{'kb':'5031364','build':'10.0.20348.2031'}}, 'sev':..., 'cvss':...}; build "" quando o guia não informa."""
    ws, sev, cvss = {}, "", None
    for v in d.get("value") or []:
        m = RE_PRODUTO.match(v.get("product") or "")
        if not m:
            continue
        ver = m.group(1)
        sev = sev or (v.get("severity") or "")[:20]
        try:
            cvss = cvss if cvss is not None else (float(v["baseScore"]) if v.get("baseScore") else None)
        except ValueError:
            pass
        kbs = v.get("kbArticles") or []
        # A atualização cumulativa ("Security Update"); hotpatch e outras variantes ficam de fora.
        kbs = [k for k in kbs if (k.get("downloadName") or "") == "Security Update"] or kbs
        for k in kbs:
            kb, b = str(k.get("articleName") or ""), str(k.get("fixedBuildNumber") or "")
            if not RE_KB.match(kb):
                continue
            mb = RE_BUILD.match(b)
            if mb and mb.group(1) != VERSOES[ver]:
                continue
            b = b if mb else ""
            atual = ws.get(ver)
            # Vale o KB com build informado; entre dois com build, o de menor build (o primeiro que já corrige).
            if not atual or (b and not atual["build"]) or (b and atual["build"] and _t(b) < _t(atual["build"])):
                ws[ver] = {"kb": kb, "build": b}
            break
    if not ws:
        return {"v": FORMATO, "ausente": True}
    return {"v": FORMATO, "ws": ws, "sev": sev, "cvss": cvss}


def _t(b):
    return tuple(int(x) for x in b.split("."))


def builds(mapa, arquivos):
    """Junta ao mapa {"v":1,"kb":{"4601318":{"14393":"10.0.14393.4225"}}} os pares das páginas de histórico."""
    try:
        m = json.load(open(mapa, encoding="utf-8"))
        assert isinstance(m.get("kb"), dict)
    except (OSError, ValueError, AssertionError, AttributeError):
        m = {"v": 1, "kb": {}}
    majores = set(VERSOES.values())
    novos = 0
    for a in arquivos:
        try:
            txt = open(a, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for kb, dentro in RE_HIST.findall(txt):
            for maj, ubr in RE_NUM.findall(dentro):
                if maj not in majores:
                    continue
                b = "10.0.%s.%s" % (maj, ubr)
                atual = m["kb"].setdefault(kb, {}).get(maj)
                # "OS Builds X and Y": vale o menor.
                if not atual or _t(b) < _t(atual):
                    if not atual:
                        novos += 1
                    m["kb"][kb][maj] = b
    tmp = mapa + ".tmp"
    json.dump(m, open(tmp, "w", encoding="utf-8"), separators=(",", ":"), sort_keys=True)
    os.replace(tmp, mapa)
    print("Microsoft: %d pares KB -> build no mapa (%d novos)" % (sum(len(v) for v in m["kb"].values()), novos))


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "compactar-pasta":
        ent, sai = sys.argv[2], sys.argv[3]
        os.makedirs(sai, exist_ok=True)
        n = a = 0
        for f in glob.glob(os.path.join(ent, "CVE-*.json")):
            nome = os.path.basename(f)
            if not re.match(r"^CVE-\d{4}-\d{4,7}\.json$", nome):
                continue
            try:
                d = json.load(open(f, encoding="utf-8"))
            except (OSError, ValueError):
                continue
            c = compactar(d)
            json.dump(c, open(os.path.join(sai, nome), "w", encoding="utf-8"), separators=(",", ":"))
            if c.get("ausente"):
                a += 1
            else:
                n += 1
        try:
            for c in open(os.path.join(ent, "404.txt"), encoding="utf-8").read().split():
                if re.match(r"^CVE-\d{4}-\d{4,7}$", c):
                    json.dump({"v": FORMATO, "ausente": True}, open(os.path.join(sai, c + ".json"), "w", encoding="utf-8"))
                    a += 1
        except OSError:
            pass
        print("Microsoft: %d CVEs com Windows Server, %d sem Windows Server ou desconhecidos" % (n, a))
    elif len(sys.argv) >= 4 and sys.argv[1] == "builds":
        builds(sys.argv[2], sys.argv[3:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
