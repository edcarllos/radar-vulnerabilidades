#!/usr/bin/env python3
"""Radar de Vulnerabilidades: verificação COMPLETA (todo o histórico de CVEs da distro).

Usado em dois lugares, com o mesmo código:
  - na coleta (construir_dados.py), para gerar os índices por versão e o resumo do painel;
  - no servidor (embutido no radar-verificar.sh --completo), para avaliar os pacotes instalados.

Subcomandos:
  indice  --familia debian|ubuntu --codinome X --fonte ARQ [--kev kev.json] [--epss epss.csv.gz] [--uct uct.tsv] --saida ARQ
  uct     --saida ARQ   (lê "git archive HEAD active" do Ubuntu CVE Tracker pela entrada padrão)
  avaliar --indice ARQ [--minimo-nota N] [--csv]   (lê a lista do dpkg pela entrada padrão)

Formato do índice (texto, separador "|"):
  #radar-indice|1|<rel>|<codinome>|<data>
  P|<pacote-fonte>|<estado>|<versão corrigida ou ->|<CVE CVE ...>
     estados: c=corrigido, p=só Ubuntu Pro, a=confirmado sem correção, d=adiado/ignorado pela distro,
              t=em triagem, u=sem correção ou em triagem (sem dados para distinguir)
  K|<variante do kernel Ubuntu>|c|<versão>|<CVEs>        (Ubuntu: kernels por variante)
  C|<CVE>|<nota CVSS ou ->|<prioridade/urgência>|<data KEV ou ->|<EPSS 0-1 ou ->|<percentil EPSS ou ->
"""
import argparse, bz2, collections, datetime, json, re, sys

REL = {"bookworm": "deb12", "trixie": "deb13", "focal": "u2004", "jammy": "u2204", "noble": "u2404", "resolute": "u2604"}
RE_VER = re.compile(r"^[0-9][0-9A-Za-z.+~:-]{0,80}$")
RE_PKG = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,62}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


# ---------- comparação de versões no formato dpkg ----------
def _ordem(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_parte(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _ordem(a[i]) if i < len(a) else 0
            bc = _ordem(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        na = nb = ""
        while i < len(a) and a[i].isdigit():
            na += a[i]; i += 1
        while j < len(b) and b[j].isdigit():
            nb += b[j]; j += 1
        da, db = int(na or 0), int(nb or 0)
        if da != db:
            return da - db
    return 0


def cmp_versao(a, b):
    def div(v):
        e = 0
        if ":" in v:
            x, v = v.split(":", 1)
            e = int(x) if x.isdigit() else 0
        up, rev = (v.rsplit("-", 1) + [""])[:2] if "-" in v else (v, "")
        return e, up, rev
    ea, ua, ra = div(a)
    eb, ub, rb = div(b)
    if ea != eb:
        return ea - eb
    return _cmp_parte(ua, ub) or _cmp_parte(ra, rb)


# ---------- construção do índice ----------
def ler_kev(caminho):
    if not caminho:
        return {}
    try:
        d = json.load(open(caminho, encoding="utf-8"))
        return {v["cveID"]: v.get("dateAdded", "") for v in d.get("vulnerabilities", [])}
    except (OSError, ValueError):
        return {}


def ler_epss(caminho):
    """CSV diário da FIRST (epss_scores-current.csv.gz): cve,epss,percentile."""
    import gzip
    out = {}
    if not caminho:
        return out
    try:
        with gzip.open(caminho, "rt", encoding="utf-8") as f:
            for linha in f:
                p = linha.strip().split(",")
                if len(p) == 3 and RE_CVE.match(p[0]):
                    out[p[0]] = (p[1], p[2])
    except (OSError, EOFError):
        pass
    return out


ESTADOS_UCT = {"needs-triage": "t", "needed": "a", "pending": "a", "deferred": "d", "ignored": "d"}


def gerar_uct(args):
    """Lê o tar de 'active/' do Ubuntu CVE Tracker e grava codinome, pacote, CVE e estado (só não corrigidos)."""
    import tarfile
    rx = re.compile(r"^(%s)_(\S+?): (\S+)" % "|".join(c for c, r in REL.items() if r.startswith("u")))
    with open(args.saida, "w", encoding="utf-8") as out, tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as t:
        for m in t:
            if not m.isfile():
                continue
            cve = m.name.rsplit("/", 1)[-1]
            if not RE_CVE.match(cve):
                continue
            for linha in t.extractfile(m).read().decode("utf-8", "replace").splitlines():
                mm = rx.match(linha)
                if mm and mm.group(3) in ESTADOS_UCT and RE_PKG.match(mm.group(2)):
                    out.write("%s\t%s\t%s\t%s\n" % (mm.group(1), mm.group(2), cve, ESTADOS_UCT[mm.group(3)]))


def ler_uct(caminho, codinome):
    out = {}
    if not caminho:
        return None
    try:
        for linha in open(caminho, encoding="utf-8"):
            p = linha.rstrip("\n").split("\t")
            if len(p) == 4 and p[0] == codinome:
                out[(p[1], p[2])] = p[3]
    except OSError:
        return None
    return out


def ler_notas(caminho):
    notas = {}
    if not caminho:
        return notas
    try:
        for linha in open(caminho, encoding="utf-8"):
            p = linha.rstrip("\n").split("\t")
            if len(p) >= 3 and RE_CVE.match(p[0]):
                notas[p[0]] = (p[1], p[2])
    except OSError:
        pass
    return notas


def indice_debian(fonte, codinome):
    """Debian Security Tracker (tracker/data/json). Ignora 'unimportant' e 'not affected'."""
    d = json.load(open(fonte, encoding="utf-8"))
    grupos = collections.defaultdict(list)  # (pkg, estado, versão) -> [CVEs]
    meta = {}
    for pkg, cves in d.items():
        if not RE_PKG.match(pkg):
            continue
        for cve, info in cves.items():
            if not RE_CVE.match(cve):
                continue
            r = (info.get("releases") or {}).get(codinome)
            if not r:
                continue
            st, fv, urg = r.get("status"), r.get("fixed_version") or "", r.get("urgency") or ""
            if st == "resolved":
                if fv in ("", "0") or not RE_VER.match(fv):
                    continue
                grupos[(pkg, "c", fv)].append(cve)
            elif urg == "unimportant":
                continue
            elif st == "undetermined":
                grupos[(pkg, "t", "-")].append(cve)
            elif r.get("nodsa") or urg == "end-of-life":
                grupos[(pkg, "d", "-")].append(cve)
            else:
                grupos[(pkg, "a", "-")].append(cve)
            if urg and urg != "not yet assigned":
                meta[cve] = urg.replace("*", "")
    return grupos, {}, meta


RX_SRC = re.compile(r"^(\S+) source package in (esm-\w+/)?\w+, (is affected and has been fixed|might be affected and may need fixing)(?:\s*\(note: '([^']*)'\))?")
RX_KER = re.compile(r"^'(\S+)' kernel in \w+ was vulnerable but has been fixed \(note: '([^']*)'\)")


def indice_ubuntu(fonte, codinome, uct=None):
    """OVAL de CVEs da Canonical (com.ubuntu.<codinome>.cve.oval.xml.bz2), lido em fluxo."""
    import xml.etree.ElementTree as ET
    ns = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
    grupos = collections.defaultdict(list)
    kernels = collections.defaultdict(list)
    notas, meta = {}, {}
    for _, el in ET.iterparse(bz2.open(fonte), events=("end",)):
        if el.tag != ns + "definition":
            continue
        cves = []
        for c in el.iter(ns + "cve"):
            cid = (c.text or "").strip()
            if RE_CVE.match(cid):
                cves.append(cid)
                if c.get("cvss_score"):
                    notas[cid] = c.get("cvss_score")
                if c.get("priority"):
                    meta[cid] = c.get("priority")
        for cr in el.iter(ns + "criterion"):
            com = cr.get("comment", "")
            m = RX_SRC.match(com)
            if m:
                pkg, esm, frase, ver = m.group(1), m.group(2), m.group(3), m.group(4)
                if not RE_PKG.match(pkg):
                    continue
                if frase.startswith("is affected and has been fixed"):
                    if ver and RE_VER.match(ver):
                        estado = "p" if esm else "c"
                        for cid in cves:
                            grupos[(pkg, estado, ver)].append(cid)
                else:
                    for cid in cves:
                        est = "u" if uct is None else uct.get((pkg, cid), "t")
                        grupos[(pkg, est, "-")].append(cid)
                continue
            m = RX_KER.match(com)
            if m and RE_PKG.match(m.group(1)) and RE_VER.match(m.group(2)):
                for cid in cves:
                    kernels[(m.group(1), "c", m.group(2))].append(cid)
        el.clear()
    return grupos, kernels, meta, notas


def mesclar_usns(grupos, pasta, codinome):
    """O OVAL pode atrasar em relação aos USNs: acrescenta as versões corrigidas dos avisos recentes."""
    import glob, os
    vistos = set()
    for f in sorted(glob.glob(os.path.join(pasta, "*.json"))):
        try:
            d = json.load(open(f, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for n in d.get("notices", []):
            if n.get("id") in vistos:
                continue
            vistos.add(n.get("id"))
            cves = [c for c in n.get("cves_ids", []) if RE_CVE.match(c)]
            for p in (n.get("release_packages") or {}).get(codinome, []):
                nome, ver = p.get("name", ""), p.get("version", "")
                if p.get("is_source") and RE_PKG.match(nome) and RE_VER.match(ver) and cves:
                    grupos[(nome, "p" if "esm" in ver else "c", ver)].extend(cves)


def gerar_indice(args):
    kev = ler_kev(args.kev)
    epss = ler_epss(args.epss)
    notas_ext = ler_notas(args.notas)
    if args.familia == "debian":
        grupos, kernels, meta = indice_debian(args.fonte, args.codinome)
        notas = {}
    else:
        grupos, kernels, meta, notas = indice_ubuntu(args.fonte, args.codinome, ler_uct(args.uct, args.codinome))
        if args.usn:
            mesclar_usns(grupos, args.usn, args.codinome)
    usados = set()
    linhas = []
    for (pkg, est, ver), cves in sorted(grupos.items()):
        cves = sorted(set(cves))
        usados.update(cves)
        linhas.append("P|%s|%s|%s|%s" % (pkg, est, ver, " ".join(cves)))
    for (flav, est, ver), cves in sorted(kernels.items()):
        cves = sorted(set(cves))
        usados.update(cves)
        linhas.append("K|%s|%s|%s|%s" % (flav, est, ver, " ".join(cves)))
    for cid in sorted(usados):
        nota = notas.get(cid) or (notas_ext.get(cid) or ("", ""))[0] or "-"
        prio = meta.get(cid) or (notas_ext.get(cid) or ("", ""))[1] or "-"
        e = epss.get(cid, ("-", "-"))
        linhas.append("C|%s|%s|%s|%s|%s|%s" % (cid, nota, prio, kev.get(cid, "-"), e[0], e[1]))
    cab = "#radar-indice|2|%s|%s|%s" % (REL.get(args.codinome, "?"), args.codinome, args.data or datetime.date.today().isoformat())
    with open(args.saida, "w", encoding="utf-8") as f:
        f.write(cab + "\n" + "\n".join(linhas) + "\n")
    if args.notas_saida and args.familia == "ubuntu":
        with open(args.notas_saida, "a", encoding="utf-8") as f:
            for cid, n in notas.items():
                f.write("%s\t%s\t%s\n" % (cid, n, meta.get(cid, "")))


# ---------- leitura do índice ----------
def ler_indice(caminho):
    pacotes = collections.defaultdict(list)
    kernels = collections.defaultdict(list)
    cves = {}
    cab = None
    for linha in open(caminho, encoding="utf-8"):
        linha = linha.rstrip("\n")
        if linha.startswith("#radar-indice"):
            cab = linha.split("|")
            continue
        p = linha.split("|")
        if p[0] in ("P", "K") and len(p) == 5:
            alvo = pacotes if p[0] == "P" else kernels
            alvo[p[1]].append((p[2], p[3], p[4].split()))
        elif p[0] == "C" and len(p) in (5, 7):
            num = lambda x: float(x) if re.match(r"^\d+(\.\d+)?(e-?\d+)?$", x or "") else None
            ep = num(p[5]) if len(p) == 7 else None
            pc = num(p[6]) if len(p) == 7 else None
            cves[p[1]] = (num(p[2]), p[3], None if p[4] == "-" else p[4], ep, pc)
    if not cab:
        raise SystemExit("Arquivo de índice inválido (sem cabeçalho #radar-indice).")
    return cab, pacotes, kernels, cves


# ---------- risco ----------
ABERTOS = ("a", "d", "t", "u")


def chave_risco(cves, c):
    """Ordena por exploração real: KEV, depois EPSS, depois CVSS."""
    nota, _, kev, ep, _ = cves.get(c, (None, None, None, None, None))
    return (0 if kev else 1, -(ep or 0), -(nota or 0))


def estados_abertos(grupos):
    """CVE -> estado aberto (a, d, t ou u), descontando os já corrigidos naquela fonte."""
    corr = set()
    abertos = {}
    for est, ver, lst in grupos:
        if est in ("c", "p"):
            corr.update(lst)
    prio = {"a": 0, "u": 1, "d": 2, "t": 3}
    for est, ver, lst in grupos:
        if est in ABERTOS:
            for c in lst:
                if c in corr:
                    continue
                if c not in abertos or prio[est] < prio[abertos[c]]:
                    abertos[c] = est
    return abertos, corr


# ---------- resumo para o painel ----------
def resumo(caminho):
    cab, pacotes, kernels, cves = ler_indice(caminho)
    por_pkg = []
    tot = collections.defaultdict(set)
    kev_abertos = set()
    for pkg, grupos in pacotes.items():
        abertos, corr = estados_abertos(grupos)
        pro = set(c for est, ver, lst in grupos if est == "p" for c in lst) - corr
        cont = collections.Counter(abertos.values())
        kev_ab = sorted(c for c in abertos if cves.get(c, (None,) * 5)[2])
        kev_tot = sorted(c for c in set(abertos) | corr | pro if cves.get(c, (None,) * 5)[2])
        notas = [cves[c][0] for c in abertos if c in cves and cves[c][0] is not None]
        epss = [cves[c][3] for c in abertos if c in cves and cves[c][3] is not None]
        for c, e in abertos.items():
            tot[e].add(c)
        kev_abertos.update(kev_ab)
        if not (abertos or kev_tot or pro):
            continue
        top = sorted((c for c, e in abertos.items() if e in ("a", "u")), key=lambda c: chave_risco(cves, c))[:3]
        por_pkg.append({"p": pkg, "a": cont["a"], "u": cont["u"], "d": cont["d"], "t": cont["t"], "c": len(corr), "pro": len(pro),
                        "ka": len(kev_ab), "kt": len(kev_tot), "n": max(notas) if notas else None,
                        "e": round(max(epss), 5) if epss else None, "top": top, "kev": kev_tot[:5]})
    por_pkg.sort(key=lambda x: (-x["ka"], -(x["e"] or 0), -(x["n"] or 0), -(x["a"] + x["u"])))
    return {"rel": cab[2], "codinome": cab[3], "data": cab[4], "pacotes_com_cve": len(pacotes),
            "confirmados": len(tot["a"]), "sem_distincao": len(tot["u"]), "adiados": len(tot["d"]), "em_triagem": len(tot["t"]),
            "cves_abertos": len(set().union(*tot.values())) if tot else 0, "cves_kev_abertos": len(kev_abertos),
            "kernels": sorted(kernels.keys()), "itens": por_pkg}


# ---------- avaliação no servidor ----------
ROTULOS = {
    "CORRECAO_DISPONIVEL": "CORREÇÃO DISPONÍVEL (atualize)",
    "SO_UBUNTU_PRO": "CORREÇÃO SÓ NO UBUNTU PRO (ESM)",
    "SEM_CORRECAO": "CONFIRMADO, SEM CORREÇÃO NA DISTRO",
    "SEM_DISTINCAO": "SEM CORREÇÃO OU EM TRIAGEM (sem dados para separar; use --dados do painel)",
    "ADIADO": "ADIADO OU IGNORADO PELA DISTRO (risco considerado baixo)",
    "EM_TRIAGEM": "EM TRIAGEM (a distro ainda não avaliou; muitos não afetam)",
}
ESTADO_STATUS = {"a": "SEM_CORRECAO", "u": "SEM_DISTINCAO", "d": "ADIADO", "t": "EM_TRIAGEM"}
ORDEM = ["CORRECAO_DISPONIVEL", "SO_UBUNTU_PRO", "SEM_CORRECAO", "SEM_DISTINCAO", "ADIADO", "EM_TRIAGEM"]


def _avaliar_fonte(grupos, versao, rotulo, bins, resultados):
    abertos, _ = estados_abertos(grupos)
    vulner, pro, ok = {}, {}, set()
    for est, ver, lst in grupos:
        if est not in ("c", "p"):
            continue
        if cmp_versao(versao, ver) < 0:
            alvo = pro if est == "p" else vulner
            for c in lst:
                if c not in alvo or cmp_versao(ver, alvo[c]) > 0:
                    alvo[c] = ver
        else:
            ok.update(lst)
    for c, ver in vulner.items():
        resultados.append(("CORRECAO_DISPONIVEL", rotulo, versao, ver, c))
    for c, ver in pro.items():
        if c not in vulner:
            resultados.append(("SO_UBUNTU_PRO", rotulo, versao, ver, c))
    for c, est in abertos.items():
        if c not in vulner and c not in pro and c not in ok:
            resultados.append((ESTADO_STATUS[est], rotulo, versao, "-", c))


def avaliar(args):
    cab, pacotes, kernels, cves = ler_indice(args.indice)
    instalados = {}  # fonte -> (versão da fonte, [binários])
    for linha in sys.stdin:
        p = linha.rstrip("\n").split("\t")
        if len(p) < 4 or not p[0].startswith("ii"):
            continue
        bin_, src, sver = p[1], p[2] or p[1].split(":")[0], p[3]
        if not RE_VER.match(sver or ""):
            continue
        atual = instalados.get(src)
        if atual is None or cmp_versao(sver, atual[0]) > 0:
            instalados[src] = (sver, (atual[1] if atual else []) + [bin_])
        else:
            atual[1].append(bin_)
    debian = cab[2].startswith("deb")
    resultados = []
    for src, (sver, bins) in instalados.items():
        if src.startswith("linux-signed") or (debian and src == "linux"):
            continue  # kernel: vale o que está em execução
        if src in pacotes:
            _avaliar_fonte(pacotes[src], sver, src, bins, resultados)
    if debian and args.kernel_versao and pacotes.get("linux"):
        _avaliar_fonte(pacotes["linux"], args.kernel_versao, "linux (em execução)", [], resultados)
    elif args.kernel_fonte and args.kernel_versao:
        flav = args.kernel_fonte.replace("linux-signed", "linux")
        if flav in kernels:
            _avaliar_fonte(kernels[flav], args.kernel_versao, flav + " (em execução)", [], resultados)
    epss_min = (args.epss_minimo or 0) / 100.0
    linhas = []
    for st, src, inst, fix, c in resultados:
        nota, prio, kev, ep, pc = cves.get(c, (None, "-", None, None, None))
        if not kev and ((args.minimo_nota and (nota or 0) < args.minimo_nota) or (epss_min and (ep or 0) < epss_min)):
            continue
        linhas.append((st, src, inst, fix, c, nota, prio, kev, ep, pc))
    linhas.sort(key=lambda x: (ORDEM.index(x[0]), x[1], chave_risco(cves, x[4])))
    if args.json or args.json_linhas:
        campos = ("status", "pacote", "instalado", "corrigido_em", "cve", "cvss", "prioridade", "kev", "epss", "percentil_epss")
        objs = [dict(zip(campos, l)) for l in linhas]
        if args.json_linhas:
            for o in objs:
                o2 = {"radar": "completo", "host": args.host, "distro": cab[2]}
                o2.update(o)
                print(json.dumps(o2, ensure_ascii=False))
        else:
            tot = collections.Counter(l[0] for l in linhas)
            print(json.dumps({"radar": "completo", "host": args.host, "distro": cab[2], "indice_data": cab[4],
                              "pacotes_avaliados": len(instalados),
                              "resumo": {k.lower(): tot.get(k, 0) for k in ORDEM},
                              "kev": sorted({l[4] for l in linhas if l[7]}),
                              "itens": objs}, ensure_ascii=False))
        return 1 if any(l[0] == "CORRECAO_DISPONIVEL" for l in linhas) else 0
    if args.csv:
        print("status;pacote_fonte;instalado;corrigido_em;cve;cvss;prioridade;kev;epss;percentil_epss")
        fmt = lambda v: "" if v is None else (("%.5f" % v) if isinstance(v, float) and v < 1.0001 and v != int(v) else (("%.1f" % v) if isinstance(v, float) else str(v)))
        for l in linhas:
            print(";".join(fmt(v) for v in l))
        return 1 if any(l[0] == "CORRECAO_DISPONIVEL" for l in linhas) else 0
    por = collections.OrderedDict()
    for l in linhas:
        por.setdefault((l[0], l[1]), []).append(l)
    tot = collections.Counter(l[0] for l in linhas)
    print("Índice: %s (%s), dados de %s" % (cab[2], cab[3], cab[4]))
    print("Pacotes-fonte instalados avaliados: %d" % len(instalados))
    print("Ordem: exploração confirmada (KEV), depois probabilidade de exploração em 30 dias (EPSS), depois nota CVSS.")
    for st in ORDEM:
        grupos = [(k, v) for k, v in por.items() if k[0] == st]
        if not grupos:
            continue
        def risco_pkg(item):
            ls = item[1]
            return (0 if any(l[7] for l in ls) else 1, -max((l[8] or 0) for l in ls), -max((l[5] or 0) for l in ls))
        grupos.sort(key=risco_pkg)
        print("\n== %s: %d CVE(s) em %d pacote(s)" % (ROTULOS[st], tot[st], len(grupos)))
        limite = args.limite if st not in ("CORRECAO_DISPONIVEL", "SO_UBUNTU_PRO") else 10 ** 6
        for n, ((_, src), ls) in enumerate(grupos):
            if n >= limite:
                print("  ... mais %d pacote(s) (use --csv para a lista completa)" % (len(grupos) - limite))
                break
            notas = [l[5] for l in ls if l[5] is not None]
            kevs = [l[4] for l in ls if l[7]]
            pior_e = max(ls, key=lambda l: l[8] or 0)
            fix = "-"
            for l in ls:
                if l[3] != "-" and (fix == "-" or cmp_versao(l[3], fix) > 0):
                    fix = l[3]
            ep_txt = ("  EPSS %.1f%% (%s)" % (pior_e[8] * 100, pior_e[4])) if pior_e[8] else ""
            print("  [%4s] %s %s%s: %d CVE(s)%s%s" % (("%.1f" % max(notas)) if notas else "-", src, ls[0][2],
                  (" -> " + fix) if fix != "-" else "", len(ls), ep_txt, ("  KEV: " + ", ".join(kevs[:3])) if kevs else ""))
    if not linhas:
        print("\nNenhum CVE aplicável aos pacotes instalados com estes filtros.")
    return 1 if tot["CORRECAO_DISPONIVEL"] else 0


def main():
    import signal
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)  # saída cortada por head/less sem erro
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("indice")
    a.add_argument("--familia", choices=["debian", "ubuntu"], required=True)
    a.add_argument("--codinome", choices=sorted(REL), required=True)
    a.add_argument("--fonte", required=True)
    a.add_argument("--kev")
    a.add_argument("--notas")
    a.add_argument("--notas-saida")
    a.add_argument("--usn", help="pasta com páginas de notices.json da Ubuntu (opcional)")
    a.add_argument("--epss", help="epss_scores-current.csv.gz da FIRST (opcional)")
    a.add_argument("--uct", help="estados do Ubuntu CVE Tracker gerados pelo subcomando uct (opcional)")
    u = sub.add_parser("uct")
    u.add_argument("--saida", required=True)
    a.add_argument("--data")
    a.add_argument("--saida", required=True)
    r = sub.add_parser("resumo")
    r.add_argument("--indice", required=True)
    v = sub.add_parser("avaliar")
    v.add_argument("--indice", required=True)
    v.add_argument("--minimo-nota", type=float, default=0)
    v.add_argument("--epss-minimo", type=float, default=0, help="percentual (0-100)")
    v.add_argument("--limite", type=int, default=25)
    v.add_argument("--csv", action="store_true")
    v.add_argument("--json", action="store_true")
    v.add_argument("--json-linhas", action="store_true")
    v.add_argument("--host", default="")
    v.add_argument("--kernel-fonte", default="")
    v.add_argument("--kernel-versao", default="")
    args = ap.parse_args()
    if args.cmd == "indice":
        gerar_indice(args)
    elif args.cmd == "uct":
        gerar_uct(args)
    elif args.cmd == "resumo":
        json.dump(resumo(args.indice), sys.stdout, ensure_ascii=False)
    else:
        sys.exit(avaliar(args))


if __name__ == "__main__":
    main()
