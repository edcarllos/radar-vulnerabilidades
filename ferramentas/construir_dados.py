#!/usr/bin/env python3
"""Monta site/vulns.json a partir de itens.json e dos dados oficiais baixados por coletar.sh.

Uso: python3 -I construir_dados.py --cache DIR [--projeto DIR] [--listar-cves]

Fontes lidas do cache (todas oficiais):
  kev.json            CISA Known Exploited Vulnerabilities
  deb.json            Debian Security Tracker (tracker/data/json)
  dsa-list.txt        lista de DSAs (salsa security-tracker)
  dla-list.txt        lista de DLAs (Debian LTS)
  usn/*.json          páginas de https://ubuntu.com/security/notices.json
  ubuntu/CVE-*.json   https://ubuntu.com/security/cves/<CVE>.json
  nvd/CVE-*.json      https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>

Regra central: só um estado "corrigido"/"parcial"/"pro" com versão validada
permite que um script imprima OK. Falta de dado vira "nao_verificado".
"""
import argparse, datetime, glob, hashlib, json, os, re, sys

RELEASES = {
    "deb12": {"familia": "debian", "codinome": "bookworm", "rotulo": "Debian 12 (bookworm)", "nota": "Suporte LTS: correções chegam como DLA"},
    "deb13": {"familia": "debian", "codinome": "trixie", "rotulo": "Debian 13 (trixie)", "nota": ""},
    "u2204": {"familia": "ubuntu", "codinome": "jammy", "rotulo": "Ubuntu 22.04 LTS (jammy)", "nota": ""},
    "u2404": {"familia": "ubuntu", "codinome": "noble", "rotulo": "Ubuntu 24.04 LTS (noble)", "nota": ""},
    "u2604": {"familia": "ubuntu", "codinome": "resolute", "rotulo": "Ubuntu 26.04 LTS (resolute)", "nota": ""},
}
POR_AVISO = {}  # (aviso, codinome, pacote) -> versão publicada pelo aviso
ESTADOS = {"corrigido", "parcial", "pro", "sem_correcao", "em_triagem", "nao_afetado", "nao_empacotado", "nao_verificado"}

RE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{2,60}$")
RE_PKG = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,62}$")
RE_VER = re.compile(r"^[0-9][0-9A-Za-z.+~:-]{0,80}$")
RE_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
RE_AVISO = re.compile(r"^((DSA|DLA|USN)-\d{3,5}-\d{1,2}|SA-CORE-\d{4}-\d{3})$")
RE_APPVER = re.compile(r"^\d+(\.\d+){1,3}$")
RE_DATA = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def aviso(msg):
    print("AVISO: " + msg, file=sys.stderr)


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
        dif = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _ordem(a[i]) if i < len(a) else 0
            bc = _ordem(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not dif:
                dif = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if dif:
            return dif
    return 0


def _divide(v):
    epoca = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoca = int(e) if e.isdigit() else 0
    if "-" in v:
        up, rev = v.rsplit("-", 1)
    else:
        up, rev = v, ""
    return epoca, up, rev


def cmp_versao(a, b):
    ea, ua, ra = _divide(a)
    eb, ub, rb = _divide(b)
    if ea != eb:
        return ea - eb
    r = _cmp_parte(ua, ub)
    return r if r else _cmp_parte(ra, rb)


def maior_versao(vs):
    m = None
    for v in vs:
        if m is None or cmp_versao(v, m) > 0:
            m = v
    return m


# ---------- leitura das fontes ----------
def ler_json(caminho, padrao=None):
    try:
        with open(caminho, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return padrao


def ler_avisos_debian(cache):
    """Retorna (cves_por_aviso, versoes[(aviso_tipo, codinome, pkg, versao)] -> id)."""
    cves, versoes, datas = {}, {}, {}
    for nome in ("dsa-list.txt", "dla-list.txt"):
        atual = None
        try:
            linhas = open(os.path.join(cache, nome), encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            aviso("sem " + nome)
            continue
        for linha in linhas:
            m = re.match(r"^\[(\d+ \w+ \d{4})\] (D[SL]A-\d+-\d+) ", linha)
            if m:
                atual = m.group(2)
                try:
                    datas[atual] = datetime.datetime.strptime(m.group(1), "%d %b %Y").strftime("%Y-%m-%d")
                except ValueError:
                    pass
                continue
            if not atual:
                continue
            m = re.match(r"^\s+\{(.*)\}", linha)
            if m:
                cves[atual] = m.group(1).split()
                continue
            m = re.match(r"^\s+\[(\w+)\] - (\S+) (\S+)", linha)
            if m:
                versoes[(m.group(1), m.group(2), m.group(3))] = atual
                POR_AVISO[(atual, m.group(1), m.group(2))] = m.group(3)
    return cves, versoes, datas


def ler_usns(cache):
    cves, versoes, datas = {}, {}, {}
    for f in glob.glob(os.path.join(cache, "usn", "*.json")):
        dados = ler_json(f, {}) or {}
        for n in dados.get("notices", []):
            cves[n["id"]] = n.get("cves_ids", [])
            datas[n["id"]] = (n.get("published") or "")[:10]
            for cod, pacotes in (n.get("release_packages") or {}).items():
                for p in pacotes:
                    if p.get("is_source"):
                        versoes[(cod, p.get("name"), p.get("version"))] = n["id"]
                        POR_AVISO[(n["id"], cod, p.get("name"))] = p.get("version")
    return cves, versoes, datas


def nota_nvd(cache, cve):
    if cve in NVD_IDX:
        n = _nota_de_metricas(NVD_IDX[cve].get("metrics") or {})
        if n:
            n["cve"] = cve
        return n
    d = ler_json(os.path.join(cache, "nvd", cve + ".json"))
    try:
        m = d["vulnerabilities"][0]["cve"]["metrics"]
    except (TypeError, KeyError, IndexError):
        return None
    for chave, versao in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if m.get(chave):
            dados = m[chave][0]["cvssData"]
            return {"valor": float(dados["baseScore"]), "versao": versao, "fonte": "NVD", "cve": cve}
    return None


def dados_ubuntu(cache, cve):
    return ler_json(os.path.join(cache, "ubuntu", cve + ".json"))


PRIORIDADES = ["negligible", "low", "medium", "high", "critical"]


# ---------- cálculo por pacote ----------
def estado_debian(deb, pkg, codinome, cves):
    fixos, abertos, sem_impacto, na, dne, sem_dado = [], [], [], [], [], []
    for cve in cves:
        info = (deb.get(pkg) or {}).get(cve)
        if info is None:
            sem_dado.append(cve)
            continue
        rel = (info.get("releases") or {}).get(codinome)
        if rel is None:
            dne.append(cve)
            continue
        st = rel.get("status")
        fv = rel.get("fixed_version") or ""
        if st == "resolved":
            if fv == "0":
                na.append(cve)
            else:
                fixos.append((cve, fv))
        elif rel.get("urgency") == "unimportant":
            sem_impacto.append(cve)
        else:
            abertos.append(cve)
    return fixos, abertos, sem_impacto, na, dne, sem_dado


def estado_ubuntu(cache, pkg, codinome, cves, triagem):
    fixos, abertos, sem_impacto, na, dne, sem_dado = [], [], [], [], [], []
    for cve in cves:
        d = dados_ubuntu(cache, cve)
        if not d or not d.get("id"):
            sem_dado.append(cve)
            continue
        pacote = next((p for p in d.get("packages", []) if p.get("name") == pkg), None)
        if pacote is None:
            sem_dado.append(cve)
            continue
        st = next((s for s in pacote.get("statuses", []) if s.get("release_codename") == codinome), None)
        if st is None:
            dne.append(cve)
            continue
        s = st.get("status")
        if s == "released":
            fixos.append((cve, (st.get("description") or "").strip()))
        elif s == "not-affected":
            na.append(cve)
        elif s == "DNE":
            dne.append(cve)
        else:
            abertos.append(cve)
            if s == "needs-triage":
                triagem.append(cve)
    return fixos, abertos, sem_impacto, na, dne, sem_dado


def linha_pacote(rel_id, pkg, cves, deb, cache, avisos_deb, avisos_usn):
    r = RELEASES[rel_id]
    triagem = []
    if r["familia"] == "debian":
        fixos, abertos, sem_impacto, na, dne, sem_dado = estado_debian(deb, pkg, r["codinome"], cves)
    else:
        fixos, abertos, sem_impacto, na, dne, sem_dado = estado_ubuntu(cache, pkg, r["codinome"], cves, triagem)
    avaliados = len(cves) - len(sem_dado)
    if avaliados == 0:
        return None
    fixos = [(c, v) for c, v in fixos if RE_VER.match(v or "")]
    linha = {"pacote": pkg, "cves_avaliados": avaliados, "abertos": abertos, "sem_impacto": sem_impacto, "em_triagem": len(triagem)}
    if fixos:
        versao = maior_versao([v for _, v in fixos])
        linha["versao"] = versao
        linha["ubuntu_pro"] = "esm" in versao
        if abertos:
            linha["estado"] = "parcial"
        elif "esm" in versao:
            linha["estado"] = "pro"
        else:
            linha["estado"] = "corrigido"
        chave = (r["codinome"], pkg, versao)
        linha["aviso"] = (avisos_deb if r["familia"] == "debian" else avisos_usn).get(chave, "")
    elif abertos:
        linha["estado"] = "em_triagem" if len(triagem) == len(abertos) else "sem_correcao"
    elif dne and not na and not sem_impacto:
        linha["estado"] = "nao_empacotado"
    else:
        linha["estado"] = "nao_afetado"
    return linha


def aplicar_piso_avisos(linha, avisos, codinome, item_id):
    """A versão mínima nunca fica abaixo do que um aviso citado pelo item publicou para esta versão/pacote."""
    for a in avisos:
        v = POR_AVISO.get((a, codinome, linha["pacote"]))
        if not v or not RE_VER.match(v):
            continue
        atual = linha.get("versao")
        if not atual or cmp_versao(v, atual) > 0:
            if atual:
                aviso("%s: mínimo de %s em %s elevado de %s para %s (%s)" % (item_id, linha["pacote"], codinome, atual, v, a))
            linha["versao"] = v
            linha["aviso"] = a
            if linha.get("estado") in ("sem_correcao", "em_triagem", "nao_verificado", "nao_afetado", "nao_empacotado"):
                linha["estado"] = "parcial" if linha.get("abertos") else "corrigido"
            if "esm" in v:
                linha["ubuntu_pro"] = True


def validar_linha(linha, item_id):
    ok = RE_PKG.match(linha.get("pacote", "")) and linha.get("estado") in ESTADOS
    if linha.get("versao") and not RE_VER.match(linha["versao"]):
        ok = False
    if linha.get("aviso") and not RE_AVISO.match(linha["aviso"]):
        linha["aviso"] = ""
    if linha.get("estado") in ("corrigido", "parcial", "pro") and not linha.get("versao"):
        ok = False
    if not ok:
        aviso("linha descartada em %s: %r" % (item_id, linha))
    return bool(ok)


# ---------- NVD por produto (sistemas fora das distros ou com poucos avisos de distro) ----------
JANELA_NVD_DIAS = 90
NVD_IDX = {}  # CVE -> objeto cve da NVD vindo das consultas por produto


def consultas_nvd(it, data):
    """Lista (arquivo, url) das consultas NVD de um item, na janela móvel."""
    from urllib.parse import quote
    n = it.get("nvd")
    if not n:
        return []
    fim = datetime.date.fromisoformat(data)
    ini = fim - datetime.timedelta(days=JANELA_NVD_DIAS)
    datas = "&pubStartDate=%sT00:00:00.000&pubEndDate=%sT23:59:59.999" % (ini.isoformat(), fim.isoformat())
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=500"
    out = []
    for i, cpe in enumerate(n.get("cpe", [])):
        if re.match(r"^cpe:2\.3:[aoh*]:[a-z0-9_\\&.-]+(:[a-z0-9_\\&.-]+)?$", cpe):
            out.append(("%s__cpe%d.json" % (it["id"], i), base + "&virtualMatchString=" + quote(cpe, safe=":*") + datas))
    if n.get("palavra") and re.match(r"^[\w .\-À-ÿ]{2,60}$", n["palavra"]):
        out.append(("%s__palavra.json" % it["id"], base + "&keywordSearch=" + quote(n["palavra"]) + "&keywordExactMatch" + datas))
    return out


NVD_DESCARTES = {}


def resultados_nvd(cache, it):
    """CVEs das consultas do item: CPE sempre; palavra-chave só se a descrição casar com o filtro do item."""
    n = it.get("nvd") or {}
    rx = re.compile(n["regex"]) if n.get("regex") else (re.compile(r"\b" + re.escape(n["palavra"]) + r"\b") if n.get("palavra") else None)
    minimo = float(n.get("nota_minima", 0))
    produtos = {":".join(x.split(":")[3:5]) for x in n.get("cpe", []) if x.count(":") >= 4}
    achados, descartes = {}, {}
    for arq, _ in consultas_nvd(it, "2000-01-01"):
        d = ler_json(os.path.join(cache, "nvd-produtos", arq), {}) or {}
        por_cpe = "__cpe" in arq
        for v in d.get("vulnerabilities", []):
            c = v.get("cve") or {}
            cid = c.get("id", "")
            if not RE_CVE.match(cid):
                continue
            desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
            if not por_cpe and rx and not rx.search(desc):
                continue
            if not por_cpe and n.get("excluir") and re.search(n["excluir"], desc):
                continue
            if not por_cpe and produtos and cid not in achados:
                # F11: CVE já analisado pela NVD (com CPEs) cujo produto não é o do item = falso positivo da palavra-chave.
                crit = [m.get("criteria", "") for cfg in c.get("configurations", []) or [] for no in cfg.get("nodes", []) or []
                        for m in no.get("cpeMatch", []) or [] if m.get("vulnerable")]
                # Mesmo fornecedor (FortiMail, plugins do Jenkins) ou mesmo produto com outro fornecedor (pfsense:pfsense) continuam.
                if crit and not any(len(x.split(":")) > 4 and (x.split(":")[3] in {p.split(":")[0] for p in produtos}
                                                              or x.split(":")[4] in {p.split(":")[1] for p in produtos}) for x in crit):
                    descartes.setdefault(cid, sorted({":".join(x.split(":")[3:5]) for x in crit})[:3])
                    continue
            descartes.pop(cid, None)
            achados[cid] = c
    out = []
    for cid, c in achados.items():
        nota = _nota_de_metricas(c.get("metrics") or {})
        if minimo and (nota is None or nota["valor"] < minimo):
            continue
        NVD_IDX[cid] = c
        out.append(cid)
    NVD_DESCARTES[it["id"]] = [{"cve": cid, "produtos": prods} for cid, prods in sorted(descartes.items()) if cid not in achados]
    return out


def _nota_de_metricas(m):
    for chave, versao in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if m.get(chave):
            return {"valor": float(m[chave][0]["cvssData"]["baseScore"]), "versao": versao, "fonte": "NVD"}
    return None


def detalhe_nvd(cid, kev_idx):
    c = NVD_IDX.get(cid) or {}
    nota = _nota_de_metricas(c.get("metrics") or {})
    desc = next((x["value"] for x in c.get("descriptions", []) if x.get("lang") == "en"), "")
    corr = set()
    for cfg in c.get("configurations", []) or []:
        for no in cfg.get("nodes", []) or []:
            for cm in no.get("cpeMatch", []) or []:
                v = cm.get("versionEndExcluding")
                if cm.get("vulnerable") and v and RE_VER.match(v):
                    corr.add(v)
    return {"cve": cid, "nota": nota["valor"] if nota else None, "cvss": nota["versao"] if nota else None,
            "publicado": (c.get("published") or "")[:10], "kev": kev_idx.get(cid, {}).get("dateAdded"),
            "corrigido_em": sorted(corr, key=lambda x: [int(p) if p.isdigit() else p for p in re.split(r"[.-]", x)])[:6],
            "resumo": limpar_texto(desc, 260)}


def gerar_historico(cache, saida_dir, data):
    """Índices completos (todo CVE conhecido por versão de distro) e resumo por pacote para o painel."""
    import importlib.util, types
    spec = importlib.util.spec_from_file_location("completo", os.path.join(os.path.dirname(os.path.abspath(__file__)), "completo.py"))
    comp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(comp)
    pasta = os.path.join(saida_dir, "indices")
    os.makedirs(pasta, exist_ok=True)
    notas = os.path.join(cache, "notas-ubuntu.tsv")
    open(notas, "w").close()
    kev = os.path.join(cache, "kev.json")
    epss_arq = os.path.join(cache, "epss.csv.gz") if os.path.exists(os.path.join(cache, "epss.csv.gz")) else None
    uct = os.path.join(cache, "uct.tsv")
    feitos = {}
    for rel_id, r in RELEASES.items():
        if r["familia"] != "ubuntu":
            continue
        oval = os.path.join(cache, "oval", "com.ubuntu.%s.cve.oval.xml.bz2" % r["codinome"])
        if not os.path.exists(oval):
            aviso("sem OVAL para %s; histórico completo não gerado" % r["codinome"])
            continue
        a = types.SimpleNamespace(familia="ubuntu", codinome=r["codinome"], fonte=oval, kev=kev, notas=None,
                                  notas_saida=notas, data=data, usn=os.path.join(cache, "usn"), epss=epss_arq,
                                  uct=uct if os.path.exists(uct) else None,
                                  saida=os.path.join(pasta, "idx-%s.txt" % rel_id))
        comp.gerar_indice(a)
        feitos[rel_id] = a.saida
    for rel_id, r in RELEASES.items():
        if r["familia"] != "debian":
            continue
        a = types.SimpleNamespace(familia="debian", codinome=r["codinome"], fonte=os.path.join(cache, "deb.json"), kev=kev,
                                  notas=notas, notas_saida=None, data=data, usn=None, epss=epss_arq, uct=None,
                                  saida=os.path.join(pasta, "idx-%s.txt" % rel_id))
        comp.gerar_indice(a)
        feitos[rel_id] = a.saida
    resumo = {}
    for rel_id in RELEASES:
        if rel_id in feitos:
            res = comp.resumo(feitos[rel_id])
            res["arquivo"] = "indices/idx-%s.txt" % rel_id
            res["bytes"] = os.path.getsize(feitos[rel_id])
            resumo[rel_id] = res
    with open(os.path.join(saida_dir, "historico.json"), "w", encoding="utf-8") as f:
        json.dump({"gerado_em": data, "versoes": resumo}, f, ensure_ascii=False, separators=(",", ":"))
    return resumo


# ---------- F4: decisão SSVC (exploração, automatizável, impacto, missão) ----------
ORDEM_EXPL = {"none": 0, "poc": 1, "active": 2}
PRAZOS = {"agir_agora": 1, "agir_em_breve": 7, "acompanhar_de_perto": 30, "acompanhar": 90}
ROTULO_DECISAO = {"agir_agora": "Agir agora", "agir_em_breve": "Agir em breve",
                  "acompanhar_de_perto": "Acompanhar de perto", "acompanhar": "Acompanhar", "nao_se_aplica": "Não se aplica"}


def _metricas_nvd(cache, cve):
    c = NVD_IDX.get(cve)
    if c is None:
        d = ler_json(os.path.join(cache, "nvd", cve + ".json"))
        try:
            c = d["vulnerabilities"][0]["cve"]
        except (TypeError, KeyError, IndexError):
            c = None
    return (c or {}).get("metrics") or {}


def _vetor(cache, cve):
    m = _metricas_nvd(cache, cve)
    for chave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        if m.get(chave):
            v = m[chave][0].get("cvssData", {}).get("vectorString")
            if v:
                return v
    d = dados_ubuntu(cache, cve) or {}
    try:
        return d["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
    except (TypeError, KeyError):
        return None


def ssvc_cve(cache, cve, kev_idx, epss):
    """Pontos de decisão de um CVE: da CISA (NVD ssvcV203) quando houver; senão derivados do CVSS, KEV e EPSS."""
    m = _metricas_nvd(cache, cve)
    for item in m.get("ssvcV203") or []:
        op = {}
        for o in (item.get("ssvcData") or {}).get("options", []):
            op.update(o)
        if op.get("exploitation") in ORDEM_EXPL:
            expl = "active" if cve in kev_idx else op["exploitation"]
            return {"exploracao": expl, "automatizavel": op.get("automatable") == "yes",
                    "impacto_total": op.get("technicalImpact") == "total", "fonte": "CISA (SSVC na NVD)"}
    vet = _vetor(cache, cve) or ""
    partes = dict(p.split(":", 1) for p in vet.split("/") if ":" in p)
    auto = partes.get("AV") == "N" and partes.get("PR") == "N" and partes.get("UI") in ("N",) and partes.get("AC", "L") == "L"
    total = (partes.get("C") == "H" and partes.get("I") == "H") or (partes.get("VC") == "H" and partes.get("VI") == "H")
    expl = "active" if cve in kev_idx else ("poc" if (epss.get(cve, (0, 0))[0] >= 0.1) else "none")
    return {"exploracao": expl, "automatizavel": bool(auto), "impacto_total": bool(total),
            "fonte": "derivado do CVSS, KEV e EPSS" if vet else "derivado do KEV e EPSS (sem vetor CVSS)"}


def decidir(expl, auto, total, missao):
    if expl == "active":
        return "agir_agora" if (missao == "alta" or (auto and total)) else "agir_em_breve"
    if expl == "poc":
        if auto and total and missao == "alta":
            return "agir_agora"
        if (auto or total) and missao != "baixa":
            return "agir_em_breve"
        return "acompanhar_de_perto"
    if auto and total and missao == "alta":
        return "acompanhar_de_perto"
    return "acompanhar"


# ---------- F6: versões mínimas e plugins a partir da NVD ----------
RE_VERS_DESC = re.compile(r"(?:before|prior to|fixed in|patched in|upgrade to|until)\s+(?:the\s+)?(?:versions?\s+)?((?:v?\d+(?:\.\d+){1,3}(?:-\d+)?(?:\s*,\s*|\s*,?\s*(?:and|or)\s+)?)+)", re.I)
RE_NUM = re.compile(r"\d+(?:\.\d+){1,3}")
_PREF = r"(?:block|mod|local|auth|tool|report|filter|theme|format|qtype|enrol|qbank|availability|atto|tiny|repository|plagiarism|logstore|gradeexport|quizaccess)"
# Só nomes no formato de pacote (moodle-block_x) ou seguidos de plugin/block/module; nunca funções, classes ou parâmetros.
RE_PLUGIN = re.compile(r"\bmoodle-(" + _PREF + r"_[a-z][a-z0-9]{1,40})\b|\b(" + _PREF + r"_[a-z][a-z0-9]{1,40})\s+(?:plugin|block|module)\b")


def _ramo(v):
    return ".".join(v.split(".")[:2])


def derivar_app(cves, excluir):
    """Mínimo seguro por ramo (major.minor) = maior versão corrigida citada; plugins do Moodle citados."""
    rx_excl = re.compile(excluir) if excluir else None
    por_ramo, plugins = {}, {}
    for c in cves:
        obj = NVD_IDX.get(c) or {}
        desc = next((x["value"] for x in obj.get("descriptions", []) if x.get("lang") == "en"), "")
        for m1, m2 in RE_PLUGIN.findall(desc):
            comp = m1 or m2
            plugins.setdefault(comp, {"componente": comp, "cves": []})["cves"].append(c)
        if rx_excl and rx_excl.search(desc):
            continue
        versoes = [v for v in (detalhe_nvd(c, {})["corrigido_em"] if c in NVD_IDX else [])]
        for grupo in RE_VERS_DESC.findall(desc):
            versoes += RE_NUM.findall(grupo)
        for v in versoes:
            v = v.lstrip("v")
            if not RE_APPVER.match(v):
                continue
            r = _ramo(v)
            if r not in por_ramo or cmp_versao(v, por_ramo[r]) > 0:
                por_ramo[r] = v
    minimos = sorted(por_ramo.values(), key=lambda v: [int(x) for x in v.split(".")])
    return minimos[-8:], sorted(plugins.values(), key=lambda p: p["componente"])[:40]


# ---------- F3: alertas nacionais (CAIS/RNP) ----------
def ler_alertas_cais(cache, data_ref, dias=120):
    import importlib.util
    spec = importlib.util.spec_from_file_location("nacionais", os.path.join(os.path.dirname(os.path.abspath(__file__)), "nacionais.py"))
    nac = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nac)
    limite = (datetime.date.fromisoformat(data_ref) - datetime.timedelta(days=dias)).isoformat()
    out = []
    for f in sorted(glob.glob(os.path.join(cache, "cais", "*.txt"))):
        try:
            url = open(f + ".url", encoding="utf-8").read().strip()
        except OSError:
            url = ""
        if not url.startswith("https://plataforma.rnp.br/"):
            continue
        a = nac.ler_cais(open(f, encoding="utf-8", errors="replace").read(), url)
        if not a["data"] or a["data"] < limite:
            continue
        try:
            a["assinatura"] = open(f + ".verif", encoding="utf-8").read().strip()
        except OSError:
            a["assinatura"] = "desconhecida"
        a["cves"] = [c for c in a["cves"] if RE_CVE.match(c)]
        out.append(a)
    out.sort(key=lambda a: a["data"], reverse=True)
    return out


def limpar_texto(s, limite=600):
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s or ""))
    return re.sub(r"\s+", " ", s).strip()[:limite]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True)
    ap.add_argument("--projeto", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--listar-cves", action="store_true", help="só imprime os CVEs necessários e sai")
    ap.add_argument("--listar-consultas", action="store_true", help="só imprime as consultas NVD por produto (arquivo<TAB>url) e sai")
    ap.add_argument("--data", default=datetime.date.today().isoformat())
    args = ap.parse_args()

    itens_def = ler_json(os.path.join(args.projeto, "itens.json"))
    cves_deb, avisos_deb, datas_deb = ler_avisos_debian(args.cache)
    cves_usn, avisos_usn, datas_usn = ler_usns(args.cache)
    cves_avisos = dict(cves_deb)
    cves_avisos.update(cves_usn)

    if args.listar_consultas:
        for it in itens_def["itens"]:
            for arq, url in consultas_nvd(it, args.data):
                print(arq + "\t" + url)
        return

    def cves_do_item(it):
        lista = list(it.get("cves", []))
        if it.get("nvd"):
            lista += resultados_nvd(args.cache, it)
        for a in it.get("cves_de", []):
            if a not in cves_avisos:
                if any(k[0] == a for k in POR_AVISO):
                    if not args.listar_cves and not args.listar_consultas:
                        print("info: %s: %s ainda sem CVEs atribuídos; usado só como versão mínima" % (it["id"], a), file=sys.stderr)
                else:
                    aviso("%s: aviso %s não encontrado no cache" % (it["id"], a))
            lista += cves_avisos.get(a, [])
        excl = set(it.get("cves_excluir", []))
        vistos, out = set(), []
        for c in lista:
            if RE_CVE.match(c) and c not in excl and c not in vistos:
                vistos.add(c)
                out.append(c)
        return out

    if args.listar_cves:
        # Só itens com pacote na distro precisam dos dados por CVE do Ubuntu/NVD.
        todos = set()
        for it in itens_def["itens"]:
            if it.get("fontes") or not it.get("nvd"):
                todos.update(cves_do_item(it))
        print("\n".join(sorted(todos)))
        return

    deb = ler_json(os.path.join(args.cache, "deb.json"), {}) or {}
    kev = ler_json(os.path.join(args.cache, "kev.json"), {}) or {}
    kev_idx = {v["cveID"]: v for v in kev.get("vulnerabilities", [])}
    EPSS = {}
    try:
        import gzip
        with gzip.open(os.path.join(args.cache, "epss.csv.gz"), "rt", encoding="utf-8") as f:
            for linha in f:
                p = linha.strip().split(",")
                if len(p) == 3 and RE_CVE.match(p[0]):
                    EPSS[p[0]] = (float(p[1]), float(p[2]))
    except (OSError, EOFError, ValueError):
        aviso("sem EPSS no cache")

    crit = ler_json(os.path.join(args.projeto, "criticidade.json"), {}) or {}
    # F8: inventário consolidado pelo receptor (só existe na coleta institucional)
    inv = ler_json(os.environ.get("RADAR_INVENTARIO", ""), {}) if os.environ.get("RADAR_INVENTARIO") else {}
    inv_item = (inv or {}).get("por_item") or {}
    alertas = ler_alertas_cais(args.cache, args.data)
    alertas_por_cve = {}
    for a in alertas:
        for c in a["cves"]:
            alertas_por_cve.setdefault(c, []).append(a)
    saida_dir = os.path.join(args.projeto, "site")
    os.makedirs(saida_dir, exist_ok=True)
    anterior = ler_json(os.path.join(saida_dir, "vulns.json"), {}) or {}
    ant_idx = {i["id"]: i for i in anterior.get("itens", [])}
    coletas = ler_json(os.path.join(saida_dir, "coletas.json"), []) or []

    erros = []
    vistos_ids = set()
    for it in itens_def["itens"]:
        if it.get("tecnologia") not in itens_def["tecnologias"]:
            erros.append("%s: tecnologia '%s' não existe em 'tecnologias' (acrescente a chave)" % (it.get("id"), it.get("tecnologia")))
        if it.get("tipo") not in ("pacote", "kernel", "app", "manual"):
            erros.append("%s: tipo inválido %r" % (it.get("id"), it.get("tipo")))
        if it.get("nvd"):
            for rx in [it["nvd"].get("regex")] if it["nvd"].get("regex") else []:
                try:
                    re.compile(rx)
                except re.error as e:
                    erros.append("%s: regex inválida (%s)" % (it.get("id"), e))
        if it.get("situacao") not in ("explorado", "urgente", "atencao", "nao_afetado"):
            erros.append("%s: situacao inválida %r" % (it.get("id"), it.get("situacao")))
        if it.get("id") in vistos_ids:
            erros.append("id repetido: %s" % it.get("id"))
        vistos_ids.add(it.get("id"))
        for r in (it.get("fontes") or {}):
            if r not in RELEASES:
                erros.append("%s: versão de distro desconhecida em fontes: %s" % (it.get("id"), r))
    if erros:
        for e in erros:
            print("ERRO: " + e, file=sys.stderr)
        sys.exit(1)

    itens = []
    novos, alterados, sem_cve, cves_novos = [], [], [], []
    for it in itens_def["itens"]:
        if not RE_ID.match(it.get("id", "")):
            aviso("id inválido: %r" % it.get("id"))
            continue
        cves = cves_do_item(it)
        detalhes = []
        if it.get("nvd"):
            if not cves:
                sem_cve.append(it["id"])
                continue
            detalhes = [detalhe_nvd(c, kev_idx) for c in cves if c in NVD_IDX]
            detalhes.sort(key=lambda d: (d["kev"] is None, -(d["nota"] or 0), d["publicado"]))
            cves = [d["cve"] for d in detalhes] + [c for c in cves if c not in NVD_IDX]
        linhas = {}
        for rel_id in RELEASES:
            rel_linhas = []
            manual = (it.get("linhas_manuais") or {}).get(rel_id)
            for pkg in (it.get("fontes") or {}).get(rel_id, []):
                l = linha_pacote(rel_id, pkg, cves, deb, args.cache, avisos_deb, avisos_usn)
                if l is None and any((a, RELEASES[rel_id]["codinome"], pkg) in POR_AVISO for a in it.get("cves_de", [])):
                    l = {"pacote": pkg, "estado": "nao_verificado", "cves_avaliados": 0, "abertos": [], "sem_impacto": []}
                if l:
                    aplicar_piso_avisos(l, it.get("cves_de", []), RELEASES[rel_id]["codinome"], it["id"])
                if l and validar_linha(l, it["id"]):
                    rel_linhas.append(l)
            if manual:
                l = {"pacote": manual.get("pacote") or ((it.get("fontes") or {}).get(rel_id) or [it["tecnologia"]])[0],
                     "estado": manual["estado"], "versao": manual.get("versao", ""), "aviso": manual.get("aviso", ""),
                     "nota": limpar_texto(manual.get("nota", ""), 200), "cves_avaliados": 0, "abertos": [], "sem_impacto": []}
                if validar_linha(l, it["id"]):
                    rel_linhas = [l]
            if it["tipo"] in ("pacote", "kernel") and not rel_linhas:
                fontes = (it.get("fontes") or {}).get(rel_id)
                if fontes:
                    rel_linhas = [{"pacote": fontes[0], "estado": "nao_verificado", "cves_avaliados": 0, "abertos": [], "sem_impacto": []}]
            # Com vários pacotes-fonte, descarta os que não existem na versão, se houver outro.
            if len(rel_linhas) > 1 and any(l["estado"] != "nao_empacotado" for l in rel_linhas):
                rel_linhas = [l for l in rel_linhas if l["estado"] != "nao_empacotado"]
            if rel_linhas:
                linhas[rel_id] = rel_linhas

        # Pontuação: NVD primeiro, depois Ubuntu (CVSS 3.x).
        notas, prioridade = [], None
        for c in cves:
            n = nota_nvd(args.cache, c)
            d = dados_ubuntu(args.cache, c) or {}
            if n is None and isinstance(d.get("cvss3"), (int, float)):
                n = {"valor": float(d["cvss3"]), "versao": "3.x", "fonte": "Ubuntu", "cve": c}
            if n:
                notas.append(n)
            p = d.get("priority")
            if p in PRIORIDADES and (prioridade is None or PRIORIDADES.index(p) > PRIORIDADES.index(prioridade)):
                prioridade = p
        melhor = max(notas, key=lambda n: n["valor"]) if notas else None
        pont = {"valor": melhor["valor"] if melhor else None,
                "versao": melhor["versao"] if melhor else None,
                "fonte": melhor["fonte"] if melhor else None,
                "cve": melhor["cve"] if melhor else None,
                "com_nota": len(notas), "total_cves": len(cves),
                "prioridade_ubuntu": prioridade, "rotulo": None}
        eps = [(EPSS[c][0], EPSS[c][1], c) for c in cves if c in EPSS]
        if eps:
            m = max(eps)
            pont.update({"epss": round(m[0], 5), "epss_percentil": round(m[1], 5), "epss_cve": m[2]})
        else:
            pont.update({"epss": None, "epss_percentil": None, "epss_cve": None})
        for d in detalhes:
            d["epss"] = round(EPSS[d["cve"]][0], 5) if d["cve"] in EPSS else None
        if it.get("pontuacao_manual") and pont["valor"] is None:
            pm = it["pontuacao_manual"]
            pont.update({"valor": pm.get("valor"), "rotulo": limpar_texto(pm.get("rotulo"), 60), "fonte": limpar_texto(pm.get("fonte"), 120)})

        # KEV a partir do catálogo oficial.
        kev_datas = sorted(kev_idx[c]["dateAdded"] for c in cves if c in kev_idx)
        ransomware = any(kev_idx[c].get("knownRansomwareCampaignUse") == "Known" for c in cves if c in kev_idx)
        kev_data = kev_datas[0] if kev_datas else None
        prazo = sorted(kev_idx[c]["dueDate"] for c in cves if c in kev_idx)
        kev_cves = [c for c in cves if c in kev_idx]
        situacao = it["situacao"]
        exploracao = it.get("exploracao", "")
        resumo_auto = afetadas_auto = publicado_auto = None
        if detalhes:
            altas = [d for d in detalhes if (d["nota"] or 0) >= 7]
            top = max(detalhes, key=lambda d: d["nota"] or 0)
            resumo_auto = "%d CVE(s) publicados na NVD nos últimos %d dias; %d com nota 7,0 ou mais. Maior nota: %s (%s)." % (
                len(detalhes), JANELA_NVD_DIAS, len(altas), ("%.1f" % top["nota"]) if top["nota"] is not None else "sem nota", top["cve"])
            corr = sorted({v for d in detalhes for v in d["corrigido_em"]})
            afetadas_auto = ("Versões corrigidas citadas na NVD: " + ", ".join(corr[:12])) if corr else "A NVD ainda não detalhou versões para estes CVEs; veja cada CVE e o aviso do fornecedor."
            publicado_auto = max(d["publicado"] for d in detalhes if d["publicado"]) if any(d["publicado"] for d in detalhes) else None
            if not kev_cves and situacao != "nao_afetado":
                situacao = "urgente" if altas else "atencao"
        if kev_cves and situacao in ("urgente", "atencao"):
            situacao = "explorado"
            exploracao = "Inclui CVE no catálogo KEV da CISA: " + ", ".join(
                "%s (desde %s)" % (c, kev_idx[c]["dateAdded"]) for c in kev_cves[:4])

        # F4: decisão SSVC
        missao = (crit.get("itens") or {}).get(it["id"]) or (crit.get("tecnologias") or {}).get(it["tecnologia"]) or crit.get("padrao", "media")
        if missao not in ("alta", "media", "baixa"):
            missao = "media"
        pontos = [ssvc_cve(args.cache, c, kev_idx, EPSS) for c in cves[:200]]
        if situacao == "explorado" and not any(p["exploracao"] == "active" for p in pontos):
            pontos.append({"exploracao": "active", "automatizavel": False, "impacto_total": False, "fonte": "fornecedor declara exploração"})
        if pontos:
            pior = max(pontos, key=lambda p: (ORDEM_EXPL[p["exploracao"]], p["automatizavel"] and p["impacto_total"], p["impacto_total"], p["automatizavel"]))
            expl = max((p["exploracao"] for p in pontos), key=lambda e: ORDEM_EXPL[e])
            auto = any(p["automatizavel"] for p in pontos)
            total = any(p["impacto_total"] for p in pontos)
            fonte_ssvc = sorted({p["fonte"] for p in pontos})
        else:
            expl, auto, total, fonte_ssvc = "none", False, False, ["sem CVE associado"]
            if situacao == "explorado":
                expl = "active"
        if situacao == "nao_afetado":
            dec = "nao_se_aplica"
        else:
            dec = decidir(expl, auto, total, missao)
        oc = inv_item.get(it["id"]) or {}
        inventario = {k: len(oc.get(c, [])) for k, c in (("vulneravel", "VULNERAVEL"), ("sem_correcao", "SEM_CORRECAO"),
                                                          ("reiniciar", "REINICIAR"), ("verificar", "VERIFICAR"), ("expostos", "expostos"))} if inv_item else None
        subiu = False
        if inventario and inventario["expostos"] and dec in ("agir_em_breve", "acompanhar_de_perto", "acompanhar"):
            dec = {"agir_em_breve": "agir_agora", "acompanhar_de_perto": "agir_em_breve", "acompanhar": "acompanhar_de_perto"}[dec]
            subiu = True
        # Prazo conta do evento mais recente: entrada no KEV, publicação ou primeira vez que o Radar viu o item.
        visto = (ant_idx.get(it["id"]) or {}).get("coletado_em") or args.data
        candidatas_ref = [d for d in (kev_datas[-1] if kev_datas else None, it.get("kev"),
                                      it.get("publicado_em") if RE_DATA.match(it.get("publicado_em") or "") else None, visto) if d]
        ref = max(candidatas_ref)
        prazo_dec = PRAZOS.get(dec)
        vence = (datetime.date.fromisoformat(ref) + datetime.timedelta(days=prazo_dec)).isoformat() if prazo_dec else None
        decisao = {"codigo": dec, "rotulo": ROTULO_DECISAO[dec], "prazo_dias": prazo_dec, "referencia": ref, "vence_em": vence,
                   "exposto": subiu,
                   "exploracao": expl, "automatizavel": auto, "impacto_total": total, "missao": missao, "fontes": fonte_ssvc,
                   # F18 (Meu contexto): a decisão para cada importância, para o painel recalcular no navegador.
                   "por_missao": {m: ("nao_se_aplica" if situacao == "nao_afetado" else decidir(expl, auto, total, m))
                                  for m in ("alta", "media", "baixa")}}
        # F3: alertas nacionais ligados por CVE
        nacs, vistos_a = [], set()
        for c in cves:
            for a in alertas_por_cve.get(c, []):
                if a["url"] not in vistos_a:
                    vistos_a.add(a["url"])
                    nacs.append({"fonte": a["fonte"], "data": a["data"], "titulo": a["titulo"], "url": a["url"], "assinatura": a["assinatura"]})

        app = it.get("app")
        plugins = []
        if app:
            minimos = [v for v in app.get("minimos", []) if RE_APPVER.match(v)]
            derivado = False
            if app.get("derivar"):
                minimos, plugins = derivar_app(cves, app.get("excluir"))
                derivado = True
            app = {"tipo": app["tipo"], "estrito": bool(app.get("estrito")), "minimos": minimos, "derivado": derivado,
                   "info": derivado and not minimos}
        ups = [v for v in it.get("upstream_minimos", []) if RE_APPVER.match(v)]

        refs = [{"t": limpar_texto(r.get("t"), 80), "u": r["u"]} for r in it.get("referencias", [])
                if isinstance(r.get("u"), str) and r["u"].startswith("https://")]

        corpo = {
            "id": it["id"],
            "titulo": limpar_texto(it["titulo"], 140).replace("|", "/"),
            "tecnologia": it["tecnologia"],
            "tipo": it["tipo"],
            "situacao": situacao,
            "exploracao": limpar_texto(exploracao, 300),
            "kev_cves": kev_cves,
            "kev": kev_data or it.get("kev"),
            "kev_prazo": prazo[0] if prazo else None,
            "ransomware": ransomware,
            "publicado_em": it.get("publicado_em") if RE_DATA.match(it.get("publicado_em") or "") else publicado_auto,
            "cves": cves,
            "pontuacao": pont,
            "resumo": limpar_texto(it.get("resumo") or resumo_auto),
            "afetadas": limpar_texto(it.get("afetadas") or afetadas_auto),
            "cves_detalhe": detalhes[:40],
            "decisao": decisao,
            "inventario": inventario,
            "alertas_nacionais": nacs,
            "fonte_nvd": bool(it.get("nvd")),
            "softwares": [limpar_texto(s, 120) for s in it.get("softwares", [])],
            "mitigacao": [limpar_texto(s, 240) for s in it.get("mitigacao", [])],
            "como_verificar": limpar_texto(it.get("como_verificar", ""), 240),
            "correcao_app": limpar_texto(it.get("correcao_app", ""), 300),
            "rollback_app": limpar_texto(it.get("rollback_app", ""), 300),
            "app": app,
            "upstream_minimos": ups,
            "plugins": plugins if (app and app["tipo"] == "moodle") else [],
            "bibliotecas": [b for b in it.get("bibliotecas", []) if RE_PKG.match(b)],
            "linhas": linhas,
            "referencias": refs,
        }
        revisao = hashlib.sha256(json.dumps({"l": linhas, "a": app, "u": ups, "c": sorted(cves)}, sort_keys=True).encode()).hexdigest()[:12]  # inventário muda toda hora: fora da revisão
        corpo["revisao"] = revisao
        prev = ant_idx.get(it["id"])
        if prev is not None:
            antes = set(prev.get("cves", []))
            notas = {d["cve"]: d["nota"] for d in detalhes}
            for c in cves:
                if c not in antes:
                    cves_novos.append({"item": it["id"], "cve": c, "nota": notas.get(c), "kev": kev_idx.get(c, {}).get("dateAdded")})
        if prev is None:
            corpo["coletado_em"] = args.data
            corpo["atualizado_em"] = args.data
            novos.append(it["id"])
        else:
            corpo["coletado_em"] = prev.get("coletado_em") or args.data
            if prev.get("revisao") != revisao:
                corpo["atualizado_em"] = args.data
                alterados.append(it["id"])
            else:
                corpo["atualizado_em"] = prev.get("atualizado_em") or args.data
        itens.append(corpo)

    # ---------- histórico completo: índices por versão e resumo por pacote ----------
    historico = gerar_historico(args.cache, saida_dir, args.data)

    cobertos = {c for i in itens for c in i["cves"]}
    candidatos = []
    lim_kev = (datetime.date.fromisoformat(args.data) - datetime.timedelta(days=14)).isoformat()
    for v in kev.get("vulnerabilities", []):
        if v.get("dateAdded", "") >= lim_kev and v["cveID"] not in cobertos:
            candidatos.append({"fonte": "CISA KEV", "data": v["dateAdded"], "cves": [v["cveID"]],
                               "titulo": limpar_texto("%s %s: %s" % (v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", "")), 200),
                               "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"})
    lim_nac = (datetime.date.fromisoformat(args.data) - datetime.timedelta(days=45)).isoformat()
    for a in alertas:
        if a["data"] >= lim_nac and not (set(a["cves"]) & cobertos):
            candidatos.append({"fonte": a["fonte"], "data": a["data"], "cves": a["cves"], "titulo": a["titulo"], "url": a["url"]})
    candidatos.sort(key=lambda c: c["data"], reverse=True)

    agora = datetime.datetime.now().astimezone().isoformat(timespec="minutes")
    coleta = {
        "id": agora,
        "data": args.data,
        "kev_versao": kev.get("catalogVersion"),
        "itens_total": len(itens),
        "novos": novos,
        "alterados": alterados,
        "janela_nvd_dias": JANELA_NVD_DIAS,
        "produtos_sem_cve": sem_cve,
        "cves_novos": cves_novos[:300],
        "historico": {r: {k: v for k, v in h.items() if k != "itens"} for r, h in historico.items()},
        "candidatos": candidatos[:60],
        "alertas_nacionais": len(alertas),
        "nvd_descartados": {k: v[:50] for k, v in sorted(NVD_DESCARTES.items()) if v},
        "fontes": ["CISA KEV", "Debian Security Tracker", "Ubuntu Security (CVE e USN)", "NVD", "avisos dos fornecedores"],
    }
    coletas.append(coleta)
    coletas = coletas[-200:]

    saida = {
        "gerado_em": agora,
        "coleta": coleta,
        "releases": RELEASES,
        "tecnologias": itens_def["tecnologias"],
        "criticidade": {"padrao": crit.get("padrao", "media") if crit.get("padrao") in ("alta", "media", "baixa") else "media",
                        "tecnologias": {k: v for k, v in (crit.get("tecnologias") or {}).items() if v in ("alta", "media", "baixa")}},
        # Modo público (RADAR_PUBLICO=1): sem o texto dos alertas do CAIS, cujo site reserva os direitos; ficam título, data, CVEs e link.
        "alertas_nacionais": [{k: a[k] for k in ("fonte", "data", "titulo", "cves", "url", "assinatura", "resumo")
                               if not (k == "resumo" and os.environ.get("RADAR_PUBLICO") == "1")} for a in alertas[:60]],
        "candidatos": candidatos[:60],
        "itens": itens,
    }
    with open(os.path.join(saida_dir, "vulns.json"), "w", encoding="utf-8") as f:
        json.dump(saida, f, ensure_ascii=False, indent=1)
    with open(os.path.join(saida_dir, "coletas.json"), "w", encoding="utf-8") as f:
        json.dump(coletas, f, ensure_ascii=False, indent=1)
    print("itens=%d novos=%d alterados=%d kev=%s" % (len(itens), len(novos), len(alterados), kev.get("catalogVersion")))


if __name__ == "__main__":
    main()
