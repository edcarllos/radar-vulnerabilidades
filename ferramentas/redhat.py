#!/usr/bin/env python3
"""Radar de Vulnerabilidades: dados de segurança da Red Hat (F24).

Fonte: Red Hat Security Data API, https://access.redhat.com/hydra/rest/securitydata/cve/<CVE>.json
Licença: CC BY 4.0 (https://access.redhat.com/security/data): exige atribuição à Red Hat e link para o original.

Rocky Linux, AlmaLinux e CentOS Stream recompilam os pacotes do RHEL: a versão corrigida no RHEL vale para eles
(com horas ou dias de atraso nos compatíveis; no Stream, como aproximação).

Uso:
  redhat.py compactar ENTRADA.json SAIDA.json   guarda só as linhas do RHEL 8, 9 e 10 (a resposta chega a 800 KB)
  redhat.py ausente SAIDA.json                  registra que a Red Hat não conhece o CVE (para não perguntar de novo)
  redhat.py cmp A B                             compara duas versões RPM (época:versão-release): -1, 0 ou 1
"""
import json, re, sys

MAJORS = ("8", "9", "10")
# Só o RHEL "comum": fora EUS/AUS/TUS/E4S, NVIDIA, tempo real, NFV e SAP.
RE_CPE_EL = re.compile(r"^cpe:/[oa]:redhat:enterprise_linux:(8|9|10)(?:\.\d+)?"
                       r"(?:::(?:baseos|appstream|crb|codeready_builder|highavailability|resilientstorage|supplementary))?$")
RE_NEVRA = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._+-]{0,99}?)-(\d{1,6}):([0-9A-Za-z._+~^]{1,80})-([0-9A-Za-z._+~^]{1,100})$")
RE_AVISO = re.compile(r"^RHSA-\d{4}:\d{3,6}$")
ESTADOS = {"Affected": "afetado", "Fix deferred": "afetado", "Under investigation": "afetado", "New": "afetado",
           "Will not fix": "nao_corrige", "Out of support scope": "fora_suporte", "Not affected": "nao_afetado"}


def compactar(d):
    """{'v':1,'el':{'9':{'fix':[[nome,'E:V-R','RHSA-..']], 'est':{nome:estado}}}, 'sev':..., 'cvss3':...}"""
    el = {}
    for a in d.get("affected_release") or []:
        prod = a.get("product_name") or ""
        m = RE_CPE_EL.match(a.get("cpe") or "")
        if not m or prod != "Red Hat Enterprise Linux " + m.group(1):
            continue
        n = RE_NEVRA.match(a.get("package") or "")
        if not n:
            continue  # fluxos de módulo (php:8.2-...) e afins ficam de fora
        adv = a.get("advisory") or ""
        el.setdefault(m.group(1), {"fix": [], "est": {}})["fix"].append(
            [n.group(1), "%s:%s-%s" % (n.group(2), n.group(3), n.group(4)), adv if RE_AVISO.match(adv) else ""])
    for p in d.get("package_state") or []:
        prod = p.get("product_name") or ""
        maj = prod.rsplit(" ", 1)[-1]
        if maj not in MAJORS or prod != "Red Hat Enterprise Linux " + maj:
            continue
        nome = p.get("package_name") or ""
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$", nome):
            continue
        est = ESTADOS.get(p.get("fix_state") or "")
        if est:
            el.setdefault(maj, {"fix": [], "est": {}})["est"][nome] = est
    cv = (d.get("cvss3") or {}).get("cvss3_base_score")
    try:
        cv = float(cv) if cv is not None else None
    except ValueError:
        cv = None
    return {"v": 1, "el": el, "sev": (d.get("threat_severity") or "")[:20], "cvss3": cv}


# ---------- comparação de versões RPM (mesmo algoritmo do rpmvercmp do rpm) ----------
_DIGITOS = set("0123456789")
_LETRAS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ALNUM = _DIGITOS | _LETRAS
def rpmvercmp(a, b):
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    ok = lambda c: c in _ALNUM
    while i < la or j < lb:
        while i < la and not ok(a[i]) and a[i] not in "~^":
            i += 1
        while j < lb and not ok(b[j]) and b[j] not in "~^":
            j += 1
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < la and j < lb):
            break
        si, sj = i, j
        num = a[i] in _DIGITOS
        if num:
            while i < la and a[i] in _DIGITOS:
                i += 1
            while j < lb and b[j] in _DIGITOS:
                j += 1
        else:
            while i < la and a[i] in _LETRAS:
                i += 1
            while j < lb and b[j] in _LETRAS:
                j += 1
        sa, sb = a[si:i], b[sj:j]
        if not sb:
            return 1 if num else -1
        if num:
            sa, sb = sa.lstrip("0"), sb.lstrip("0")
            if len(sa) != len(sb):
                return 1 if len(sa) > len(sb) else -1
        if sa != sb:
            return 1 if sa > sb else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def evr(s):
    e, _, vr = s.partition(":") if ":" in s else ("0", "", s)
    v, _, r = vr.rpartition("-")
    return int(e or 0), v, r


def cmp_evr(a, b):
    ea, va, ra = evr(a)
    eb, vb, rb = evr(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return rpmvercmp(va, vb) or rpmvercmp(ra, rb)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "compactar":
        try:
            d = json.load(open(sys.argv[2], encoding="utf-8"))
        except (OSError, ValueError):
            sys.exit(1)
        json.dump(compactar(d), open(sys.argv[3], "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
    elif len(sys.argv) == 4 and sys.argv[1] == "compactar-pasta":
        # Compacta todos os CVE-*.json baixados em ENTRADA e grava em SAIDA; os listados em ENTRADA/404.txt viram "ausente".
        import glob, os
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
            json.dump(compactar(d), open(os.path.join(sai, nome), "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))
            n += 1
        try:
            for c in open(os.path.join(ent, "404.txt"), encoding="utf-8").read().split():
                if re.match(r"^CVE-\d{4}-\d{4,7}$", c):
                    json.dump({"v": 1, "ausente": True}, open(os.path.join(sai, c + ".json"), "w", encoding="utf-8"))
                    a += 1
        except OSError:
            pass
        print("Red Hat: %d CVEs atualizados, %d desconhecidos pela Red Hat" % (n, a))
    elif len(sys.argv) == 3 and sys.argv[1] == "ausente":
        json.dump({"v": 1, "ausente": True}, open(sys.argv[2], "w", encoding="utf-8"))
    elif len(sys.argv) == 4 and sys.argv[1] == "cmp":
        print(cmp_evr(sys.argv[2], sys.argv[3]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
