#!/usr/bin/env python3
"""Radar de Vulnerabilidades: inventário e consolidação automática (F7) e exposição (F8).

Só entra o que o script de verificação MEDIU nos servidores; não há marcação manual de status.

Subcomandos:
  token-novo HOST [--tokens /etc/radar/tokens.json]
      cria um token para o servidor HOST e imprime-o uma única vez (guarda só o SHA-256).
  token-remover HOST [--tokens ...]
  servir [--porta 8790] [--db ARQ] [--tokens ARQ] [--publicar DIR] [--exposicao ARQ]
      recebe POST /api/relatorio (Authorization: Bearer <token>) com a saída de radar-verificar.sh --json
      (ou --completo --json), grava no SQLite e regrava DIR/inventario.json. Escuta só em 127.0.0.1;
      publique atrás do nginx com HTTPS.
      GET /api/coleta mostra o estado da coleta; POST /api/coleta (cabeçalho X-Radar-Pedido: 1) pede uma coleta
      agora: grava ESTADO/pedido-coleta, que a unidade radar-coleta-pedido.path transforma em radar-coleta.service.
      Recusa se houver coleta em andamento ou se a última começou há menos de RADAR_INTERVALO_MIN (padrão 15) minutos.
  consolidar [--db ARQ] [--publicar DIR] [--exposicao ARQ] [--internetdb]
      regrava DIR/inventario.json; com --internetdb consulta https://internetdb.shodan.io/<ip>
      apenas para os IPs públicos listados em exposicao.json.
  importar --db ARQ --host HOST ARQ.json
      grava um relatório local (para servidores sem rede até o coletor).

exposicao.json: {"servidores": ["moodle01"], "ips": {"portal01": "200.0.113.10"}}
"""
import argparse, datetime, hashlib, http.server, json, os, re, secrets, sqlite3, sys, threading, urllib.request

RE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
RE_ITEM = re.compile(r"^[a-z0-9][a-z0-9-]{2,60}$")
RE_REL = re.compile(r"^(deb12|deb13|u2204|u2404|u2604)$")
STATUS = {"VULNERAVEL", "SEM_CORRECAO", "REINICIAR", "VERIFICAR", "ATENCAO", "OK", "NAO_AFETADO", "AUSENTE"}
DECISOES = {"agir_agora", "agir_em_breve", "acompanhar_de_perto", "acompanhar", "nao_se_aplica"}
LIMITE_CORPO = 4 * 1024 * 1024
TRAVA = threading.Lock()


def agora():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def txt(v, n=200):
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v if v is not None else ""))[:n]


# ---------- tokens ----------
def ler_tokens(arq):
    try:
        with open(arq, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except FileNotFoundError:
        return {}
    except PermissionError:
        print("ERRO: sem permissão para ler %s (pasta e arquivo devem ser do grupo radar-coletor)" % arq, file=sys.stderr)
        return {}
    except (OSError, ValueError):
        return {}


def gravar_tokens(arq, d):
    tmp = arq + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1)
    try:  # mantém dono e grupo do arquivo atual (root:radar-coletor), senão o receptor deixa de lê-lo
        st = os.stat(arq)
        os.chown(tmp, st.st_uid, st.st_gid)
        os.chmod(tmp, st.st_mode & 0o777 & ~0o007)
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    os.replace(tmp, arq)


def host_do_token(tokens, token):
    h = hashlib.sha256(token.encode()).hexdigest()
    for host, info in tokens.items():
        if secrets.compare_digest(info.get("sha256", ""), h):
            return host
    return None


# ---------- banco ----------
def abrir_db(arq):
    db = sqlite3.connect(arq, timeout=30, check_same_thread=False)  # o receptor usa threads; TRAVA serializa o acesso
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript("""
      CREATE TABLE IF NOT EXISTS servidores (host TEXT PRIMARY KEY, distro TEXT, kernel TEXT, ultima TEXT, origem TEXT);
      CREATE TABLE IF NOT EXISTS relatorios (id INTEGER PRIMARY KEY, host TEXT, tipo TEXT, recebido TEXT, json TEXT);
      CREATE INDEX IF NOT EXISTS rel_host ON relatorios(host, tipo, recebido);
      CREATE TABLE IF NOT EXISTS exposicao (host TEXT PRIMARY KEY, ip TEXT, data TEXT, portas TEXT);
      -- F14: histórico durável e pequeno para o relatório mensal (os relatórios brutos guardam só os 60 últimos).
      CREATE TABLE IF NOT EXISTS episodios (id INTEGER PRIMARY KEY, host TEXT, item TEXT, decisao TEXT,
        inicio TEXT, com_correcao TEXT, fim TEXT);
      CREATE INDEX IF NOT EXISTS epi_aberto ON episodios(host, item, fim);
      CREATE TABLE IF NOT EXISTS diario (host TEXT, dia TEXT, resumo TEXT, PRIMARY KEY (host, dia));
    """)
    return db


def normalizar(host, d):
    """Valida e reduz o relatório ao que o painel usa. Retorna (tipo, objeto) ou levanta ValueError."""
    if not isinstance(d, dict):
        raise ValueError("corpo não é um objeto JSON")
    if d.get("radar") == 1:
        if not RE_REL.match(str(d.get("distro", ""))):
            raise ValueError("distro inválida")
        itens = []
        for it in (d.get("itens") or [])[:5000]:
            if not isinstance(it, dict) or it.get("status") not in STATUS or not RE_ITEM.match(str(it.get("item", ""))):
                continue
            itens.append({"item": it["item"], "status": it["status"],
                          "decisao": it.get("decisao") if it.get("decisao") in DECISOES else "acompanhar",
                          "alvo": txt(it.get("alvo"), 80), "instalado": txt(it.get("instalado"), 80),
                          "minimo": txt(it.get("minimo"), 120), "cvss": txt(it.get("cvss"), 6),
                          "titulo": txt(it.get("titulo"), 160), "binarios": txt(it.get("binarios"), 600)})
        return "verificacao", {"host": host, "distro": d["distro"], "kernel": txt(d.get("kernel"), 80),
                               "coleta": txt(d.get("coleta"), 10), "idade_dados_dias": int(d.get("idade_dados_dias") or 0),
                               "resumo": {k: int(v) for k, v in (d.get("resumo") or {}).items() if isinstance(v, int)},
                               "itens": itens}
    if d.get("radar") == "completo":
        if not RE_REL.match(str(d.get("distro", ""))):
            raise ValueError("distro inválida")
        return "completo", {"host": host, "distro": d["distro"],
                            "resumo": {k: int(v) for k, v in (d.get("resumo") or {}).items() if isinstance(v, int)},
                            "kev": [c for c in (d.get("kev") or []) if re.match(r"^CVE-\d{4}-\d{4,7}$", str(c))][:200],
                            "pacotes_avaliados": int(d.get("pacotes_avaliados") or 0)}
    raise ValueError("relatório desconhecido (esperado radar-verificar.sh --json ou --completo --json)")


def gravar_relatorio(db, host, tipo, obj, origem=""):
    with TRAVA:
        db.execute("INSERT INTO relatorios(host, tipo, recebido, json) VALUES (?,?,?,?)", (host, tipo, agora(), json.dumps(obj)))
        if tipo == "verificacao":
            db.execute("INSERT INTO servidores(host, distro, kernel, ultima, origem) VALUES (?,?,?,?,?) "
                       "ON CONFLICT(host) DO UPDATE SET distro=excluded.distro, kernel=excluded.kernel, ultima=excluded.ultima, origem=excluded.origem",
                       (host, obj["distro"], obj["kernel"], agora(), origem))
            registrar_episodios(db, host, obj)
        # Retenção: 60 relatórios por servidor e tipo (histórico para indicadores da fase 3).
        db.execute("DELETE FROM relatorios WHERE host=? AND tipo=? AND id NOT IN "
                   "(SELECT id FROM relatorios WHERE host=? AND tipo=? ORDER BY id DESC LIMIT 60)", (host, tipo, host, tipo))
        db.commit()


EXPOSTO = ("VULNERAVEL", "SEM_CORRECAO", "REINICIAR")


def registrar_episodios(db, host, obj):
    """Abre um episódio quando um item passa a expor o servidor e fecha quando deixa de expor.
    com_correcao = primeira vez em que havia correção disponível (VULNERAVEL ou REINICIAR): base do prazo."""
    t = agora()
    exp = {}
    for it in obj.get("itens", []):
        if it.get("status") in EXPOSTO:
            e = exp.setdefault(it["item"], {"decisao": it.get("decisao") or "acompanhar", "fix": False})
            e["fix"] = e["fix"] or it["status"] != "SEM_CORRECAO"
    abertos = {r[1]: r for r in db.execute("SELECT id, item, com_correcao FROM episodios WHERE host=? AND fim IS NULL", (host,))}
    for item, (eid, _, cc) in abertos.items():
        if item not in exp:
            db.execute("UPDATE episodios SET fim=? WHERE id=?", (t, eid))
        else:
            db.execute("UPDATE episodios SET decisao=?, com_correcao=? WHERE id=?",
                       (exp[item]["decisao"], cc or (t if exp[item]["fix"] else None), eid))
    for item, e in exp.items():
        if item not in abertos:
            db.execute("INSERT INTO episodios(host, item, decisao, inicio, com_correcao) VALUES (?,?,?,?,?)",
                       (host, item, e["decisao"], t, t if e["fix"] else None))
    db.execute("INSERT INTO diario(host, dia, resumo) VALUES (?,?,?) ON CONFLICT(host, dia) DO UPDATE SET resumo=excluded.resumo",
               (host, t[:10], json.dumps(obj.get("resumo") or {})))


# ---------- exposição ----------
def ler_exposicao(arq):
    try:
        with open(arq, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError, TypeError):
        return set(), {}
    manuais = {h for h in d.get("servidores", []) if RE_HOST.match(str(h))}
    ips = {h: ip for h, ip in (d.get("ips") or {}).items() if RE_HOST.match(str(h)) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(ip))}
    return manuais, ips


def consultar_internetdb(db, ips):
    hoje = datetime.date.today().isoformat()
    for host, ip in ips.items():
        linha = db.execute("SELECT data FROM exposicao WHERE host=? AND ip=?", (host, ip)).fetchone()
        if linha and linha[0] == hoje:
            continue
        portas = []
        try:
            with urllib.request.urlopen("https://internetdb.shodan.io/" + ip, timeout=15) as r:
                portas = [int(p) for p in json.load(r).get("ports", [])][:50]
        except Exception:
            portas = []  # 404 = nada visto na internet para esse IP
        db.execute("INSERT INTO exposicao(host, ip, data, portas) VALUES (?,?,?,?) ON CONFLICT(host) DO UPDATE SET ip=excluded.ip, data=excluded.data, portas=excluded.portas",
                   (host, ip, hoje, json.dumps(portas)))
    db.commit()


# ---------- consolidação ----------
def consolidar(db, publicar, exposicao_arq=None, internetdb=False):
    manuais, ips = ler_exposicao(exposicao_arq) if exposicao_arq else (set(), {})
    if internetdb and ips:
        consultar_internetdb(db, ips)
    portas = {h: json.loads(p or "[]") for h, p in db.execute("SELECT host, portas FROM exposicao")}
    agora_dt = datetime.datetime.now(datetime.timezone.utc)
    servidores, por_item = [], {}
    for host, distro, kernel, ultima in db.execute("SELECT host, distro, kernel, ultima FROM servidores ORDER BY host"):
        lin = db.execute("SELECT json FROM relatorios WHERE host=? AND tipo='verificacao' ORDER BY id DESC LIMIT 1", (host,)).fetchone()
        if not lin:
            continue
        rel = json.loads(lin[0])
        comp = db.execute("SELECT json, recebido FROM relatorios WHERE host=? AND tipo='completo' ORDER BY id DESC LIMIT 1", (host,)).fetchone()
        try:
            idade = round((agora_dt - datetime.datetime.fromisoformat(ultima)).total_seconds() / 3600, 1)
        except (TypeError, ValueError):
            idade = None
        exposto = host in manuais or bool(portas.get(host))
        relevantes = [i for i in rel["itens"] if i["status"] in ("VULNERAVEL", "SEM_CORRECAO", "REINICIAR", "VERIFICAR", "ATENCAO")]
        for i in relevantes:
            por_item.setdefault(i["item"], {}).setdefault(i["status"], []).append(host)
            if exposto and i["status"] in ("VULNERAVEL", "SEM_CORRECAO", "REINICIAR"):
                por_item[i["item"]].setdefault("expostos", []).append(host)
        servidores.append({"host": host, "distro": distro, "kernel": kernel, "ultima": ultima, "idade_horas": idade,
                           "exposto": exposto, "portas_publicas": portas.get(host, []), "coleta_script": rel.get("coleta"),
                           "resumo": rel.get("resumo", {}), "itens": relevantes,
                           "completo": (json.loads(comp[0]) | {"recebido": comp[1]}) if comp else None})
    saida = {"gerado_em": agora(), "servidores": servidores, "por_item": por_item,
             "sem_relato_recente": [s["host"] for s in servidores if s["idade_horas"] is None or s["idade_horas"] > 48]}
    if publicar:
        os.makedirs(publicar, exist_ok=True)
        tmp = os.path.join(publicar, ".inventario.json.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(saida, f, ensure_ascii=False)
        os.chmod(tmp, 0o644)
        os.replace(tmp, os.path.join(publicar, "inventario.json"))
    return saida


# ---------- servidor HTTP ----------
def _ler_json(arq):
    try:
        with open(arq, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _epoca(iso):
    try:
        return datetime.datetime.fromisoformat(str(iso)).timestamp()
    except ValueError:
        return None


def estado_coleta(dir_estado, intervalo_min):
    """Estado gravado por rodar-coleta.sh (coleta-estado.json) e pedido pendente (pedido-coleta)."""
    e = _ler_json(os.path.join(dir_estado, "coleta-estado.json"))
    agora_s = datetime.datetime.now().timestamp()
    ini, fim = _epoca(e.get("inicio")), _epoca(e.get("fim"))
    # Em andamento: começou e não terminou, há menos de 50 min (o serviço tem limite de 45 min).
    andamento = bool(ini and (not fim or fim < ini) and agora_s - ini < 50 * 60)
    pedido = _ler_json(os.path.join(dir_estado, "pedido-coleta")) if os.path.exists(os.path.join(dir_estado, "pedido-coleta")) else None
    proxima = None
    if ini and not andamento:
        p = ini + intervalo_min * 60
        if p > agora_s:
            proxima = datetime.datetime.fromtimestamp(p).astimezone().isoformat(timespec="seconds")
    return {"em_andamento": andamento, "pedido_pendente": pedido is not None, "pedido_em": (pedido or {}).get("quando"),
            "inicio": e.get("inicio"), "fim": e.get("fim") if fim and ini and fim >= ini else None,
            "ok": e.get("ok") if fim and ini and fim >= ini else None, "proxima_permitida": proxima,
            "intervalo_min": intervalo_min}


def servir(args):
    db = abrir_db(args.db)
    dir_estado = os.path.dirname(os.path.abspath(args.db))
    try:
        intervalo = max(1, int(os.environ.get("RADAR_INTERVALO_MIN", "15")))
    except ValueError:
        intervalo = 15

    class H(http.server.BaseHTTPRequestHandler):
        server_version = "radar-receptor"

        def log_message(self, fmt, *a):
            sys.stderr.write("%s %s\n" % (self.headers.get("X-Real-IP", self.client_address[0]) if self.headers else "-", fmt % a))

        def _resp(self, cod, obj):
            corpo = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(cod)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(corpo)))
            self.end_headers()
            self.wfile.write(corpo)

        def do_GET(self):
            if self.path.rstrip("/") == "/api/saude":
                return self._resp(200, {"ok": True})
            if self.path.rstrip("/") == "/api/coleta":
                return self._resp(200, estado_coleta(dir_estado, intervalo))
            self._resp(404, {"erro": "não encontrado"})

        def _pedir_coleta(self):
            # Proteção contra pedidos forjados por outros sites: cabeçalho próprio (força preflight CORS,
            # que este servidor não aceita) e, quando o navegador informa, origem igual à do painel.
            if self.headers.get("X-Radar-Pedido") != "1":
                return self._resp(403, {"erro": "cabeçalho X-Radar-Pedido ausente"})
            if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
                return self._resp(403, {"erro": "pedido de outra origem"})
            origem, hostp = self.headers.get("Origin"), self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
            if origem and origem.split("://", 1)[-1] != hostp:
                return self._resp(403, {"erro": "pedido de outra origem"})
            with TRAVA:
                e = estado_coleta(dir_estado, intervalo)
                if e["em_andamento"] or e["pedido_pendente"]:
                    return self._resp(409, dict(e, erro="já há uma coleta em andamento"))
                if e["proxima_permitida"]:
                    return self._resp(429, dict(e, erro="a última coleta começou há menos de %d minutos" % intervalo))
                quem = self.headers.get("X-Remote-User") or self.headers.get("X-Real-IP", self.client_address[0])
                arq = os.path.join(dir_estado, "pedido-coleta")
                tmp = arq + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump({"quando": agora(), "quem": txt(quem, 80)}, f)
                os.replace(tmp, arq)
                sys.stderr.write("coleta pedida pelo painel por %s\n" % txt(quem, 80))
                return self._resp(202, estado_coleta(dir_estado, intervalo))

        def do_POST(self):
            if self.path.rstrip("/") == "/api/coleta":
                return self._pedir_coleta()
            if self.path.rstrip("/") != "/api/relatorio":
                return self._resp(404, {"erro": "não encontrado"})
            aut = self.headers.get("Authorization", "")
            token = aut[7:].strip() if aut.startswith("Bearer ") else ""
            host = host_do_token(ler_tokens(args.tokens), token) if token else None
            if not host:
                return self._resp(401, {"erro": "token inválido"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = 0
            if n <= 0 or n > LIMITE_CORPO:
                return self._resp(413, {"erro": "corpo ausente ou maior que 4 MB"})
            try:
                tipo, obj = normalizar(host, json.loads(self.rfile.read(n)))
            except (ValueError, UnicodeDecodeError) as e:
                return self._resp(400, {"erro": str(e)[:200]})
            gravar_relatorio(db, host, tipo, obj, self.headers.get("X-Real-IP", self.client_address[0]))
            with TRAVA:
                consolidar(db, args.publicar, args.exposicao)
            self._resp(200, {"ok": True, "host": host, "tipo": tipo, "itens": len(obj.get("itens", []))})

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", args.porta), H)
    print("radar-receptor ouvindo em 127.0.0.1:%d" % args.porta, file=sys.stderr)
    srv.serve_forever()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("comando", choices=["token-novo", "token-remover", "servir", "consolidar", "importar"])
    ap.add_argument("alvo", nargs="?")
    ap.add_argument("--tokens", default="/etc/radar/tokens.json")
    ap.add_argument("--db", default="/var/lib/radar-coletor/inventario.db")
    ap.add_argument("--publicar", default="")
    ap.add_argument("--exposicao", default="/etc/radar/exposicao.json")
    ap.add_argument("--porta", type=int, default=8790)
    ap.add_argument("--internetdb", action="store_true")
    ap.add_argument("--host", default="")
    a = ap.parse_args()
    if a.comando in ("token-novo", "token-remover"):
        if not a.alvo or not RE_HOST.match(a.alvo):
            sys.exit("Informe o nome do servidor (letras, números, ponto e hífen).")
        t = ler_tokens(a.tokens)
        if a.comando == "token-remover":
            t.pop(a.alvo, None)
            gravar_tokens(a.tokens, t)
            print("Token de %s removido." % a.alvo)
            return
        token = secrets.token_urlsafe(32)
        t[a.alvo] = {"sha256": hashlib.sha256(token.encode()).hexdigest(), "criado": agora()}
        gravar_tokens(a.tokens, t)
        print(token)
    elif a.comando == "servir":
        servir(a)
    elif a.comando == "consolidar":
        s = consolidar(abrir_db(a.db), a.publicar, a.exposicao, a.internetdb)
        print("%d servidores, %d itens com ocorrência" % (len(s["servidores"]), len(s["por_item"])))
    elif a.comando == "importar":
        if not RE_HOST.match(a.host or "") or not a.alvo:
            sys.exit("Use: importar --host HOST ARQ.json")
        tipo, obj = normalizar(a.host, json.load(open(a.alvo, encoding="utf-8")))
        db = abrir_db(a.db)
        gravar_relatorio(db, a.host, tipo, obj, "importado")
        consolidar(db, a.publicar, a.exposicao)
        print("Importado: %s (%s)" % (a.host, tipo))


if __name__ == "__main__":
    main()
