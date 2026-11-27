#!/usr/bin/env python3
"""Radar de Vulnerabilidades: notificações (F9) e feed RSS.

Subcomandos
  enviar   avisos imediatos: item que passou a "Agir agora", entrada nova no KEV, EPSS alto
           ou CVE novo com KEV/nota >= 9 num item existente. Cada aviso sai uma vez só
           (estado em --estado). Na primeira execução só registra o que já existe, sem enviar.
  resumo   resumo diário (decisões, prazos, novidades das últimas 24 h, servidores).
  testar   manda uma mensagem curta a cada canal, para conferir a configuração.
  feed     gera novidades.xml (RSS 2.0) a partir de coletas.json, para leitores de feed.

Configuração (padrão /etc/radar/notificacoes.json; veja implantacao/coletor/notificacoes.exemplo.json):
  {"painel_url": "https://intranet/radar/", "epss_minimo": 0.1,
   "canais": [{"tipo": "email", "smtp": "smtp.campus", "porta": 587, "starttls": true,
               "usuario": "radar", "senha_arquivo": "/etc/radar/smtp.senha",
               "de": "radar@campus", "para": ["seguranca@campus"]},
              {"tipo": "telegram", "token_arquivo": "/etc/radar/telegram.token", "chat_id": "-100123"},
              {"tipo": "mattermost", "url_arquivo": "/etc/radar/mattermost.url"},
              {"tipo": "teams", "url_arquivo": "/etc/radar/teams.url", "eventos": ["resumo"]}]}
  Segredos (senha, token, URL de webhook) ficam em arquivos próprios, legíveis só por radar-coletor.
  "mattermost" também serve para Slack e Rocket.Chat (webhook de entrada com {"text": ...}).
  "eventos" limita o canal a "imediato" e/ou "resumo" (padrão: os dois).
"""
import argparse
import datetime as dt
import json
import os
import re
import smtplib
import ssl
import sys
import urllib.request
from email.message import EmailMessage
from xml.sax.saxutils import escape

DECISOES = [("agir_agora", "Agir agora"), ("agir_em_breve", "Agir em breve"),
            ("acompanhar_de_perto", "Acompanhar de perto"), ("acompanhar", "Acompanhar")]
ROT = dict(DECISOES)


def ler_json(caminho, padrao=None):
    try:
        with open(caminho, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return padrao


def gravar_json(caminho, dados):
    tmp = caminho + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=1)
    os.replace(tmp, caminho)


def ler_segredo(caminho):
    with open(caminho, encoding="utf-8") as f:
        return f.read().strip()


def url_permitida(u):
    """Webhooks só por https; http apenas para localhost (testes)."""
    return bool(re.match(r"^https://[^\s/]+/\S*$", u) or re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/\S*$", u))


def data_br(s):
    m = re.match(r"^(\d{4})-(\d\d)-(\d\d)", str(s or ""))
    return "%s/%s/%s" % (m.group(3), m.group(2), m.group(1)) if m else "?"


# ---------------------------------------------------------------- conteúdo

def nota_txt(it):
    p = it.get("pontuacao") or {}
    partes = []
    if isinstance(p.get("valor"), (int, float)):
        partes.append("nota %.1f" % p["valor"])
    elif p.get("rotulo"):
        partes.append(p["rotulo"])
    if isinstance(p.get("epss"), (int, float)):
        partes.append("EPSS %.0f%%" % (p["epss"] * 100))
    if it.get("kev"):
        partes.append("KEV desde " + data_br(it["kev"]))
    return ", ".join(partes)


def correcoes_txt(it, releases):
    linhas = []
    for rel, lst in sorted((it.get("linhas") or {}).items()):
        rot = (releases.get(rel) or {}).get("rotulo", rel)
        est = []
        for l in lst or []:
            e = l.get("estado")
            if e in ("corrigido", "parcial") and l.get("versao"):
                est.append("%s %s%s" % (l.get("pacote"), l["versao"], " (parcial)" if e == "parcial" else ""))
            elif e == "pro":
                est.append("%s: só no Ubuntu Pro" % l.get("pacote"))
            elif e == "sem_correcao":
                est.append("%s: sem correção" % l.get("pacote"))
            elif e == "em_triagem":
                est.append("%s: em triagem" % l.get("pacote"))
        if est:
            linhas.append("  %s: %s" % (rot, "; ".join(est)))
    return linhas


def afetados_txt(it):
    inv = it.get("inventario") or {}
    n = sum(inv.get(k, 0) for k in ("vulneravel", "sem_correcao", "reiniciar"))
    if not n:
        return ""
    return "Afeta %d servidor(es)%s." % (n, ", %d exposto(s) à internet" % inv["expostos"] if inv.get("expostos") else "")


def bloco_item(it, releases, motivo, completo=True):
    d = it.get("decisao") or {}
    cves = it.get("cves") or []
    l = ["[%s] %s" % (d.get("rotulo") or ROT.get(d.get("codigo"), "?"), it.get("titulo", it["id"])),
         "Motivo: " + motivo]
    if cves:
        l.append("CVE: " + ", ".join(cves[:6]) + (" e mais %d" % (len(cves) - 6) if len(cves) > 6 else ""))
    nt = nota_txt(it)
    if nt:
        l.append("Gravidade: " + nt)
    if d.get("vence_em"):
        l.append("Prazo sugerido: até " + data_br(d["vence_em"]))
    a = afetados_txt(it)
    if a:
        l.append(a)
    if completo:
        if it.get("afetadas"):
            l.append("Versões afetadas: " + str(it["afetadas"])[:400])
        c = correcoes_txt(it, releases)
        if c:
            l.append("Correções por distro:")
            l += c[:8]
        mit = it.get("mitigacao") or []
        if isinstance(mit, str):
            mit = [mit]
        if mit:
            l.append("Mitigação: " + "; ".join(str(x).rstrip(". ") for x in mit)[:500] + ".")
        refs = [r.get("u") for r in (it.get("referencias") or []) if isinstance(r, dict) and str(r.get("u", "")).startswith("https://")]
        if refs:
            l.append("Referências: " + " ".join(refs[:4]))
    return "\n".join(l)


def eventos_imediatos(vulns, coleta, epss_minimo):
    """Lista (chave, item, motivo). A chave identifica o aviso para não repeti-lo."""
    hoje = dt.date.today()
    novos_cves = {}
    for c in coleta.get("cves_novos") or []:
        if isinstance(c, dict) and (c.get("kev") or (c.get("nota") or 0) >= 9):
            novos_cves.setdefault(c.get("item"), []).append(c)
    out = []
    for it in vulns.get("itens", []):
        d = it.get("decisao") or {}
        p = it.get("pontuacao") or {}
        if d.get("codigo") == "agir_agora":
            out.append(("%s|agir_agora" % it["id"], it, "passou a Agir agora (prazo de 1 dia)"))
        if it.get("kev"):
            try:
                recente = (hoje - dt.date.fromisoformat(it["kev"][:10])).days <= 7
            except ValueError:
                recente = False
            if recente:
                out.append(("%s|kev|%s" % (it["id"], it["kev"][:10]), it, "entrou no catálogo KEV da CISA (exploração ativa) em " + data_br(it["kev"])))
        if isinstance(p.get("epss"), (int, float)) and p["epss"] >= epss_minimo:
            out.append(("%s|epss" % it["id"], it, "EPSS de %.0f%% (probabilidade alta de exploração em 30 dias)" % (p["epss"] * 100)))
        for c in novos_cves.get(it["id"], []):
            m = "CVE novo %s%s" % (c.get("cve"), " no KEV" if c.get("kev") else ", nota %.1f" % c.get("nota", 0))
            out.append(("%s|cve|%s" % (it["id"], c.get("cve")), it, m))
    return out


def texto_resumo(vulns, coletas, inv, painel):
    agora = dt.datetime.now(dt.timezone.utc)
    itens = vulns.get("itens", [])
    cont = {k: 0 for k, _ in DECISOES}
    for it in itens:
        k = (it.get("decisao") or {}).get("codigo")
        if k in cont:
            cont[k] += 1
    c = vulns.get("coleta") or {}
    l = ["Radar de Vulnerabilidades: resumo de %s" % agora.astimezone().strftime("%d/%m/%Y"),
         "Coleta %s · catálogo KEV %s · %d itens" % (data_br(c.get("data")), c.get("kev_versao", "?"), len(itens)),
         " · ".join("%s: %d" % (r, cont[k]) for k, r in DECISOES), ""]
    for cod in ("agir_agora", "agir_em_breve"):
        lst = sorted([it for it in itens if (it.get("decisao") or {}).get("codigo") == cod],
                     key=lambda it: (it["decisao"].get("vence_em") or "9", it["id"]))
        if lst:
            l.append("%s (%d):" % (ROT[cod], len(lst)))
            for it in lst[:15]:
                extra = afetados_txt(it)
                l.append("- %s · até %s%s" % (it.get("titulo", it["id"]), data_br(it["decisao"].get("vence_em")), (" · " + extra) if extra else ""))
            if len(lst) > 15:
                l.append("- e mais %d no painel" % (len(lst) - 15))
            l.append("")
    titulo = {it["id"]: it.get("titulo", it["id"]) for it in itens}
    novos, alterados = set(), set()
    for co in coletas or []:
        try:
            quando = dt.datetime.fromisoformat(str(co.get("id")))
        except ValueError:
            continue
        if quando.tzinfo and (agora - quando).total_seconds() <= 86400:
            novos.update(co.get("novos") or [])
            alterados.update(co.get("alterados") or [])
    alterados -= novos
    if novos or alterados:
        l.append("Últimas 24 h:")
        l += ["- Novo: " + titulo.get(i, i) for i in sorted(novos)]
        l += ["- Atualizado: " + titulo.get(i, i) for i in sorted(alterados)][:20]
        l.append("")
    if inv and inv.get("servidores"):
        sv = inv["servidores"]
        pend = [s["host"] for s in sv if (s.get("resumo") or {}).get("vulneravel")]
        l.append("Servidores: %d enviando resultados; %d com correção pendente%s; %d sem resultado há mais de 48 h."
                 % (len(sv), len(pend), (" (" + ", ".join(pend[:10]) + ")") if pend else "", len(inv.get("sem_relato_recente") or [])))
        l.append("")
    if painel:
        l.append("Painel: " + painel)
    return "\n".join(l).strip() + "\n"


# ---------------------------------------------------------------- canais

def post_json(url, dados):
    if not url_permitida(url):
        raise ValueError("URL recusada (use https://)")
    req = urllib.request.Request(url, data=json.dumps(dados).encode(), headers={"Content-Type": "application/json", "User-Agent": "radar-vulnerabilidades"})
    with urllib.request.urlopen(req, timeout=20) as r:
        r.read(2000)


def enviar_canal(canal, assunto, texto):
    t = canal.get("tipo")
    if t == "email":
        msg = EmailMessage()
        msg["Subject"] = assunto
        msg["From"] = canal["de"]
        msg["To"] = ", ".join(canal["para"])
        msg.set_content(texto)
        porta = int(canal.get("porta", 25))
        ctx = ssl.create_default_context()
        cls = smtplib.SMTP_SSL if canal.get("ssl") else smtplib.SMTP
        kw = {"context": ctx} if canal.get("ssl") else {}
        with cls(canal.get("smtp", "localhost"), porta, timeout=30, **kw) as s:
            if canal.get("starttls"):
                s.starttls(context=ctx)
            if canal.get("usuario"):
                s.login(canal["usuario"], ler_segredo(canal["senha_arquivo"]))
            s.send_message(msg)
    elif t == "telegram":
        base = canal.get("api", "https://api.telegram.org")
        post_json("%s/bot%s/sendMessage" % (base.rstrip("/"), ler_segredo(canal["token_arquivo"])),
                  {"chat_id": canal["chat_id"], "text": (assunto + "\n\n" + texto)[:4000], "disable_web_page_preview": True})
    elif t in ("mattermost", "slack", "rocketchat"):
        post_json(ler_segredo(canal["url_arquivo"]), {"text": ("**%s**\n```\n%s\n```" % (assunto, texto[:15000]))})
    elif t == "teams":
        corpo = [{"type": "TextBlock", "text": assunto, "weight": "Bolder", "wrap": True}]
        corpo += [{"type": "TextBlock", "text": bloco, "wrap": True, "spacing": "Medium"} for bloco in texto.split("\n\n") if bloco.strip()][:40]
        post_json(ler_segredo(canal["url_arquivo"]), {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": corpo}}]})
    else:
        raise ValueError("tipo de canal desconhecido: %r" % t)


def difundir(cfg, evento, assunto, texto, simular=False):
    """Envia a todos os canais que aceitam o evento. Devolve (sucessos, falhas)."""
    ok = falhas = 0
    for i, canal in enumerate(cfg.get("canais", [])):
        if evento not in canal.get("eventos", ["imediato", "resumo"]) and evento != "teste":
            continue
        nome = "%s#%d" % (canal.get("tipo"), i)
        if simular:
            print("--- [simulação] %s: %s\n%s" % (nome, assunto, texto))
            ok += 1
            continue
        try:
            enviar_canal(canal, assunto, texto)
            ok += 1
            print("enviado: %s" % nome)
        except Exception as e:  # um canal com problema não impede os outros
            falhas += 1
            print("FALHA ao enviar por %s: %s" % (nome, str(e)[:200]), file=sys.stderr)
    return ok, falhas


# ---------------------------------------------------------------- feed

def gerar_feed(vulns, coletas, painel, saida):
    titulo = {it["id"]: it for it in vulns.get("itens", [])}
    entradas = []
    for co in reversed((coletas or [])[-60:]):
        quando = co.get("id", "")
        try:
            pub = dt.datetime.fromisoformat(quando)
        except ValueError:
            continue
        for tipo, ids in (("Novo", co.get("novos") or []), ("Atualizado", co.get("alterados") or [])):
            for i in ids:
                it = titulo.get(i)
                if not it:
                    continue
                d = it.get("decisao") or {}
                desc = "%s. %s %s" % (d.get("rotulo", ""), nota_txt(it), (it.get("resumo") or "")[:600])
                entradas.append((pub, "%s: %s" % (tipo, it.get("titulo", i)), desc.strip(), "%s|%s|%s" % (quando, tipo, i)))
    entradas = entradas[:200]
    agora = dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    x = ['<?xml version="1.0" encoding="utf-8"?>', '<rss version="2.0"><channel>',
         "<title>Radar de Vulnerabilidades</title>", "<link>%s</link>" % escape(painel or "https://localhost/"),
         "<description>Itens novos e atualizados a cada coleta</description>", "<language>pt-BR</language>",
         "<lastBuildDate>%s</lastBuildDate>" % agora]
    for pub, tit, desc, guid in entradas:
        x.append("<item><title>%s</title><link>%s</link><description>%s</description><pubDate>%s</pubDate><guid isPermaLink=\"false\">%s</guid></item>"
                 % (escape(tit), escape(painel or "https://localhost/"), escape(desc),
                    pub.astimezone(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"), escape(guid)))
    x.append("</channel></rss>")
    tmp = saida + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(x) + "\n")
    os.replace(tmp, saida)
    return len(entradas)


# ---------------------------------------------------------------- principal

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("comando", choices=["enviar", "resumo", "testar", "feed"])
    ap.add_argument("--site", required=True, help="pasta com vulns.json e coletas.json (e inventario.json, se houver)")
    ap.add_argument("--config", default=os.environ.get("RADAR_NOTIFICACOES", "/etc/radar/notificacoes.json"))
    ap.add_argument("--estado", default="/var/lib/radar-coletor/notificados.json")
    ap.add_argument("--saida", help="feed: arquivo de saída (padrão SITE/novidades.xml)")
    ap.add_argument("--simular", action="store_true", help="mostra as mensagens em vez de enviar")
    ap.add_argument("--enviar-existentes", action="store_true", help="enviar: na primeira execução, avisa também o que já existia")
    a = ap.parse_args()

    vulns = ler_json(os.path.join(a.site, "vulns.json"))
    if not vulns or not isinstance(vulns.get("itens"), list):
        sys.exit("vulns.json ausente ou inválido em " + a.site)
    coletas = ler_json(os.path.join(a.site, "coletas.json"), []) or []
    inv = ler_json(os.path.join(a.site, "inventario.json"))
    cfg = ler_json(a.config, None)
    if a.comando != "feed" and cfg is None:
        sys.exit("Configuração ausente ou inválida: %s (veja implantacao/coletor/notificacoes.exemplo.json)" % a.config)
    cfg = cfg or {}
    painel = cfg.get("painel_url", "")
    if painel and not url_permitida(painel):
        painel = ""

    if a.comando == "feed":
        n = gerar_feed(vulns, coletas, painel, a.saida or os.path.join(a.site, "novidades.xml"))
        print("feed: %d entradas" % n)
        return
    if a.comando == "testar":
        ok, falhas = difundir(cfg, "teste", "Radar: mensagem de teste", "Se você recebeu isto, o canal está configurado.\n" + (("Painel: " + painel) if painel else ""), a.simular)
        sys.exit(1 if falhas else 0)
    if a.comando == "resumo":
        ok, falhas = difundir(cfg, "resumo", "Radar: resumo diário", texto_resumo(vulns, coletas, inv, painel), a.simular)
        sys.exit(1 if falhas and not ok else 0)

    # enviar (imediato)
    estado = ler_json(a.estado, None)
    primeira = estado is None
    estado = estado or {"vistos": {}}
    eventos = [e for e in eventos_imediatos(vulns, vulns.get("coleta") or {}, float(cfg.get("epss_minimo", 0.1))) if e[0] not in estado["vistos"]]
    agora = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    if primeira and not a.enviar_existentes:
        for k, _, _ in eventos:
            estado["vistos"][k] = agora
        if not a.simular:
            gravar_json(a.estado, estado)
        print("Primeira execução: %d avisos existentes registrados sem envio (use --enviar-existentes para enviá-los)." % len(eventos))
        return
    if not eventos:
        print("Nada novo para avisar.")
        return
    por_item = {}
    for k, it, motivo in eventos:
        por_item.setdefault(it["id"], [it, []])[1].append(motivo)
    releases = vulns.get("releases") or {}
    ordem = {k: n for n, (k, _) in enumerate(DECISOES)}
    lst = sorted(por_item.values(), key=lambda x: (ordem.get((x[0].get("decisao") or {}).get("codigo"), 9), x[0]["id"]))
    blocos = [bloco_item(it, releases, "; ".join(m)) for it, m in lst[:10]]
    if len(lst) > 10:
        blocos.append("E mais %d item(ns) no painel." % (len(lst) - 10))
    if painel:
        blocos.append("Painel: " + painel)
    nomes = ", ".join(it.get("titulo", it["id"]).split(":")[0] for it, _ in lst[:3])
    assunto = "Radar: %d aviso(s) urgente(s): %s%s" % (len(lst), nomes, "…" if len(lst) > 3 else "")
    ok, falhas = difundir(cfg, "imediato", assunto, "\n\n".join(blocos), a.simular)
    if ok and not a.simular:
        for k, _, _ in eventos:
            estado["vistos"][k] = agora
        # esquece avisos com mais de 180 dias para o arquivo não crescer sem limite
        limite = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=180)).isoformat()
        estado["vistos"] = {k: v for k, v in estado["vistos"].items() if v >= limite}
        gravar_json(a.estado, estado)
    sys.exit(1 if falhas and not ok else 0)


if __name__ == "__main__":
    main()
