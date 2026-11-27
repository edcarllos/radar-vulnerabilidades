#!/usr/bin/env python3
"""Radar de Vulnerabilidades: relatório gerencial mensal (F14).

Gera uma página HTML imprimível (Ctrl+P vira PDF) com indicadores de gestão de vulnerabilidades:
  - servidores monitorados e sem verificação recente;
  - tempo de exposição a itens do catálogo KEV (exploração ativa);
  - aderência aos prazos da decisão SSVC (Agir agora 1 dia, Agir em breve 7, Acompanhar de perto 30, Acompanhar 90);
  - evolução diária de servidores com correção pendente e de CVEs confirmados sem correção por distro;
  - itens que mais expõem o parque no fim do período;
  - correspondência com o controle de gestão contínua de vulnerabilidades do Framework do PPSI.

Usa só o histórico medido (inventario.db: tabelas episodios e diario) e os dados da coleta (vulns.json, coletas.json).
O relatório lista nomes de servidores: publique só na intranet, como o inventário.

Uso: relatorio.py --db /var/lib/radar-coletor/inventario.db --site /var/www/radar --saida /var/www/radar/relatorios [--mes AAAA-MM]
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import sqlite3
import sys

PRAZO = {"agir_agora": 1, "agir_em_breve": 7, "acompanhar_de_perto": 30, "acompanhar": 90}
ROT = {"agir_agora": "Agir agora", "agir_em_breve": "Agir em breve", "acompanhar_de_perto": "Acompanhar de perto", "acompanhar": "Acompanhar"}
UTC = dt.timezone.utc


def ler_json(c, p=None):
    try:
        with open(c, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return p


def quando(s):
    if not s:
        return None
    d = dt.datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=UTC)


def e(s):
    return html.escape(str(s if s is not None else ""), quote=True)


def num(v, casas=1):
    return ("%%.%df" % casas % v).replace(".", ",")


def br(d):
    return d.strftime("%d/%m/%Y")


def periodo(mes):
    a, m = map(int, mes.split("-"))
    ini = dt.datetime(a, m, 1, tzinfo=UTC)
    fim = dt.datetime(a + (m == 12), (m % 12) + 1, 1, tzinfo=UTC)
    return ini, fim


def grafico_linha(pontos, titulo_y):
    """SVG de uma série (dia -> valor), com dica nativa em cada ponto. Sem bibliotecas: imprime igual em qualquer navegador."""
    if len(pontos) < 2:
        return '<p class="nota">Ainda não há dias suficientes de medição para o gráfico.</p>'
    L, A, me, md, mt, mb = 720, 220, 44, 16, 14, 30
    mx = max(v for _, v in pontos) or 1
    passo = max(1, -(-mx // 4))
    topo = passo * 4
    n = len(pontos)
    x = lambda i: me + (L - me - md) * i / (n - 1)
    y = lambda v: mt + (A - mt - mb) * (1 - v / topo)
    g = ['<svg viewBox="0 0 %d %d" role="img" aria-label="%s" class="graf">' % (L, A, e(titulo_y))]
    for k in range(5):
        v = passo * k
        g.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" class="grade"/><text x="%d" y="%.1f" class="eixo" text-anchor="end">%d</text>'
                 % (me, L - md, y(v), y(v), me - 6, y(v) + 4, v))
    rotulos = {0, n - 1, (n - 1) // 2}
    for i in rotulos:
        g.append('<text x="%.1f" y="%d" class="eixo" text-anchor="middle">%s</text>' % (x(i), A - 8, e(pontos[i][0][8:10] + "/" + pontos[i][0][5:7])))
    g.append('<polyline class="serie" points="%s"/>' % " ".join("%.1f,%.1f" % (x(i), y(v)) for i, (_, v) in enumerate(pontos)))
    for i, (d, v) in enumerate(pontos):
        g.append('<circle cx="%.1f" cy="%.1f" r="9" class="alvo"><title>%s: %d</title></circle>' % (x(i), y(v), e(d[8:10] + "/" + d[5:7]), v))
    ult = pontos[-1]
    g.append('<circle cx="%.1f" cy="%.1f" r="4" class="ponto"/><text x="%.1f" y="%.1f" class="rotulo" text-anchor="end">%d</text>'
             % (x(n - 1), y(ult[1]), x(n - 1) - 8, y(ult[1]) - 8, ult[1]))
    g.append("</svg>")
    return "".join(g)


def gerar(db, vulns, coletas, mes, agora):
    ini, fim = periodo(mes)
    ref = min(agora, fim)
    itens = {i["id"]: i for i in vulns.get("itens", [])}
    kev = {i for i, it in itens.items() if it.get("kev")}

    servidores = db.execute("SELECT host, distro, ultima FROM servidores ORDER BY host").fetchall()
    ativos = [s for s in servidores if quando(s[2]) and quando(s[2]) >= ini]
    sem_rec = [s for s in servidores if not quando(s[2]) or (ref - quando(s[2])).total_seconds() > 48 * 3600]

    epis = []
    for host, item, dec, i0, cc, f in db.execute("SELECT host, item, decisao, inicio, com_correcao, fim FROM episodios"):
        a, b = quando(i0), quando(f)
        if a >= fim or (b and b < ini):
            continue
        epis.append({"host": host, "item": item, "decisao": dec or "acompanhar", "inicio": a, "cc": quando(cc), "fim": b})

    # KEV: tempo de exposição (dias) dos episódios que tocaram o período
    kev_ep = [x for x in epis if x["item"] in kev]
    dur = [((x["fim"] or ref) - x["inicio"]).total_seconds() / 86400 for x in kev_ep]
    kev_abertos = [x for x in kev_ep if not x["fim"] or x["fim"] > ref]

    # Prazos: episódios com correção disponível cujo prazo venceu no período ou que foram fechados no período
    no_prazo = atrasado = 0
    atrasados = []
    for x in epis:
        if not x["cc"]:
            continue
        limite = x["cc"] + dt.timedelta(days=PRAZO.get(x["decisao"], 90))
        fechado = x["fim"] and x["fim"] <= ref
        if fechado and x["fim"] < ini:
            continue
        if not fechado and limite > ref:
            continue  # ainda dentro do prazo e aberto: não conta
        if fechado and x["fim"] <= limite:
            no_prazo += 1
        else:
            atrasado += 1
            if not fechado:
                atrasados.append((x, limite))
    total_prazo = no_prazo + atrasado

    # Série diária: servidores com correção pendente
    por_dia = {}
    for host, dia, resumo in db.execute("SELECT host, dia, resumo FROM diario WHERE dia >= ? AND dia < ? ORDER BY dia", (ini.date().isoformat(), fim.date().isoformat())):
        r = json.loads(resumo or "{}")
        por_dia.setdefault(dia, 0)
        if r.get("vulneravel"):
            por_dia[dia] += 1
    serie = sorted(por_dia.items())

    # CVEs confirmados sem correção por distro (coletas no período)
    hist = {}
    for c in coletas or []:
        d = str(c.get("data", ""))
        if not (ini.date().isoformat() <= d < fim.date().isoformat()):
            continue
        for rel, h in (c.get("historico") or {}).items():
            hist.setdefault(rel, []).append((d, (h.get("confirmados") or 0) + (h.get("sem_distincao") or 0), h.get("cves_kev_abertos") or 0))
    rotulos = {k: v.get("rotulo", k) for k, v in (vulns.get("releases") or {}).items()}

    # Itens que mais expõem no fim do período
    abertos_fim = {}
    for x in epis:
        if x["inicio"] <= ref and (not x["fim"] or x["fim"] > ref):
            abertos_fim.setdefault(x["item"], set()).add(x["host"])
    top = sorted(abertos_fim.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:10]

    # ---------------- HTML
    p = []
    p.append('<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">')
    p.append("<title>Radar: relatório %s</title><style>%s</style></head><body><main>" % (e(mes), CSS))
    p.append('<header><span class="sobre">Radar de Vulnerabilidades · relatório gerencial</span><h1>%s</h1>' % e(MESES[ini.month - 1].capitalize() + " de " + str(ini.year)))
    p.append('<p class="nota">Período: %s a %s%s. Gerado em %s UTC a partir do que os servidores mediram; nada aqui é declarado à mão.</p></header>'
             % (br(ini), br(fim - dt.timedelta(days=1)), " (parcial, até " + br(ref) + ")" if ref < fim else "", agora.strftime("%d/%m/%Y %H:%M")))
    media = sum(dur) / len(dur) if dur else 0
    perc = 100 * no_prazo / total_prazo if total_prazo else None
    p.append('<section class="tiles">')
    p.append(tile(len(ativos), "servidores enviaram resultados no período", ""))
    p.append(tile(len(sem_rec), "sem verificação nas últimas 48 h", "w" if sem_rec else ""))
    p.append(tile(num(media) + " dias" if dur else "—", "exposição média a itens do KEV (%d ocorrência%s)" % (len(dur), "s" if len(dur) != 1 else ""), "c" if media > 7 else ""))
    p.append(tile(len(kev_abertos), "exposições a itens do KEV ainda abertas", "c" if kev_abertos else ""))
    p.append(tile(num(perc, 0) + "%" if perc is not None else "—", "correções dentro do prazo da decisão (%d de %d)" % (no_prazo, total_prazo), "w" if perc is not None and perc < 80 else ""))
    p.append("</section>")

    p.append("<h2>Servidores com correção pendente, por dia</h2>")
    p.append(grafico_linha(serie, "Servidores com pelo menos um item vulnerável com correção disponível"))
    p.append('<p class="nota">Conta servidores com ao menos um item VULNERÁVEL (há correção na distro e ainda não foi aplicada), pelo último resultado de cada dia.</p>')

    p.append("<h2>Exposição a vulnerabilidades exploradas (KEV)</h2>")
    if kev_ep:
        p.append('<table><thead><tr><th>Servidor</th><th>Item</th><th>Desde</th><th>Até</th><th class="n">Dias</th></tr></thead><tbody>')
        for x, d in sorted(zip(kev_ep, dur), key=lambda t: -t[1])[:25]:
            p.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"n\">%s</td></tr>" % (
                e(x["host"]), e(itens.get(x["item"], {}).get("titulo", x["item"])), br(x["inicio"]), br(x["fim"]) if x["fim"] and x["fim"] <= ref else "<b>aberta</b>", num(d)))
        p.append("</tbody></table>")
    else:
        p.append('<p>Nenhum servidor ficou exposto a item do KEV no período.</p>')

    p.append("<h2>Aderência aos prazos</h2>")
    p.append('<p class="nota">Prazo contado da primeira medição com correção disponível: Agir agora 1 dia, Agir em breve 7, Acompanhar de perto 30, Acompanhar 90. Entram as correções concluídas no período e as que venceram sem correção.</p>')
    if atrasados:
        p.append('<table><thead><tr><th>Servidor</th><th>Item</th><th>Decisão</th><th>Prazo venceu em</th></tr></thead><tbody>')
        for x, lim in sorted(atrasados, key=lambda t: t[1])[:30]:
            p.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (e(x["host"]), e(itens.get(x["item"], {}).get("titulo", x["item"])), e(ROT.get(x["decisao"], x["decisao"])), br(lim)))
        p.append("</tbody></table>")
    elif total_prazo:
        p.append("<p>Nenhuma correção em atraso.</p>")
    else:
        p.append("<p>Ainda não há prazos vencidos ou correções concluídas no período.</p>")

    p.append("<h2>Itens que mais expõem o parque</h2>")
    if top:
        p.append('<table><thead><tr><th>Item</th><th>Decisão atual</th><th class="n">Servidores</th></tr></thead><tbody>')
        for item, hosts in top:
            it = itens.get(item, {})
            p.append("<tr><td>%s%s</td><td>%s</td><td class=\"n\">%d</td></tr>" % (e(it.get("titulo", item)), ' <span class="kev">KEV</span>' if item in kev else "", e(ROT.get((it.get("decisao") or {}).get("codigo"), "—")), len(hosts)))
        p.append("</tbody></table>")
    else:
        p.append("<p>Nenhum item expondo servidores no fim do período.</p>")

    p.append("<h2>Cenário externo: CVEs confirmados sem correção por distro</h2>")
    if hist:
        p.append('<table><thead><tr><th>Distro</th><th class="n">Início do período</th><th class="n">Fim do período</th><th class="n">Variação</th><th class="n">Do KEV, sem correção</th></tr></thead><tbody>')
        for rel in sorted(hist):
            l = sorted(hist[rel])
            v0, v1 = l[0][1], l[-1][1]
            p.append("<tr><td>%s</td><td class=\"n\">%d</td><td class=\"n\">%d</td><td class=\"n\">%+d</td><td class=\"n\">%d</td></tr>" % (e(rotulos.get(rel, rel)), v0, v1, v1 - v0, l[-1][2]))
        p.append("</tbody></table>")
        p.append('<p class="nota">Vale para a distro inteira, não para os nossos servidores: mostra quanto a distribuição acumula de falhas reconhecidas e ainda sem correção.</p>')
    else:
        p.append("<p>Sem coletas registradas no período.</p>")

    p.append("<h2>Correspondência com o PPSI</h2>")
    p.append('<p class="nota">Framework de Privacidade e Segurança da Informação do PPSI (baseado no CIS Controls v8), controle de gestão contínua de vulnerabilidades. Confira a numeração na versão vigente do framework.</p>')
    p.append('<table><thead><tr><th>Medida</th><th>Evidência no Radar</th></tr></thead><tbody>')
    for m, ev in PPSI:
        p.append("<tr><td>%s</td><td>%s</td></tr>" % (e(m), e(ev)))
    p.append("</tbody></table>")
    p.append('<footer class="nota">Radar de Vulnerabilidades. Fontes: CISA KEV, Debian Security Tracker, Ubuntu Security, NVD, FIRST EPSS e resultados dos servidores. Documento interno: contém nomes de servidores.</footer>')
    p.append("</main></body></html>")
    return "\n".join(p)


def tile(v, rot, cls):
    return '<div class="tile %s"><b>%s</b><span>%s</span></div>' % (cls, e(v), e(rot))


MESES = ["janeiro", "fevereiro", "março", "abril", "maio", "junho", "julho", "agosto", "setembro", "outubro", "novembro", "dezembro"]
PPSI = [
    ("7.1 Processo de gestão de vulnerabilidades", "Decisão SSVC com prazo por item; criticidade.json aprovada pela gestão; este relatório"),
    ("7.2 Processo de remediação", "radar-corrigir.sh passo a passo, playbook Ansible em lotes, rollback com ponto de restauração"),
    ("7.3 e 7.4 Atualização do sistema e das aplicações", "Verificação de pacotes, kernel e aplicações web (Moodle, GLPI, OJS, Nextcloud, Keycloak, DSpace)"),
    ("7.5 Varredura automatizada interna", "Verificação de hora em hora em cada servidor, enviada ao coletor; verificação completa diária"),
    ("7.6 Varredura de ativos expostos", "Lista de servidores expostos e consulta ao Shodan InternetDB; decisão sobe um nível"),
    ("7.7 Remediar vulnerabilidades detectadas", "Indicadores de exposição ao KEV e de aderência aos prazos acima"),
]
CSS = """
:root { --fg:#151a22; --muted:#5b6474; --line:#d8dde5; --bg:#fff; --surf:#f3f5f8; --acc:#1d4f91; --crit:#b3261e; --warn:#876000; }
@media (prefers-color-scheme: dark) { :root { --fg:#e5e9f0; --muted:#9aa3b2; --line:#2a3340; --bg:#11161d; --surf:#18202a; --acc:#8cb3ee; --crit:#ff8b80; --warn:#f0c66b; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 28px 16px 48px; }
h1 { font-size: 2rem; margin: 4px 0 2px; } h2 { font-size: 1.15rem; margin: 30px 0 8px; }
.sobre { font-size:.75rem; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); }
.nota { color: var(--muted); font-size: .85rem; margin: 4px 0; }
.tiles { display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:10px; margin-top:18px; }
.tile { border:1px solid var(--line); border-radius:6px; padding:10px 12px; display:grid; gap:2px; background:var(--surf); }
.tile b { font-size: 1.6rem; line-height:1.1; font-variant-numeric: tabular-nums; } .tile span { font-size:.8rem; color:var(--muted); }
.tile.c b { color: var(--crit); } .tile.w b { color: var(--warn); }
table { width:100%; border-collapse: collapse; font-size:.86rem; } th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align: top; }
th { font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); } .n { text-align:right; font-variant-numeric: tabular-nums; }
.kev { font-size:.7rem; border:1px solid var(--crit); color:var(--crit); border-radius:999px; padding:0 6px; margin-left:4px; }
.graf { width:100%; height:auto; } .grade { stroke: var(--line); stroke-width:1; } .eixo { fill: var(--muted); font-size: 11px; }
.serie { fill:none; stroke: var(--acc); stroke-width: 2; stroke-linejoin: round; } .ponto { fill: var(--acc); stroke: var(--bg); stroke-width: 2; }
.alvo { fill: transparent; } .alvo:hover { fill: var(--acc); fill-opacity: .15; } .rotulo { fill: var(--fg); font-size: 12px; font-weight: 600; }
footer { margin-top: 32px; }
@media print { :root { --fg:#000; --muted:#444; --line:#bbb; --bg:#fff; --surf:#fff; } main { padding: 0; } h2 { break-after: avoid; } table, .tiles, svg { break-inside: avoid; } }
"""


def main():
    ap = argparse.ArgumentParser(description="Relatório gerencial mensal do Radar")
    ap.add_argument("--db", default="/var/lib/radar-coletor/inventario.db")
    ap.add_argument("--site", required=True, help="pasta com vulns.json e coletas.json")
    ap.add_argument("--saida", required=True, help="pasta onde gravar AAAA-MM.html e index.html")
    ap.add_argument("--mes", help="AAAA-MM (padrão: mês corrente)")
    ap.add_argument("--agora", help=argparse.SUPPRESS)  # testes: data de referência ISO
    a = ap.parse_args()
    agora = quando(a.agora) if a.agora else dt.datetime.now(UTC).replace(microsecond=0)
    mes = a.mes or agora.strftime("%Y-%m")
    if not re.match(r"^\d{4}-(0[1-9]|1[0-2])$", mes):
        sys.exit("--mes deve ser AAAA-MM")
    if not os.path.exists(a.db):
        sys.exit("Banco do inventário não encontrado: %s (os servidores ainda não enviaram resultados)" % a.db)
    vulns = ler_json(os.path.join(a.site, "vulns.json"), {}) or {}
    coletas = ler_json(os.path.join(a.site, "coletas.json"), []) or []
    db = sqlite3.connect("file:%s?mode=ro" % a.db, uri=True, timeout=30)
    try:
        db.execute("SELECT 1 FROM episodios LIMIT 1")
    except sqlite3.OperationalError:
        sys.exit("O banco ainda não tem o histórico do relatório: atualize o coletor e aguarde novos resultados.")
    os.makedirs(a.saida, exist_ok=True)
    texto = gerar(db, vulns, coletas, mes, agora)
    arq = os.path.join(a.saida, mes + ".html")
    with open(arq + ".tmp", "w", encoding="utf-8") as f:
        f.write(texto)
    os.replace(arq + ".tmp", arq)
    meses = sorted((x[:-5] for x in os.listdir(a.saida) if re.match(r"^\d{4}-\d{2}\.html$", x)), reverse=True)
    ind = ['<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Radar: relatórios</title><style>%s</style></head><body><main><h1>Relatórios mensais</h1><ul>' % CSS]
    for m in meses:
        a_, m_ = m.split("-")
        ind.append('<li><a href="%s.html">%s de %s</a></li>' % (e(m), MESES[int(m_) - 1], a_))
    ind.append("</ul></main></body></html>")
    with open(os.path.join(a.saida, "index.html.tmp"), "w", encoding="utf-8") as f:
        f.write("\n".join(ind))
    os.replace(os.path.join(a.saida, "index.html.tmp"), os.path.join(a.saida, "index.html"))
    print("relatório: %s" % arq)


if __name__ == "__main__":
    main()
