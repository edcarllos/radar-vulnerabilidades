/*
 * Radar de Vulnerabilidades: gerador de scripts.
 * O mesmo código roda no painel (navegador) e no Node (ferramentas/build.mjs).
 * Todo campo que entra no script é validado por expressão regular; o que não passa é descartado.
 */
(function (raiz, fabrica) {
  if (typeof module === "object" && module.exports) module.exports = fabrica();
  else raiz.RadarGerador = fabrica();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var RELEASES = ["deb12", "deb13", "u2204", "u2404", "u2604"];
  var ROTULOS = {
    deb12: "Debian 12 (bookworm)",
    deb13: "Debian 13 (trixie)",
    u2204: "Ubuntu 22.04 LTS (jammy)",
    u2404: "Ubuntu 24.04 LTS (noble)",
    u2604: "Ubuntu 26.04 LTS (resolute)"
  };
  var RE = {
    id: /^[a-z0-9][a-z0-9-]{2,60}$/,
    pkg: /^[a-z0-9][a-z0-9+.-]{0,62}$/,
    ver: /^[0-9][0-9A-Za-z.+~:-]{0,80}$/,
    appver: /^\d+(\.\d+){1,3}$/,
    cve: /^CVE-\d{4}-\d{4,7}$/,
    aviso: /^((DSA|DLA|USN)-\d{3,5}-\d{1,2}|SA-CORE-\d{4}-\d{3})$/,
    estado: /^(corrigido|parcial|pro|sem_correcao|em_triagem|nao_afetado|nao_empacotado|nao_verificado)$/,
    decisao: /^(agir_agora|agir_em_breve|acompanhar_de_perto|acompanhar|nao_se_aplica)$/,
    app: /^(drupal|wordpress|gitlab|freeswitch|moodle|glpi|ojs|nextcloud|keycloak|dspace)$/,
    plugin: /^[a-z]+_[a-z][a-z0-9_]{1,50}$/,
    data: /^\d{4}-\d{2}-\d{2}$/,
    kev: /^[0-9.]{4,20}$/
  };

  var RE_LIMPAR = new RegExp("[\\u0000-\\u001f\\u007f\\u2028\\u2029|`]", "g");

  function limpo(s, max) {
    // Uma linha, sem separador de campo nem caracteres de controle.
    return String(s == null ? "" : s)
      .replace(RE_LIMPAR, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, max || 200);
  }

  function nota(item) {
    var p = item.pontuacao || {};
    return typeof p.valor === "number" && isFinite(p.valor) ? p.valor.toFixed(1) : "-";
  }

  function cvesCurtos(item) {
    var l = (item.cves || []).filter(function (c) { return RE.cve.test(c); });
    var s = l.slice(0, 3).join(",");
    return l.length > 3 ? s + ",+" + (l.length - 3) : s;
  }

  function montar(dados, sel) {
    var rels = (sel.releases || []).filter(function (r) { return RELEASES.indexOf(r) >= 0; });
    var ids = {};
    (sel.ids || []).forEach(function (i) { ids[i] = true; });
    var linhas = [], textos = [], itens = 0, descartes = 0;

    function add(campos) {
      var l = campos.join("|");
      if (l === "RADAR_DADOS_FIM" || l === "RADAR_TEXTOS_FIM") return;
      linhas.push(l);
    }
    function texto(id, tipo, t) {
      t = limpo(t, 400).replace(/\|/g, "/");
      if (t) textos.push(id + "|" + tipo + "|" + t);
    }

    (dados.itens || []).forEach(function (it) {
      if (!ids[it.id] || !RE.id.test(it.id)) return;
      itens++;
      var titulo = limpo(it.titulo, 140);
      var dec = it.decisao && RE.decisao.test(it.decisao.codigo || "") ? it.decisao.codigo : "acompanhar";
      var cv = nota(it);
      var cs = cvesCurtos(it);
      if (it.tipo === "manual") {
        add(["*", it.id, "manual", "-", "-", "-", "-", "", cv, cs, dec, titulo]);
      }
      {
        if (it.app && RE.app.test(it.app.tipo)) {
          var mins = (it.app.minimos || []).filter(function (v) { return RE.appver.test(v); });
          if (mins.length) add(["*", it.id, "app", it.app.tipo, it.app.estrito ? "estrito" : (it.app.derivado ? "derivado" : "leniente"), mins.join(","), "-", "", cv, cs, dec, titulo]);
          else if (it.app.info) add(["*", it.id, "app", it.app.tipo, "info", "-", "-", "", cv, cs, dec, titulo]);
          (it.plugins || []).forEach(function (pl) {
            var pc = (pl.cves || []).filter(function (c) { return RE.cve.test(c); }).slice(0, 3).join(",");
            if (RE.plugin.test(pl.componente || "")) add(["*", it.id, "plugin", pl.componente, "-", "-", "-", "", cv, pc, dec, titulo]);
          });
        }
        if (it.tipo !== "manual") rels.forEach(function (r) {
          ((it.linhas || {})[r] || []).forEach(function (ln) {
            var ok = RE.pkg.test(ln.pacote || "") && RE.estado.test(ln.estado || "");
            var versao = ln.versao || "-";
            if (versao !== "-" && !RE.ver.test(versao)) ok = false;
            if (/^(corrigido|parcial|pro)$/.test(ln.estado) && versao === "-") ok = false;
            var aviso = RE.aviso.test(ln.aviso || "") ? ln.aviso : "";
            var ups = (it.upstream_minimos || []).filter(function (v) { return RE.appver.test(v); }).join(",") || "-";
            if (!ok) { descartes++; return; }
            var tipo = it.tipo === "kernel" ? "kernel" : "src";
            if (tipo === "kernel" && !/^(corrigido|parcial|pro)$/.test(ln.estado)) return;
            add([r, it.id, tipo, ln.pacote, ln.estado, versao, ups, aviso, cv, cs, dec, titulo]);
          });
        });
        // Referências de todas as versões: permitem avaliar PHP instalado de outra versão da distro ou de PPA.
        var upsRef = (it.upstream_minimos || []).filter(function (v) { return RE.appver.test(v); }).join(",");
        if (upsRef) {
          RELEASES.forEach(function (r) {
            ((it.linhas || {})[r] || []).forEach(function (ln) {
              if (/^php[0-9]+\.[0-9]+$/.test(ln.pacote || "") && /^(corrigido|parcial|pro)$/.test(ln.estado) && RE.ver.test(ln.versao || "")) {
                add(["*", it.id, "ref", ln.pacote, ln.estado, ln.versao, upsRef, RE.aviso.test(ln.aviso || "") ? ln.aviso : "", cv, cs, dec, titulo]);
              }
            });
          });
        }
        (it.bibliotecas || []).forEach(function (b) {
          if (RE.pkg.test(b)) add(["*", it.id, "lib", b, "-", "-", "-", "", cv, cs, dec, titulo]);
        });
      }
      texto(it.id, "correcao", it.correcao_app);
      texto(it.id, "rollback", it.rollback_app);
      texto(it.id, "verificar", it.como_verificar);
      texto(it.id, "mitigacao", (it.mitigacao || []).slice(0, 2).join("; "));
    });
    return { rels: rels, linhas: linhas, textos: textos, itens: itens, descartes: descartes };
  }

  function substituir(s, mapa) {
    Object.keys(mapa).forEach(function (k) { s = s.split("@@" + k + "@@").join(mapa[k]); });
    return s;
  }

  /**
   * gerar(dados, modelos, {tipo, releases, ids, geradoEm}) -> {texto, itens, descartes}
   * modelos: {comum, verificar, corrigir, rollback} (textos dos arquivos em ferramentas/modelos)
   */
  function gerar(dados, modelos, op) {
    var tipo = op.tipo;
    if (!/^(verificar|corrigir|rollback|ansible)$/.test(tipo)) throw new Error("tipo inválido");
    if (tipo === "ansible") {
      // F10: o playbook embute o script de verificação da mesma seleção num bloco YAML !unsafe (sem templating).
      var v = gerar(dados, modelos, { tipo: "verificar", releases: op.releases, ids: op.ids, geradoEm: op.geradoEm });
      if (/[\u0000-\u0008\u000b-\u001f\u007f\u0085\u2028\u2029\ufeff]/.test(v.texto) || !/^#!/.test(v.texto)) throw new Error("script de verificação com caractere que o YAML não aceita");
      var mv = montar(dados, op);
      var yml = substituir(String(modelos.ansible || ""), {
        GERADO: limpo(op.geradoEm || new Date().toISOString().slice(0, 16).replace("T", " "), 30),
        COLETA: (dados.coleta && RE.data.test(dados.coleta.data)) ? dados.coleta.data : "desconhecida",
        KEV: (dados.coleta && RE.kev.test(String(dados.coleta.kev_versao || ""))) ? dados.coleta.kev_versao : "?",
        QTD_ITENS: String(mv.itens),
        RELEASES_ROTULOS: mv.rels.map(function (r) { return ROTULOS[r]; }).join(", ") || "nenhuma",
        VERIFICAR_YAML: v.texto.replace(/\n$/, "").split("\n").map(function (l) { return l ? "      " + l : ""; }).join("\n")
      });
      return { texto: yml, itens: v.itens, linhas: v.linhas, descartes: v.descartes };
    }
    var m = montar(dados, op);
    var coleta = (dados.coleta && RE.data.test(dados.coleta.data)) ? dados.coleta.data : "desconhecida";
    var kev = (dados.coleta && RE.kev.test(String(dados.coleta.kev_versao || ""))) ? dados.coleta.kev_versao : "?";
    var gerado = limpo(op.geradoEm || new Date().toISOString().slice(0, 16).replace("T", " "), 30);
    var comum = substituir(modelos.comum, {
      COLETA: coleta,
      KEV: kev,
      GERADO: gerado,
      RELEASES: m.rels.join(" "),
      RELEASES_ROTULOS: m.rels.map(function (r) { return ROTULOS[r]; }).join(", ") || "nenhuma",
      QTD_ITENS: String(m.itens),
      DADOS: m.linhas.join("\n"),
      TEXTOS: m.textos.join("\n")
    });
    var py = String(modelos.completo || "");
    if (/^RADAR_PY_FIM$/m.test(py)) py = "";
    var texto = substituir(modelos[tipo], { COMUM: comum, PY_COMPLETO: py });
    return { texto: texto, itens: m.itens, linhas: m.linhas.length, descartes: m.descartes };
  }

  return { gerar: gerar, montar: montar, RELEASES: RELEASES, ROTULOS: ROTULOS };
});
