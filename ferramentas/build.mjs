// Monta site/painel.html (com o gerador embutido) e os scripts completos em scripts/.
// Uso: node ferramentas/build.mjs
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync, rmSync } from "node:fs";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const aqui = dirname(fileURLToPath(import.meta.url));
const proj = dirname(aqui);
const require = createRequire(import.meta.url);
const gerador = require(join(aqui, "gerador.js"));

const ler = (p) => readFileSync(join(aqui, p), "utf8");
const modelos = {
  comum: ler("modelos/comum.sh"),
  verificar: ler("modelos/verificar.sh"),
  corrigir: ler("modelos/corrigir.sh"),
  rollback: ler("modelos/rollback.sh"),
  ansible: ler("modelos/ansible.yml"),
  completo: ler("completo.py"),
};
const dados = JSON.parse(readFileSync(join(proj, "site", "vulns.json"), "utf8"));

// JSON seguro dentro de <script>: escapa "<".
const emScript = (v) => JSON.stringify(v).replace(/</g, "\\u003c").replace(new RegExp("\\u2028", "g"), "\\u2028").replace(new RegExp("\\u2029", "g"), "\\u2029");

// F17: publicação pública (GitHub Pages). RADAR_PUBLICO=1 tira as partes institucionais e as fontes de terceiros.
const publico = process.env.RADAR_PUBLICO === "1";
const repo = process.env.RADAR_REPO || "";
if (repo && !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) throw new Error("RADAR_REPO inválido (use dono/nome)");
const horario = /^\d{2}:\d{2}$/.test(process.env.RADAR_HORARIO || "") ? process.env.RADAR_HORARIO : "06:40";
const config = { publico, repo, horario };

let pagina = ler("pagina.html");
pagina = pagina.split("/*@@GERADOR@@*/").join(ler("gerador.js"));
pagina = pagina.split("/*@@MODELOS@@*/null").join(emScript(modelos));
pagina = pagina.split("/*@@CONFIG@@*/{}").join(emScript(config));
if (publico) {
  // Sem Google Fonts (privacidade: nenhum pedido a terceiros) e sem metadados do claude.ai.
  pagina = pagina.split("\n").filter((l) => !/fonts\.googleapis\.com|claude:viewport/.test(l)).join("\n");
}
writeFileSync(join(proj, "site", "painel.html"), pagina);

// Scripts completos: todos os itens, todas as versões.
mkdirSync(join(proj, "scripts"), { recursive: true });
const ids = dados.itens.map((i) => i.id);
const geradoEm = new Date().toISOString().slice(0, 16).replace("T", " ") + " UTC";
const somas = [];
for (const tipo of ["verificar", "corrigir", "rollback", "ansible"]) {
  const r = gerador.gerar(dados, modelos, { tipo, releases: gerador.RELEASES, ids, geradoEm });
  const nome = tipo === "ansible" ? "radar-ansible.yml" : `radar-${tipo}.sh`;
  const arq = join(proj, "scripts", nome);
  writeFileSync(arq, r.texto);
  chmodSync(arq, tipo === "ansible" ? 0o644 : 0o755);
  console.log(`scripts/${nome}: ${r.itens} itens, ${r.linhas} linhas de dados, ${r.descartes} descartadas`);
  somas.push(`${createHash("sha256").update(r.texto, "utf8").digest("hex")}  ${nome}`);
}
// F25: scripts do Windows Server (PowerShell) com as falhas exploradas que têm correção no Windows Server
// (aba Exploradas). Cada linha é validada; o arquivo vai com BOM UTF-8 para o PowerShell 5.1 ler os acentos.
const arqExpl = join(proj, "site", "exploradas.json");
if (existsSync(arqExpl)) {
  const expl = JSON.parse(readFileSync(arqExpl, "utf8"));
  const RW = { cve: /^CVE-\d{4}-\d{4,7}$/, kb: /^KB\d{6,8}$/, build: /^10\.0\.\d{5}\.\d{1,6}$/, data: /^\d{4}-\d{2}-\d{2}$/ };
  const limparWin = (t) => String(t || "").replace(/[\u0000-\u001f\u007f\u2028\u2029|`$]/g, " ").replace(/\s+/g, " ").trim().slice(0, 160);
  const linhasWin = [];
  let descWin = 0;
  for (const e of expl.itens || []) {
    for (const r of ["ws2016", "ws2019", "ws2022", "ws2025"]) {
      const x = (e.so || {})[r];
      if (!x) continue;
      if (!RW.cve.test(e.cve) || !RW.kb.test(x.p || "") || !RW.build.test(x.v || "") || !RW.data.test(e.d || "")) { descWin++; continue; }
      linhasWin.push([r, e.cve, x.p.slice(2), x.v, e.d, e.r ? 1 : 0, limparWin(`${e.f} ${e.p}: ${e.n}`)].join("|"));
    }
  }
  const comumWin = ler("modelos/windows-comum.ps1");
  for (const tipo of ["verificar", "corrigir", "rollback"]) {
    let t = ler(`modelos/windows-${tipo}.ps1`).split("@@COMUM@@").join(comumWin);
    const col = dados.coleta || {};
    const dataCol = /^\d{4}-\d{2}-\d{2}$/.test(String(col.data || "")) ? col.data : "desconhecida";
    const kevCol = /^[0-9.]{4,20}$/.test(String(col.kev_versao || "")) ? String(col.kev_versao) : "?";
    t = t.split("@@COLETA@@").join(dataCol).split("@@KEV@@").join(kevCol)
      .split("@@GERADO@@").join(geradoEm).split("@@DADOS@@").join(linhasWin.join("\n"));
    t = "\ufeff" + t.replace(/\r?\n/g, "\r\n");
    const nome = `radar-${tipo}.ps1`;
    writeFileSync(join(proj, "scripts", nome), t, "utf8");
    console.log(`scripts/${nome}: ${linhasWin.length} linhas de dados (Windows Server), ${descWin} descartadas`);
    somas.push(`${createHash("sha256").update(t, "utf8").digest("hex")}  ${nome}`);
  }
}
// F1: integridade. SHA256SUMS sempre; assinatura GPG se RADAR_GPG_CHAVE estiver definida.
const arqSomas = join(proj, "scripts", "SHA256SUMS");
writeFileSync(arqSomas, somas.join("\n") + "\n");
const asc = arqSomas + ".asc";
const chave = process.env.RADAR_GPG_CHAVE || "";
if (chave && /^[A-Za-z0-9@._+-]{6,128}$/.test(chave)) {
  const g = spawnSync("gpg", ["--batch", "--yes", "--local-user", chave, "--armor", "--detach-sign", "--output", asc, arqSomas], { stdio: "inherit" });
  console.log(g.status === 0 ? "scripts/SHA256SUMS.asc assinado com " + chave : "AVISO: falha ao assinar SHA256SUMS");
} else if (existsSync(asc)) {
  rmSync(asc); // assinatura antiga não vale para somas novas
}
console.log("scripts/SHA256SUMS gerado");
console.log("site/painel.html gerado" + (publico ? " (modo público" + (repo ? ", " + repo : "") + ")" : ""));
