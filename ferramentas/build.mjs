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
