<#
Radar de Vulnerabilidades: CORREÇÃO no Windows Server, passo a passo
Instala, pelo próprio Windows Update (ou pelo WSUS configurado), as atualizações de segurança pendentes.
Pergunta antes de cada ação e nunca reinicia o servidor.
Uso: powershell -ExecutionPolicy Bypass -File radar-corrigir.ps1 [-Simular]
  -Simular  não altera nada: só mostra o diagnóstico e as atualizações que seriam instaladas
Ao final grava um ponto de restauração em C:\ProgramData\radar-vuln\<data>\ para o radar-rollback.ps1.
#>
param([switch]$Simular)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
@@COMUM@@

function Perguntar([string]$texto, [string]$padrao = 'n') {
  if ($Simular -and $env:RADAR_RESPOSTA) { Write-Host "$texto -> $env:RADAR_RESPOSTA (automático, simulação)"; $r = $env:RADAR_RESPOSTA }
  elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
    $op = 's/N'; if ($padrao -eq 's') { $op = 'S/n' }
    $r = Read-Host "$texto [$op]"
  } else { $r = '' }
  if (-not $r) { $r = $padrao }
  return ($r -match '^(s|sim|y|yes)$')
}
function Passo([string]$t) { Write-Host ''; Write-Host "━━ $t ━━" -ForegroundColor White }

try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $admin = $false }
if (-not $Simular -and -not $admin) { Write-Host 'Rode como administrador (ou use -Simular para só ver o que seria feito).' -ForegroundColor Red; exit 2 }

$s = Get-RadarSistema
Test-RadarSistema $s
Write-Host 'Radar de Vulnerabilidades: correção passo a passo' -ForegroundColor White
if ($Simular) { Write-Host 'MODO SIMULAÇÃO: nada será alterado.' -ForegroundColor Yellow }
Write-Host "Host: $RadarHost · $($s.Rotulo) · build $($s.Versao)"
Test-RadarIdade

Passo 'Passo 1 de 5: diagnóstico'
$vuln = @(Get-RadarResultado $s | Where-Object { $_.Status -eq 'VULNERAVEL' } | Sort-Object Build -Descending)
if (-not $vuln.Count) { Write-Host 'Nenhuma falha explorada conhecida afeta este build. Nada a corrigir.' -ForegroundColor Green; exit 0 }
foreach ($x in $vuln) { Write-Host ("  {0} · {1} (corrigido no KB{2}, build {3})" -f $x.Cve, $x.Titulo, $x.Kb, $x.Build) -ForegroundColor Red }
Write-Host ("Build necessário: {0} ou mais novo (KB{1})." -f $vuln[0].Build, $vuln[0].Kb)

Passo 'Passo 2 de 5: ponto de restauração'
Write-Host 'O Windows Server não tem restauração do sistema: antes de atualizar, faça um snapshot da VM ou um backup do servidor.'
if (-not (Perguntar 'Já fez (ou não precisa de) snapshot ou backup e quer continuar?' 's')) { Write-Host 'Encerrado sem alterações.'; exit 0 }
$carimbo = Get-Date -Format 'yyyyMMdd-HHmmss'
if ($Simular) { $pasta = Join-Path ([IO.Path]::GetTempPath()) "radar-simulacao-$carimbo" } else { $pasta = Join-Path $env:ProgramData "radar-vuln\$carimbo" }
New-Item -ItemType Directory -Force -Path $pasta | Out-Null
"$($s.Versao)" | Set-Content (Join-Path $pasta 'build-antes.txt')
try { Get-HotFix | Select-Object HotFixID, InstalledOn, Description | Export-Csv (Join-Path $pasta 'atualizacoes-antes.csv') -NoTypeInformation -Encoding UTF8 }
catch { Write-Host "Não consegui listar as atualizações instaladas (Get-HotFix): $($_.Exception.Message)" -ForegroundColor Yellow }
New-Item -ItemType File -Force -Path (Join-Path $pasta 'aplicados.txt') | Out-Null
Write-Host "Atualizações instaladas e build atual salvos em $pasta"

Passo 'Passo 3 de 5: procurar as atualizações de segurança'
Write-Host 'Consultando o Windows Update (ou o WSUS configurado). Pode levar alguns minutos…'
try {
  $sessao = New-Object -ComObject Microsoft.Update.Session
  $sessao.ClientApplicationID = 'Radar de Vulnerabilidades'
  $busca = $sessao.CreateUpdateSearcher()
  $res = $busca.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
} catch {
  Write-Host "Não consegui consultar o Windows Update: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host 'Confira se o serviço Windows Update (wuauserv) está ativo e se o servidor alcança o Windows Update ou o WSUS.'
  exit 1
}
$atual = @()
foreach ($u in $res.Updates) {
  $seg = $false
  foreach ($c in $u.Categories) { if ($c.Name -match 'Security Updates|Atualizações de segurança') { $seg = $true } }
  if ($seg -or $u.Title -match 'Cumulative|cumulativa') { $atual += $u }
}
if (-not $atual.Count) {
  Write-Host 'Nenhuma atualização de segurança disponível na fonte configurada (Windows Update ou WSUS).' -ForegroundColor Yellow
  Write-Host ("Se o build continua abaixo de {0}, confira se o KB{1} foi aprovado no WSUS ou baixe-o no Microsoft Update Catalog." -f $vuln[0].Build, $vuln[0].Kb)
  exit 1
}
foreach ($u in $atual) {
  $kbs = (@($u.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ', '
  Write-Host ("  {0} · {1} · {2:N0} MB" -f $kbs, $u.Title, ($u.MaxDownloadSize / 1MB))
}

Passo 'Passo 4 de 5: instalar'
if (-not (Perguntar "Instalar estas $($atual.Count) atualização(ões) agora?" 'n')) { Write-Host 'Encerrado sem alterações.'; exit 0 }
if ($Simular) {
  Write-Host 'Simulação: baixaria e instalaria as atualizações acima pelo Windows Update, sem reiniciar.' -ForegroundColor Cyan
} else {
  $col = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $atual) { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$col.Add($u) }
  $baixar = $sessao.CreateUpdateDownloader(); $baixar.Updates = $col; [void]$baixar.Download()
  $inst = $sessao.CreateUpdateInstaller(); $inst.Updates = $col
  $resultado = $inst.Install()
  for ($i = 0; $i -lt $col.Count; $i++) {
    $cod = $resultado.GetUpdateResult($i).ResultCode
    $kbs = @($col.Item($i).KBArticleIDs) -join ','
    $txt = @{ 2 = 'instalada'; 3 = 'instalada com avisos'; 4 = 'FALHOU'; 5 = 'cancelada' }[[int]$cod]
    Write-Host ("  KB{0}: {1}" -f $kbs, $txt)
    if ($cod -eq 2 -or $cod -eq 3) { "$kbs" | Add-Content (Join-Path $pasta 'aplicados.txt') }
  }
  if ($resultado.RebootRequired) { Write-Host 'É preciso reiniciar para concluir. Agende a janela: este script não reinicia.' -ForegroundColor Yellow }
}

Passo 'Passo 5 de 5: conferência'
Write-Host 'O build só muda depois de reiniciar. Depois do reinício, rode: powershell -ExecutionPolicy Bypass -File radar-verificar.ps1'
Write-Host "Ponto de restauração: $pasta"
Write-Host "Para desfazer: powershell -ExecutionPolicy Bypass -File radar-rollback.ps1 `"$pasta`""
