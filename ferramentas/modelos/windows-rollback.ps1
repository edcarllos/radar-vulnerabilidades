<#
Radar de Vulnerabilidades: ROLLBACK no Windows Server
Desinstala a atualização que o radar-corrigir.ps1 instalou. Isso REEXPÕE o servidor às falhas corrigidas:
use só para recuperar um serviço quebrado. O caminho mais seguro é voltar o snapshot da VM feito antes.
Uso: powershell -ExecutionPolicy Bypass -File radar-rollback.ps1 [C:\ProgramData\radar-vuln\<data>] [-Simular]
#>
param([string]$Ponto = '', [switch]$Simular)
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
function Executar([string]$descricao, [scriptblock]$acao) {
  Write-Host "  > $descricao" -ForegroundColor Cyan
  if (-not $Simular) { & $acao }
}

try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $admin = $false }
if (-not $Simular -and -not $admin) { Write-Host 'Rode como administrador (ou use -Simular).' -ForegroundColor Red; exit 2 }
$s = Get-RadarSistema
Test-RadarSistema $s
Write-Host 'Radar de Vulnerabilidades: rollback' -ForegroundColor White
if ($Simular) { Write-Host 'MODO SIMULAÇÃO: nada será alterado.' -ForegroundColor Yellow }
Write-Host 'Desinstalar atualizações reexpõe o servidor às falhas corrigidas. Se fez snapshot antes, prefira voltá-lo.' -ForegroundColor Red

if (-not $Ponto) {
  $base = Join-Path $env:ProgramData 'radar-vuln'
  $pontos = @(Get-ChildItem -Directory $base -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
  if (-not $pontos.Count) { Write-Host "Nenhum ponto de restauração em $base. Informe o caminho como argumento."; exit 1 }
  Write-Host 'Pontos de restauração:'
  for ($i = 0; $i -lt $pontos.Count -and $i -lt 10; $i++) { Write-Host ("  {0}) {1}" -f ($i + 1), $pontos[$i].FullName) }
  $Ponto = $pontos[0].FullName
  Write-Host "Usando o mais recente: $Ponto"
}
$arq = Join-Path $Ponto 'aplicados.txt'
if (-not (Test-Path $arq)) { Write-Host "Ponto de restauração inválido: $Ponto (falta aplicados.txt)"; exit 1 }
$antes = (Get-Content (Join-Path $Ponto 'build-antes.txt') -ErrorAction SilentlyContinue | Select-Object -First 1)
Write-Host "Build antes da correção: $antes · build agora: $($s.Versao)"
$kbs = @(Get-Content $arq | ForEach-Object { $_ -split ',' } | Where-Object { $_ -match '^\d{6,8}$' } | Select-Object -Unique)
if (-not $kbs.Count) { Write-Host 'O ponto de restauração não registra atualizações instaladas.'; exit 0 }

if ($s.Rel -eq 'ws2016') {
  # No 2016 cada atualização sai pelo wusa, inclusive a cumulativa.
  foreach ($kb in $kbs) {
    Write-Host ''
    Write-Host "KB$kb" -ForegroundColor White
    if (Perguntar "  Desinstalar o KB$kb (wusa, sem reiniciar)?" 'n') {
      Executar "wusa.exe /uninstall /kb:$kb /quiet /norestart" { Start-Process -Wait -FilePath wusa.exe -ArgumentList "/uninstall /kb:$kb /quiet /norestart" }
    }
  }
} else {
  # A partir do 2019 a cumulativa vem junto com a de pilha (SSU) e só sai pelo DISM: remove-se uma vez,
  # o pacote RollupFix do build atual, e só se o build subiu desde a correção.
  Write-Host ''
  Write-Host "Atualizações registradas pela correção: $((@($kbs) | ForEach-Object { "KB$_" }) -join ', ')"
  $vAntes = $null; try { $vAntes = [version]"$antes" } catch { }
  if ($vAntes -and $s.Versao -le $vAntes) {
    Write-Host "O build atual ($($s.Versao)) não é mais novo que o de antes da correção ($vAntes): não há atualização cumulativa a remover. Se ainda não reiniciou, reinicie antes; a correção só muda o build depois do reinício."
    exit 0
  }
  try {
    $pac = @(Get-WindowsPackage -Online | Where-Object { $_.PackageName -like 'Package_for_RollupFix*' -and $_.PackageState -eq 'Installed' })
  } catch {
    Write-Host "Não consegui listar os pacotes com o DISM (rode como administrador): $($_.Exception.Message)" -ForegroundColor Yellow
    $pac = @()
  }
  $alvo = @($pac | Where-Object { $_.PackageName -like "*~$($s.Build).$($s.Ubr).*" })
  if (-not $alvo.Count -and $pac.Count) {
    Write-Host "Nenhum pacote RollupFix com o build atual ($($s.Build).$($s.Ubr)) no nome; usando o instalado mais recentemente." -ForegroundColor Yellow
    $alvo = @($pac | Sort-Object InstallTime -Descending | Select-Object -First 1)
  }
  if (-not $alvo.Count) {
    Write-Host 'Não encontrei o pacote da atualização cumulativa no DISM. Use o snapshot ou a desinstalação pelas Configurações do Windows.'
  } else {
    $p = $alvo[0].PackageName
    Write-Host "Pacote da atualização cumulativa do build atual: $p"
    if (Perguntar 'Remover este pacote com o DISM (sem reiniciar)?' 'n') {
      Executar "Remove-WindowsPackage -Online -PackageName $p -NoRestart" { Remove-WindowsPackage -Online -PackageName $p -NoRestart | Out-Null }
      Write-Host 'Reinicie numa janela combinada para concluir. A atualização de pilha (SSU) continua instalada, como a Microsoft determina.'
    }
  }
  Write-Host 'Outras atualizações da lista (por exemplo, do .NET) não são removidas aqui: se causarem problema, desinstale pelas Configurações do Windows.'
}
Write-Host ''
Write-Host 'Depois de reiniciar, confira com: powershell -ExecutionPolicy Bypass -File radar-verificar.ps1'
