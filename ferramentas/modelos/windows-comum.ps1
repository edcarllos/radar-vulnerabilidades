# ---------------------------------------------------------------------------
# Radar de Vulnerabilidades: funções comuns (Windows Server)
# Dados coletados em @@COLETA@@ (catálogo KEV @@KEV@@). Script gerado em @@GERADO@@.
# Dados do Microsoft Security Update Guide (https://msrc.microsoft.com/update-guide) e, para o build de KBs antigos,
# das páginas de histórico de atualizações da Microsoft (support.microsoft.com), usados com atribuição.
# ---------------------------------------------------------------------------
$RadarColeta = '@@COLETA@@'
$RadarGerado = '@@GERADO@@'
$RadarHost = [Environment]::MachineName
# versão|CVE|KB|build corrigido|entrada no KEV|ransomware (1/0)|título
$RadarDados = @'
@@DADOS@@
'@

function Get-RadarSistema {
  # Em testes, RADAR_WIN_BUILD, RADAR_WIN_UBR e RADAR_WIN_TIPO simulam outro servidor.
  if ($env:RADAR_WIN_BUILD) {
    $b = [int]$env:RADAR_WIN_BUILD; $u = [int]$env:RADAR_WIN_UBR; $t = [string]$env:RADAR_WIN_TIPO; $n = 'simulado'
  } else {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $b = [int]$cv.CurrentBuildNumber; $u = [int]$cv.UBR; $t = [string]$cv.InstallationType; $n = [string]$cv.ProductName
  }
  $mapa = @{ 14393 = 'ws2016'; 17763 = 'ws2019'; 20348 = 'ws2022'; 26100 = 'ws2025' }
  $rot = @{ ws2016 = 'Windows Server 2016'; ws2019 = 'Windows Server 2019'; ws2022 = 'Windows Server 2022'; ws2025 = 'Windows Server 2025' }
  $rel = $mapa[$b]
  [pscustomobject]@{ Build = $b; Ubr = $u; Tipo = $t; Nome = $n; Versao = [version]"10.0.$b.$u"; Rel = $rel; Rotulo = $(if ($rel) { $rot[$rel] } else { '' }) }
}

function Test-RadarSistema($s) {
  if ($s.Tipo -notlike 'Server*') {
    Write-Host 'Este script é para o Windows Server (2016, 2019, 2022 e 2025).' -ForegroundColor Red; exit 2
  }
  if ($s.Build -eq 9200 -or $s.Build -eq 9600) {
    Write-Host 'Windows Server 2012 e 2012 R2 estão sem suporte (o suporte estendido pago, ESU, terminou em 13/10/2026). Não recebem mais correções: migre para o 2022 ou 2025.' -ForegroundColor Red; exit 2
  }
  if (-not $s.Rel) { Write-Host "Versão do Windows Server não reconhecida (build $($s.Build))." -ForegroundColor Red; exit 2 }
}

function Get-RadarLinhas($rel) {
  foreach ($l in ($RadarDados -split "`n")) {
    $c = $l.Trim() -split '\|', 7
    if ($c.Count -eq 7 -and $c[0] -eq $rel) {
      [pscustomobject]@{ Cve = $c[1]; Kb = $c[2]; Build = [version]$c[3]; Kev = $c[4]; Ransomware = ($c[5] -eq '1'); Titulo = $c[6] }
    }
  }
}

# Atualizações cumulativas: corrigido quando o build instalado (10.0.build.UBR) é igual ou maior que o do KB.
function Get-RadarResultado($s) {
  foreach ($x in @(Get-RadarLinhas $s.Rel)) {
    $st = 'OK'; if ($s.Versao -lt $x.Build) { $st = 'VULNERAVEL' }
    $x | Add-Member -NotePropertyName Status -NotePropertyValue $st -PassThru
  }
}

function Test-RadarIdade {
  try { $dias = ((Get-Date) - [datetime]::ParseExact($RadarColeta, 'yyyy-MM-dd', $null)).Days } catch { $dias = 0 }
  if ($dias -gt 7) { Write-Host "Atenção: os dados deste script têm $dias dias ($RadarColeta). Baixe a versão nova no painel." -ForegroundColor Yellow }
}
