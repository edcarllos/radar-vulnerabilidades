<#
Radar de Vulnerabilidades: VERIFICAÇÃO no Windows Server (somente leitura)
Compara o build instalado com o build corrigido de cada falha explorada (catálogo KEV da CISA) no Windows Server.
Uso: powershell -ExecutionPolicy Bypass -File radar-verificar.ps1 [-Todos] [-Csv] [-Json] [-Registro] [-Saida arquivo]
  -Todos      mostra também as falhas já corrigidas neste servidor
  -Csv        saída em CSV (separador ;)
  -Json       um objeto JSON com resumo e itens
  -Registro   CSV com os campos do modelo de norma de gestão de vulnerabilidades do PPSI; fica neste servidor
  -Saida      grava o CSV, o JSON ou o registro num arquivo UTF-8 (abre certo no Excel), em vez de mostrar na tela
Saída: 0 = nada vulnerável; 1 = há falhas exploradas sem a atualização; 2 = sistema não suportado.
#>
param([switch]$Todos, [switch]$Csv, [switch]$Json, [switch]$Registro, [string]$Saida = '')
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
@@COMUM@@

$s = Get-RadarSistema
Test-RadarSistema $s
$r = @(Get-RadarResultado $s)
$vuln = @($r | Where-Object { $_.Status -eq 'VULNERAVEL' } | Sort-Object Build -Descending)
$ok = @($r | Where-Object { $_.Status -eq 'OK' })
$codigo = [int]($vuln.Count -gt 0)
function Emitir($linhas) {
  if ($Saida) {
    $arq = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Saida)
    [IO.File]::WriteAllLines($arq, [string[]]@($linhas), (New-Object Text.UTF8Encoding $true))
    Write-Host "Gravado em $arq"
  } else { $linhas }
}

if ($Json) {
  $j = [pscustomobject]@{
    radar = 1; host = $RadarHost; distro = $s.Rel; build = "$($s.Versao)"; coleta = $RadarColeta; gerado = $RadarGerado
    resumo = [pscustomobject]@{ vulneravel = $vuln.Count; ok = $ok.Count }
    itens = @($(if ($Todos) { $r } else { $vuln }) | ForEach-Object { [pscustomobject]@{ status = $_.Status; cve = $_.Cve; kb = 'KB' + $_.Kb; minimo = "$($_.Build)"; kev = $_.Kev; ransomware = $_.Ransomware; titulo = $_.Titulo } })
  } | ConvertTo-Json -Depth 4
  Emitir @($j)
  exit $codigo
}
if ($Csv) {
  $l = @('status;cve;kb;minimo;instalado;kev;ransomware;titulo')
  foreach ($x in $(if ($Todos) { $r } else { $vuln })) { $l += '{0};{1};KB{2};{3};{4};{5};{6};"{7}"' -f $x.Status, $x.Cve, $x.Kb, $x.Build, $s.Versao, $x.Kev, [int]$x.Ransomware, ($x.Titulo -replace '"', "'") }
  Emitir $l
  exit $codigo
}
if ($Registro) {
  # Prazo: sugestão do Radar para falha explorada (1 dia); ajuste ao processo de remediação da instituição (PPSI 7.2 e 7.7).
  $hoje = Get-Date -Format 'yyyy-MM-dd'; $prazo = (Get-Date).AddDays(1).ToString('yyyy-MM-dd')
  $l = @('identificacao;ativo;severidade;fonte;situacao;responsavel;prazo_sugerido;data_verificacao;descricao')
  foreach ($x in $(if ($Todos) { $r } else { $vuln })) {
    $sit = 'corrigida'; $pz = ''
    if ($x.Status -eq 'VULNERAVEL') { $sit = 'aberta: correção disponível'; $pz = $prazo }
    $l += '{0};{1};"Explorada (KEV {2})";Microsoft KB{3};{4};;{5};{6};"{7}: build instalado {8}, mínimo {9}"' -f $x.Cve, $RadarHost, $x.Kev, $x.Kb, $sit, $pz, $hoje, ($x.Titulo -replace '"', "'"), $s.Versao, $x.Build
  }
  Emitir $l
  exit $codigo
}

Write-Host 'Radar de Vulnerabilidades: verificação' -ForegroundColor White
Write-Host "Host: $RadarHost · $($s.Rotulo) ($($s.Tipo)) · build $($s.Versao)"
Write-Host "Dados coletados em $RadarColeta · script gerado em $RadarGerado"
Test-RadarIdade
Write-Host ''
if ($vuln.Count) {
  Write-Host "== VULNERÁVEL ($($vuln.Count) falhas exploradas sem a atualização)" -ForegroundColor Red
  foreach ($x in $vuln) {
    $rw = ''; if ($x.Ransomware) { $rw = ' · usada por ransomware' }
    Write-Host ("  {0} · {1}{2}" -f $x.Cve, $x.Titulo, $rw) -ForegroundColor Red
    Write-Host ("         corrigido no KB{0} (build {1}) · no KEV desde {2}" -f $x.Kb, $x.Build, $x.Kev)
  }
  $max = $vuln[0]
  Write-Host ''
  Write-Host ("Instale a atualização cumulativa KB{0} (build {1}) ou mais nova: ela corrige todas as falhas acima." -f $max.Kb, $max.Build) -ForegroundColor Yellow
  Write-Host 'Próximo passo: powershell -ExecutionPolicy Bypass -File radar-corrigir.ps1 (pergunta antes de cada ação; nunca reinicia sozinho).'
} else {
  Write-Host "Nenhuma das $($r.Count) falhas exploradas conhecidas para o $($s.Rotulo) afeta este build." -ForegroundColor Green
}
if ($Todos -and $ok.Count) {
  Write-Host ''; Write-Host "== OK ($($ok.Count))" -ForegroundColor Green
  foreach ($x in $ok) { Write-Host ("  {0} · KB{1} (build {2})" -f $x.Cve, $x.Kb, $x.Build) }
} elseif ($ok.Count) {
  Write-Host "OK: $($ok.Count) falha(s) já corrigida(s) (use -Todos para listar)" -ForegroundColor Green
}
exit $codigo
