# Board1 hardware verification (ProMicro nRF52840 + SEGGER J-Link + COM11).
# Compiles CC310Smoke and CryptoSelfTest, flashes over J-Link, captures serial.
param(
    [string]$RepoRoot = (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent),
    [string]$CoreRoot = (Join-Path (Split-Path $RepoRoot -Parent) 'ArduinoNRF'),
    [string]$Fqbn = 'arduinonrf:nrf52:promicro_nrf52840:uploadmode=jlink',
    [string]$ComPort = $(if ($env:NIUS_BOARD1_COM) { $env:NIUS_BOARD1_COM } else { 'COM11' }),
    [string]$BuildRoot = (Join-Path $PSScriptRoot '..\hwverify\_verify_board1')
)

$ErrorActionPreference = 'Stop'
$cliCfg = Join-Path $RepoRoot 'vendor\hwverify\arduino-cli.yaml'
if (-not (Test-Path $cliCfg)) {
    $cliCfg = $null
}

function Invoke-ArduinoCli {
    param([string[]]$Args)
    $base = @('compile')
    if ($cliCfg) { $base = @('--config-file', $cliCfg) + $base }
    & arduino-cli @base @Args
    if ($LASTEXITCODE -ne 0) { throw "arduino-cli failed: $($Args -join ' ')" }
}

function Invoke-Upload {
    param([string]$BuildDir)
    $args = @('upload', '--fqbn', $Fqbn, '--input-dir', $BuildDir)
    if ($cliCfg) { $args = @('--config-file', $cliCfg) + $args }
    & arduino-cli @args
    if ($LASTEXITCODE -ne 0) { throw "upload failed: $BuildDir" }
}

$lib = $RepoRoot
$smokeSketch = Join-Path $CoreRoot 'hardware\arduinonrf\nrf52\libraries\CC310\examples\CC310Smoke'
$selfTest = Join-Path $RepoRoot 'examples\CryptoSelfTest'
$smokeBuild = Join-Path $BuildRoot 'CC310Smoke'
$selfBuild = Join-Path $BuildRoot 'CryptoSelfTest'

Write-Host "== verify_board1 ==" -ForegroundColor Cyan
Write-Host "repo=$RepoRoot core=$CoreRoot com=$ComPort"

New-Item -ItemType Directory -Force -Path $smokeBuild, $selfBuild | Out-Null

Write-Host "`n-- compile CC310Smoke --" -ForegroundColor Yellow
Invoke-ArduinoCli @('--fqbn', $Fqbn, '--library', $lib, '--build-path', $smokeBuild, $smokeSketch)

Write-Host "`n-- upload + capture CC310Smoke --" -ForegroundColor Yellow
Invoke-Upload $smokeBuild
$env:NIUS_BOARD1_COM = $ComPort
python (Join-Path $PSScriptRoot 'capture_board1_serial.py')

Write-Host "`n-- compile CryptoSelfTest --" -ForegroundColor Yellow
Invoke-ArduinoCli @('--fqbn', $Fqbn, '--library', $lib, '--build-path', $selfBuild, $selfTest)

Write-Host "`n-- upload + capture CryptoSelfTest --" -ForegroundColor Yellow
Invoke-Upload $selfBuild
python (Join-Path $PSScriptRoot 'capture_board1_serial.py')

Write-Host "`nboard1 verification: OK" -ForegroundColor Green
