# Board1 hardware verification (ProMicro nRF52840 clone + SEGGER J-Link + COM11).
# Compiles CC310Smoke, SdCryptoSmoke, and CryptoSelfTest; flashes over J-Link;
# captures serial until RESULT: OK.
#
# board1 is a clone ProMicro with MBR-only layout: application links at 0x1000
# (Bootloader / DFU -> "no SoftDevice / MBR only"). Do NOT use the default
# 0x26000 S140 layout here — J-Link loadfile will place the hex at the wrong
# address and the board will stop enumerating USB serial.
param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent),
    [string]$CoreRoot = (Join-Path (Split-Path $RepoRoot -Parent) 'ArduinoNRF'),
    [string]$Fqbn = 'arduinonrf:nrf52:promicro_nrf52840:uploadmode=jlink,bootloader=autonosd,usbcdc=enabled',
    [string]$ComPort = $(if ($env:NIUS_BOARD1_COM) { $env:NIUS_BOARD1_COM } else { 'COM11' }),
    [string]$BuildRoot = (Join-Path $PSScriptRoot '_verify_board1')
)

$ErrorActionPreference = 'Stop'
$cliCfg = Join-Path $PSScriptRoot 'arduino-cli.yaml'
if (-not (Test-Path $cliCfg)) {
    $cliCfg = $null
}

function Invoke-ArduinoCli {
    param([string[]]$CliArgs)
    $base = @('compile')
    if ($cliCfg) { $base = @('--config-file', $cliCfg) + $base }
    & arduino-cli @base @CliArgs
    if ($LASTEXITCODE -ne 0) { throw "arduino-cli failed: $($CliArgs -join ' ')" }
}

function Invoke-Upload {
    param([string]$BuildDir)
    $uploadArgs = @('upload', '--fqbn', $Fqbn, '--input-dir', $BuildDir)
    if ($cliCfg) { $uploadArgs = @('--config-file', $cliCfg) + $uploadArgs }
    & arduino-cli @uploadArgs
    if ($LASTEXITCODE -ne 0) { throw "upload failed: $BuildDir" }
}

$lib = $RepoRoot
$smokeSketch = Join-Path $CoreRoot 'hardware\arduinonrf\nrf52\libraries\CC310\examples\CC310Smoke'
$selfTest = Join-Path $RepoRoot 'examples\CryptoSelfTest'
$smokeBuild = Join-Path $BuildRoot 'CC310Smoke'
$selfBuild = Join-Path $BuildRoot 'CryptoSelfTest'
$capturePy = Join-Path $PSScriptRoot 'capture_serial.py'

Write-Host "== verify_board1 ==" -ForegroundColor Cyan
Write-Host "repo=$RepoRoot core=$CoreRoot com=$ComPort"
Write-Host "fqbn=$Fqbn" -ForegroundColor DarkGray
Write-Host "(set `$env:NIUS_BOARD1_COM if the data CDC is not COM11)" -ForegroundColor DarkGray

New-Item -ItemType Directory -Force -Path $smokeBuild, $selfBuild | Out-Null

Write-Host "`n-- compile CC310Smoke --" -ForegroundColor Yellow
Invoke-ArduinoCli @('--fqbn', $Fqbn, '--library', $lib, '--build-path', $smokeBuild, $smokeSketch)

Write-Host "`n-- upload + capture CC310Smoke --" -ForegroundColor Yellow
Invoke-Upload $smokeBuild
$env:NIUS_BOARD1_COM = $ComPort
python $capturePy
if ($LASTEXITCODE -ne 0) { throw "serial capture failed (CC310Smoke); set NIUS_BOARD1_COM if port changed" }

Write-Host "`n-- compile SdCryptoSmoke --" -ForegroundColor Yellow
$sdBuild = Join-Path $BuildRoot 'SdCryptoSmoke'
New-Item -ItemType Directory -Force -Path $sdBuild | Out-Null
$sdSketch = Join-Path $RepoRoot 'examples\SdCryptoSmoke'
Invoke-ArduinoCli @('--fqbn', $Fqbn, '--library', $lib, '--build-path', $sdBuild, $sdSketch)

Write-Host "`n-- upload + capture SdCryptoSmoke --" -ForegroundColor Yellow
Invoke-Upload $sdBuild
python $capturePy
if ($LASTEXITCODE -ne 0) { throw "serial capture failed (SdCryptoSmoke)" }

Write-Host "`n-- compile CryptoSelfTest --" -ForegroundColor Yellow
Invoke-ArduinoCli @('--fqbn', $Fqbn, '--library', $lib, '--build-path', $selfBuild, $selfTest)

Write-Host "`n-- upload + capture CryptoSelfTest --" -ForegroundColor Yellow
Invoke-Upload $selfBuild
python $capturePy
if ($LASTEXITCODE -ne 0) { throw "serial capture failed (CryptoSelfTest)" }

Write-Host "`nboard1 verification: OK" -ForegroundColor Green
