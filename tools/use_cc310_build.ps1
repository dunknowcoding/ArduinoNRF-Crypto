# Restore default CC310 + OnChip auto-detect profile.
$Root = Split-Path $PSScriptRoot -Parent
Copy-Item (Join-Path $Root 'configs\BuildProfile.default.h') (Join-Path $Root 'src\internal\BuildProfile.h') -Force
Set-Location $Root
git checkout -- library.properties 2>$null
if (-not (Test-Path (Join-Path $Root 'library.properties'))) {
  throw "library.properties missing — restore from git manually"
}
Write-Host "CC310 build profile restored" -ForegroundColor Green
