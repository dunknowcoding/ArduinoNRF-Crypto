# Switch this working copy to OnChip-only (no CC310 link).
$Root = Split-Path $PSScriptRoot -Parent
Copy-Item (Join-Path $Root 'library.properties.onchip') (Join-Path $Root 'library.properties') -Force
Copy-Item (Join-Path $Root 'configs\BuildProfile.onchip.h') (Join-Path $Root 'src\internal\BuildProfile.h') -Force
Write-Host "OnChip build profile active (library.properties + BuildProfile.h)" -ForegroundColor Green
