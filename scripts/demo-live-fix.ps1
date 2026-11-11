# =============================================================================
# Demo "correction en direct" - 100 % local : ne touche ni Jenkins ni GitHub.
#
#   powershell -ExecutionPolicy Bypass -File scripts\demo-live-fix.ps1 -Start
#       -> cree la branche locale demo-live a partir de vulnerable et s'y place
#   powershell -ExecutionPolicy Bypass -File $env:TEMP\demo-live-fix.ps1 -Reset
#       -> supprime le conteneur facturation-live, revient sur main,
#          supprime demo-live (les modifications faites pendant la demo sont jetees)
#
# Ce script n'existe pas sur la branche vulnerable : -Start en garde une copie dans
# %TEMP% ; lancer -Reset depuis le dossier du depot.
# Ne jamais pousser demo-live (aucun "git push" dans ce script).
# =============================================================================
param([switch]$Start, [switch]$Reset)

# Dossier du depot : celui du script s'il y est, sinon le dossier courant (copie dans %TEMP%)
$root = (Resolve-Path "$PSScriptRoot\..").Path
if (-not (Test-Path "$root\.git")) { $root = (git rev-parse --show-toplevel 2>$null) }
if (-not $root) { Write-Host "Lancer depuis le dossier du depot." -ForegroundColor Red; exit 1 }
Set-Location $root

function Remove-DemoBranch {
    git show-ref --verify --quiet refs/heads/demo-live
    if ($LASTEXITCODE -eq 0) { git branch -D demo-live | Out-Null }
}

if ($Start) {
    if (git status --porcelain --untracked-files=no) {
        Write-Host "Modifications non commitees : committer ou annuler avant -Start." -ForegroundColor Red
        exit 1
    }
    git checkout -q main
    Copy-Item $PSCommandPath "$env:TEMP\demo-live-fix.ps1" -Force
    Remove-DemoBranch
    git checkout -q -b demo-live vulnerable
    Write-Host "`nBranche demo-live creee depuis vulnerable (locale uniquement).`n" -ForegroundColor Green
    Write-Host "Attaque 1 - injection SQL (alice voit aussi la facture de bob) :" -ForegroundColor Yellow
    Write-Host '  $key = "alice-demo-key"'
    Write-Host '  curl.exe -s -G "http://localhost:8090/invoices/search" --data-urlencode "customer=x'' OR 1=1 --" -H "X-API-Key: $key"'
    Write-Host "Attaque 2 - injection de commande (execute 'id' sur le serveur) :" -ForegroundColor Yellow
    Write-Host '  curl.exe -s -G "http://localhost:8090/admin/ping" --data-urlencode "host=127.0.0.1;id"'
    Write-Host "`nA corriger : app\facturation\main.py lignes 53 (SQL) et 79 (shell=True)."
    Write-Host "Pour revenir a main a la fin :" -ForegroundColor Yellow
    Write-Host '  powershell -ExecutionPolicy Bypass -File $env:TEMP\demo-live-fix.ps1 -Reset'
    exit 0
}

if ($Reset) {
    docker rm -f facturation-live 2>$null | Out-Null
    git checkout -q -f main          # -f : jette les modifications faites pendant la demo
    Remove-DemoBranch
    Write-Host "Reset termine : branche main, demo-live supprimee, conteneur facturation-live supprime." -ForegroundColor Green
    exit 0
}

Write-Host "Usage : demo-live-fix.ps1 -Start | -Reset"
exit 1
