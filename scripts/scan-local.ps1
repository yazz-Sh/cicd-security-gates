# =============================================================================
# Execution CIBLEE des controles de securite en local, AVANT le push.
# Utilise exactement les memes outils et versions que la CI (image Jenkins),
# et la meme politique (security/policy.yml) : pas de surprise en CI.
#
#   powershell -File scripts\scan-local.ps1                 # tous les controles rapides
#   powershell -File scripts\scan-local.ps1 -Only gitleaks  # un seul controle
# =============================================================================
param([ValidateSet("all", "gitleaks", "semgrep", "bandit", "trivy-fs")] [string]$Only = "all")
$repo = (Resolve-Path "$PSScriptRoot\..").Path
$steps = @{
    "gitleaks" = "gitleaks git --redact --no-banner --report-format json --report-path reports/gitleaks.json . ; true"
    "semgrep"  = "semgrep scan --metrics=off --quiet --config p/python --config security/semgrep --json-output=reports/semgrep.json app/facturation ; true"
    "bandit"   = "bandit -q -r app/facturation -f json -o reports/bandit.json ; true"
    "trivy-fs" = "trivy fs --quiet --scanners vuln --format json -o reports/trivy-fs.json app"
}
$tools = if ($Only -eq "all") { "gitleaks", "semgrep", "bandit", "trivy-fs" } else { @($Only) }
$cmd = "git config --global --add safe.directory '*'; mkdir -p reports; "
foreach ($t in $tools) { $cmd += $steps[$t] + "; /opt/sast/bin/python security/gate.py check --tool $t || FAIL=1; " }
$cmd += 'exit ${FAIL:-0}'
docker run --rm -v "${repo}:/src" -w /src -e SEMGREP_SEND_METRICS=off devsecops/jenkins:local bash -c $cmd
if ($LASTEXITCODE -ne 0) { Write-Host "`nBLOQUE : corriger avant de pousser (ou demander une derogation)." -ForegroundColor Red; exit 1 }
Write-Host "`nOK : aucun resultat bloquant." -ForegroundColor Green