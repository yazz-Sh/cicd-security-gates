# =============================================================================
# Demarrage reproductible de la plateforme DevSecOps (Windows / Docker Desktop)
#   1. genere les secrets locaux dans infra/.env (jamais versionne)
#   2. demarre SonarQube + Mailpit, configure SonarQube par API
#      (mot de passe admin, jeton d'analyse, quality gate "DevSecOps", webhook Jenkins)
#   3. demarre Jenkins, entierement configure par JCasC (jobs, credentials, SonarQube, SMTP)
# Usage :  powershell -ExecutionPolicy Bypass -File infra\bootstrap.ps1
# =============================================================================
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$envFile = Join-Path $PSScriptRoot ".env"

function New-Secret([int]$n = 20) {
    $chars = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789".ToCharArray()
    $bytes = New-Object byte[] $n
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}
function Read-Env {
    $h = @{}
    if (Test-Path $envFile) { Get-Content $envFile | Where-Object { $_ -match "=" } | ForEach-Object { $k, $v = $_ -split "=", 2; $h[$k] = $v } }
    $h
}
function Save-Env($h) { ($h.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) | Set-Content -Encoding ascii $envFile }

$cfg = Read-Env
if (-not $cfg.JENKINS_ADMIN_PASSWORD) { $cfg.JENKINS_ADMIN_PASSWORD = New-Secret }
if (-not $cfg.SONAR_ADMIN_PASSWORD) { $cfg.SONAR_ADMIN_PASSWORD = (New-Secret 16) + "#9a" }
if (-not $cfg.SONAR_TOKEN) { $cfg.SONAR_TOKEN = "pending" }
Save-Env $cfg

Write-Host "==> Demarrage de SonarQube et Mailpit"
docker compose up -d sonarqube mailpit | Out-Null

$sonar = "http://localhost:9000"
Write-Host -NoNewline "==> Attente de SonarQube "
for ($i = 0; $i -lt 90; $i++) {
    try { if ((Invoke-RestMethod "$sonar/api/system/status").status -eq "UP") { break } } catch {}
    Write-Host -NoNewline "."; Start-Sleep 5
}
Write-Host " UP"

function Auth($user, $pass) { @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${user}:${pass}")) } }
$admin = Auth "admin" $cfg.SONAR_ADMIN_PASSWORD
try { Invoke-RestMethod "$sonar/api/authentication/validate" -Headers $admin | Out-Null; $ok = (Invoke-RestMethod "$sonar/api/authentication/validate" -Headers $admin).valid } catch { $ok = $false }
if (-not $ok) {
    Write-Host "==> Changement du mot de passe admin SonarQube par defaut"
    Invoke-RestMethod -Method Post "$sonar/api/users/change_password" -Headers (Auth "admin" "admin") `
        -Body @{ login = "admin"; previousPassword = "admin"; password = $cfg.SONAR_ADMIN_PASSWORD } | Out-Null
}

if ($cfg.SONAR_TOKEN -eq "pending") {
    Write-Host "==> Creation du jeton d'analyse pour Jenkins"
    $t = Invoke-RestMethod -Method Post "$sonar/api/user_tokens/generate" -Headers $admin -Body @{ name = "jenkins-" + (Get-Date -Format "yyyyMMddHHmmss") }
    $cfg.SONAR_TOKEN = $t.token
    Save-Env $cfg
}

Write-Host "==> Quality gate 'DevSecOps'"
$gates = Invoke-RestMethod "$sonar/api/qualitygates/list" -Headers $admin
if (-not ($gates.qualitygates | Where-Object name -eq "DevSecOps")) {
    Invoke-RestMethod -Method Post "$sonar/api/qualitygates/create" -Headers $admin -Body @{ name = "DevSecOps" } | Out-Null
    # Securite : note A exigee (aucune vulnerabilite) sur l'ensemble du code
    Invoke-RestMethod -Method Post "$sonar/api/qualitygates/create_condition" -Headers $admin -Body @{ gateName = "DevSecOps"; metric = "security_rating"; op = "GT"; error = "1" } | Out-Null
    # Fiabilite : pas pire que C (bugs majeurs)
    Invoke-RestMethod -Method Post "$sonar/api/qualitygates/create_condition" -Headers $admin -Body @{ gateName = "DevSecOps"; metric = "reliability_rating"; op = "GT"; error = "3" } | Out-Null
    # Couverture de tests minimale
    Invoke-RestMethod -Method Post "$sonar/api/qualitygates/create_condition" -Headers $admin -Body @{ gateName = "DevSecOps"; metric = "coverage"; op = "LT"; error = "80" } | Out-Null
}
Invoke-RestMethod -Method Post "$sonar/api/qualitygates/set_as_default" -Headers $admin -Body @{ name = "DevSecOps" } | Out-Null

$hooks = Invoke-RestMethod "$sonar/api/webhooks/list" -Headers $admin
if (-not ($hooks.webhooks | Where-Object name -eq "jenkins")) {
    Write-Host "==> Webhook SonarQube -> Jenkins (resultat du quality gate)"
    Invoke-RestMethod -Method Post "$sonar/api/webhooks/create" -Headers $admin -Body @{ name = "jenkins"; url = "http://jenkins:8080/sonarqube-webhook/" } | Out-Null
}

Write-Host "==> Demarrage de Jenkins (configuration as code)"
docker compose up -d --build jenkins | Out-Null

Write-Host ""
Write-Host "Plateforme prete :"
Write-Host "  Jenkins   http://localhost:8080   admin / $($cfg.JENKINS_ADMIN_PASSWORD)"
Write-Host "  SonarQube http://localhost:9000   admin / $($cfg.SONAR_ADMIN_PASSWORD)"
Write-Host "  Mailpit   http://localhost:8025   (emails de notification)"
Write-Host "Identifiants stockes dans infra\.env (exclu de Git)."
