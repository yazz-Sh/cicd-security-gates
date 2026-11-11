# Demo cheat sheet: facturation-api DevSecOps

> Open this file **on GitHub** before the demo: it is not in the folder while you are on the
> `demo-live` branch. In PowerShell always type **`curl.exe`** (plain `curl` is a different command).

## 1. The project in 5 sentences

1. facturation-api is a small Python API with real vulnerabilities (secrets, SQL injection, command injection, pickle, MD5, old dependencies).
2. One Jenkins pipeline (the `Jenkinsfile`) runs 7 kinds of security checks: secrets, SAST, SCA, image scan, DAST, IaC and SBOM.
3. A quality gate (`security/gate.py` + `security/policy.yml`) decides PASS or BLOCK, and BLOCK stops deployment to production.
4. The same pipeline runs on two versions of the code: `vulnerable` is blocked, `main` (fixed) passes and is deployed.
5. Developers get the same checks before pushing (IDE, pre-commit, `scan-local.ps1`), and GitHub Actions runs the pipeline on every push.

## 2. Before the demo (5 min)

```powershell
cd C:\Users\yasmi\projects\devsecops-pipeline ; git checkout main ; git status   # clean, on main
cd infra ; docker compose up -d ; cd ..                                          # Docker Desktop must be running
curl.exe -s http://localhost:8090/health ; curl.exe -s http://localhost:8081/health   # {"status":"ok"} twice
```
- Open these tabs: Jenkins http://localhost:8080 · SonarQube http://localhost:9000 · Mailpit http://localhost:8025 · https://github.com/yazz-Sh/shift-left-cicd-security/actions
- In Jenkins, check: job 1 green, job 2 red, job 3 green.

## 3. The demo (8 steps)

| # | Do | You see | Say (FR) |
|---|----|---------|----------|
| 1 | Jenkins → `1-as-is-pipeline` (10 s), then `curl.exe -s -G "http://localhost:8090/admin/ping" --data-urlencode "host=127.0.0.1;id"` | green job; `uid=0(root)` | « Avant : le pipeline est vert et déploie une application qui exécute n'importe quelle commande. » |
| 2 | Open the `Jenkinsfile` | stages `secrets_scan`, `sast`, `scan_dependencies`, `docker_scan`, `dast`, `security_gate` | « Un seul pipeline, appliqué aux deux versions du code. » |
| 3 | Jenkins → `2-devsecops-vulnerable` → stage view | red stages, `security_gate` red, `deploy_production` skipped | « Sur le code vulnérable, le gate bloque : rien n'arrive en production. » |
| 4 | Build → **Rapports sécurité** → Quality gate; then Mailpit | BLOCK, findings per tool (4 secrets, 5 SAST, 14 deps, 114 image, 1 ZAP High); e-mail `[BLOQUE]` | « Chaque outil donne un rapport, le gate les regroupe, et l'équipe est alertée par e-mail. » |
| 5 | Jenkins → `3-devsecops-main`; then the attack from step 1 on port **8081** | green, deployed; HTTP 404 (endpoint removed). SQL attack on 8081 → `[]` | « Même pipeline sur le code corrigé : tout passe et l'application est déployée. » |
| 6 | SonarQube: `facturation-api-2-…` vs `facturation-api-3-…` | rating E / ERROR vs rating A / OK, 98 % coverage | « SonarQube centralise les résultats et garde l'historique. » |
| 7 | Open `security/exemptions.yml` | 4 exemptions, each with approver, ticket and expiry date | « Un faux positif se gère par une dérogation tracée qui expire, jamais en désactivant l'outil. » |
| 8 | GitHub → Actions tab, then Security → Code scanning | `main` green, `vulnerable` red at `security_gate` | « Le même pipeline tourne sur GitHub Actions à chaque push. » |

## 4. Live fix (local only, about 3 min)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo-live-fix.ps1 -Start     # branch demo-live, prints the 2 attacks
$key = "alice-demo-key"                                                       # alice's demo API key (public test data)
curl.exe -s -G "http://localhost:8090/invoices/search" --data-urlencode "customer=x' OR 1=1 --" -H "X-API-Key: $key"
#   -> 3 invoices, including bob's "Poulina Group" (alice should only see her own 2)
powershell -ExecutionPolicy Bypass -File scripts\scan-local.ps1 -Only semgrep  # BLOCK: facturation-sql-fstring main.py:53
powershell -ExecutionPolicy Bypass -File scripts\scan-local.ps1 -Only bandit   # BLOCK: B602 main.py:79 (+ B324 MD5)
```
Edit `app\facturation\main.py`. **Line 53–54**, replace the two lines with:
```python
    rows = conn.execute(
        "SELECT * FROM invoices WHERE owner_id = ? AND customer LIKE ?",
        (user["id"], f"%{customer}%"),
    ).fetchall()
```
**Line 79** (`subprocess.run(f"ping ...", shell=True ...)`), replace with:
```python
    if not host.replace(".", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Hote invalide")
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
```
```powershell
powershell -ExecutionPolicy Bypass -File scripts\scan-local.ps1 -Only semgrep  # sql-fstring gone; BLOCK only for pickle (line 75)
powershell -ExecutionPolicy Bypass -File scripts\scan-local.ps1 -Only bandit   # B602 gone; BLOCK only for B324 MD5 (line 94)
docker build -t facturation-live app                                           # about 35 s
docker run -d --name facturation-live -p 8095:8000 facturation-live
curl.exe -s -G "http://localhost:8095/invoices/search" --data-urlencode "customer=x' OR 1=1 --" -H "X-API-Key: $key"   # []
curl.exe -s -G "http://localhost:8095/admin/ping" --data-urlencode "host=127.0.0.1;id"   # {"detail":"Hote invalide"} (HTTP 400)
powershell -ExecutionPolicy Bypass -File $env:TEMP\demo-live-fix.ps1 -Reset   # back to main, everything cleaned
```
Say: « Le scanner a trouvé la faille avant le commit ; je corrige avec une requête paramétrée et une validation d'entrée, puis je rescanne : ces deux failles ont disparu, et le gate bloque encore pour pickle et MD5. Il ne laisse rien passer tant que tout n'est pas corrigé. »
Do **not** test a valid host on 8095: it returns HTTP 500 because `ping` is not installed in the image.

## 5. If something breaks

| Problem | Fix |
|---------|-----|
| `docker` errors / "cannot connect" | Start Docker Desktop, wait for "Engine running", then `cd infra ; docker compose up -d` |
| Port 8090 or 8081 does not answer | `docker start facturation-prod-asis facturation-prod` |
| SonarQube shows "starting" | Wait 1–2 min after Docker starts; refresh |
| Jenkins build red with Trivy `failed to download vulnerability DB` | Network problem, not the code: click **Build Now** again |
| `-Start` says uncommitted changes, or you are stuck on `demo-live` | `powershell -ExecutionPolicy Bypass -File $env:TEMP\demo-live-fix.ps1 -Reset` (or `git checkout -f main`) |

## 6. Likely questions

- **Shift-left?** « Détecter les failles le plus tôt possible : dans l'IDE et au commit, où elles coûtent le moins cher à corriger. La CI rejoue tout, car les hooks locaux peuvent être contournés. »
- **SAST vs DAST?** « Le SAST lit le code sans l'exécuter (Semgrep, Bandit) ; le DAST attaque l'application qui tourne en staging (ZAP). Ils trouvent des failles différentes, par exemple l'injection de commande confirmée par ZAP. »
- **SCA?** « L'analyse des dépendances : Trivy compare nos bibliothèques aux bases de CVE connues et indique la version corrigée. »
- **Why block CVSS ≥ 7 only if a fix exists?** « On bloque ce que l'équipe peut corriger tout de suite ; sans correctif, bloquer arrêterait toutes les livraisons sans gain. Ces CVE restent visibles en avertissement et sont suivies. »
- **Why does every secret block?** « Un secret commité est compromis quelle que soit sa sévérité : il faut le révoquer, pas seulement le supprimer, car il reste dans l'historique Git. »
- **Exemptions?** « Une dérogation exige outil, règle, emplacement, justification, approbateur et date d'expiration ; le gate refuse une dérogation incomplète, et à l'expiration le résultat redevient bloquant. »
- **Why do scans continue after a failure?** « Grâce à `catchError` : le stage passe en rouge mais les scans suivants tournent, donc le développeur a la liste complète en un seul build ; le `security_gate` final bloque la production. »
- **What did the tools miss?** « Le BOLA (lire la facture d'un autre utilisateur) et le XSS : les outils ne comprennent pas la logique métier. Nous les avons corrigés par revue de code et des tests ; le pipeline ne remplace pas la revue ni le pentest. »
