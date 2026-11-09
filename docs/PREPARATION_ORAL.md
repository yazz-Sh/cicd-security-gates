# Préparation à l'oral — questions probables et réponses

> Objectif : pouvoir **expliquer chaque choix avec tes propres mots**. Lis une réponse,
> ferme le fichier, et réexplique-la à voix haute. Si tu bloques, relis le fichier source indiqué.

---

## 1. Concepts DevSecOps

**Q : Qu'est-ce que le « shift-left » ?**
Déplacer les contrôles de sécurité **le plus tôt possible** dans le cycle : dans l'IDE
(SonarLint, Semgrep), au commit (pre-commit), puis en CI. Plus une faille est trouvée tôt,
moins elle coûte : quelques secondes à corriger dans l'IDE, contre un incident en production.
→ Dans le projet : extensions VS Code + `.pre-commit-config.yaml` + 12 stages Jenkins.

**Q : Et le « shift-right » ?**
Continuer à contrôler ce qui tourne : DAST en staging, surveillance des nouvelles CVE sur le
SBOM, détection runtime. Le shift-left ne suffit pas : une CVE peut être publiée **après** le
déploiement. → Le SBOM (`sbom-image.cdx.json`) permet de savoir en minutes si on est concerné.

**Q : Quelle différence entre SAST, SCA, DAST ?**
| | Analyse | Quand | Outil ici | Exemple trouvé |
|---|---|---|---|---|
| SAST | le **code source**, sans l'exécuter | dès le commit | Semgrep, Bandit, SonarQube | injection SQL ligne 53 |
| SCA | les **dépendances** tierces | à chaque build | Trivy fs | PyJWT 2.3.0 (CVE-2022-29217) |
| DAST | l'**application qui tourne**, de l'extérieur | en staging | OWASP ZAP | en-têtes de sécurité absents |

**Q : Pourquoi plusieurs outils SAST ?**
Ils sont **complémentaires**. SonarQube Community ne fait pas d'analyse de flux (taint) sur Python :
il n'a pas vu l'injection SQL. Semgrep l'a trouvée grâce à une **règle personnalisée** que j'ai
écrite (`security/semgrep/facturation-rules.yml`). Bandit est spécialisé Python (MD5, shell=True).

---

## 2. Le pipeline

**Q : Décris ton pipeline.**
12 stages : `checkout → secrets_scan → sast (semgrep ∥ bandit) → unit_tests → scan_dependencies
→ iac_scan → sonarqube → build → docker_scan → deploy_staging → dast → security_gate →
deploy_production`. Chaque stage produit un rapport JSON (pour la machine) et HTML/SARIF (pour l'humain).

**Q : Pourquoi les scans continuent après un échec au lieu de s'arrêter tout de suite ?**
Choix délibéré : `catchError` marque le stage en rouge mais laisse les suivants s'exécuter.
Le développeur reçoit **en une seule exécution** la liste complète des problèmes, au lieu de
corriger un problème, relancer, découvrir le suivant… Le blocage effectif est fait par le stage
`security_gate`, qui **interdit le déploiement en production**.

**Q : Le code vulnérable est déployé en staging — n'est-ce pas un risque ?**
Le staging est un conteneur **isolé** sur un réseau Docker interne, sans port exposé ni donnée
réelle, détruit en fin de build. Le DAST a besoin d'une application qui tourne. Ce qui compte :
rien de non conforme n'atteint la **production**.

**Q : Comment le pipeline se déclenche-t-il ?**
Automatiquement : Jenkins scrute le dépôt chaque minute (`pollSCM`) et lance le build à chaque
nouveau commit, sans intervention. En local, `scripts/scan-local.ps1` permet de lancer les mêmes
contrôles **avant** de pousser.

**Q : Pourquoi Jenkins ?**
Demandé par le sujet (Jenkinsfile), standard en entreprise, et j'ai pu le configurer
**entièrement en code** (JCasC : `infra/jenkins/casc.yaml`) → plateforme reproductible en une
commande (`infra/bootstrap.ps1`).

---

## 3. Quality gates et seuils

**Q : Comment as-tu choisi tes seuils de blocage ?**
→ `security/policy.yml`. Principe : **bloquer ce qui est grave ET actionnable**, signaler le reste.
- **Secrets : tout bloque.** Un secret commité est compromis, peu importe sa « sévérité ».
- **SAST : HIGH/CRITICAL bloquent.** Bandit exige en plus une confiance ≥ MEDIUM, pour limiter les faux positifs.
- **SCA / image : CRITICAL et HIGH bloquent seulement si un correctif existe.** Bloquer sur une
  CVE sans correctif paralyse l'équipe sans rien améliorer ; elle reste visible en avertissement.
- **DAST : alertes de risque High.**
- **IaC (Checkov) : non bloquant** → mode observation, comme recommandé (2–4 semaines avant de bloquer).
- **Absence de rapport = échec** : un scanner qui plante ne doit pas laisser passer le build.

**Q : Lien avec le CVSS ?**
Trivy utilise la sévérité fournisseur, dérivée du CVSS v3 : CRITICAL ≥ 9.0, HIGH 7.0–8.9,
MEDIUM 4.0–6.9. Donc concrètement : **on bloque à partir de CVSS 7.0 quand un correctif existe**.

**Q : Bloquant vs non bloquant, pourquoi ?**
Trop bloquer = les développeurs contournent l'outil (« fatigue d'alertes »). Le non-bloquant
garde la visibilité (rapports + historique) sans freiner les livraisons.

---

## 4. Dérogations

**Q : Que se passe-t-il en cas de faux positif bloquant ?**
→ `docs/PROCEDURE_DEROGATION.md`. On n'enlève **jamais** le contrôle. On ajoute une entrée dans
`security/exemptions.yml` : outil + règle + emplacement précis + justification + approbateur +
ticket + **date d'expiration**. Le gate refuse une dérogation incomplète, et une dérogation
expirée redevient bloquante automatiquement.

**Q : Un exemple réel ?**
Gitleaks bloquait `main` alors que le code est corrigé : les clés AWS restent dans
**l'historique Git** (commit e006ce6). Supprimer le fichier ne suffit pas ! Le bon traitement :
1) **révoquer** la clé, 2) dérogation tracée EXC-2026-001, 3) réécriture de l'historique planifiée.
Deux autres cas étaient de vrais **faux positifs** (mot de passe de test, clé de projet SonarQube).

**Q : Comment SonarQube connaît-il les dérogations ?**
Le gate filtre le SARIF de Gitleaks (`filter-sarif`) avant l'import dans SonarQube : le registre
des dérogations est la **source unique de vérité** pour le gate ET pour SonarQube.

---

## 5. Secrets du pipeline lui-même

**Q : Comment protèges-tu les secrets utilisés par le pipeline ?**
- Le jeton SonarQube est un **credential Jenkins** (type secret text), injecté via
  `withSonarQubeEnv` et **masqué** dans les logs.
- Les mots de passe sont générés aléatoirement par `bootstrap.ps1` dans `infra/.env`, **exclu de Git**.
- Le pipeline « as-is » avait au contraire `DB_PASSWORD` en clair dans le Jenkinsfile (faiblesse W5).
- Amélioration : HashiCorp Vault + plugin Jenkins Vault, ou OIDC pour des identifiants éphémères.

**Q : Une faiblesse que tu assumes dans ton labo ?**
Jenkins accède au socket Docker de l'hôte = **équivalent root sur la machine**. Acceptable en
labo local ; en production : agents de build éphémères, Docker rootless ou Kaniko. Savoir citer
ses propres limites montre la compréhension.

---

## 6. Résultats

**Q : Qu'est-ce que ton pipeline a trouvé ?** (sur le code vulnérable)
4 secrets, 3 failles Semgrep + 2 Bandit (injection SQL, désérialisation pickle, injection de
commande, MD5), 14 vulnérabilités de dépendances corrigeables (PyJWT, urllib3), 114 CVE
corrigeables dans l'image (Debian 12.2 obsolète), 1 alerte ZAP High (**injection de commande OS**,
confirmée en attaquant l'application qui tourne), quality gate SonarQube en échec (security
rating E). → **139 résultats bloquants, déploiement en production bloqué.**
Sur le code corrigé : 0 bloquant, note A, couverture 98 %, déployé.

**Q : Comment as-tu corrigé l'injection SQL ?**
Requête **paramétrée** : `execute("... WHERE customer LIKE ?", (f"%{customer}%",))`. La saisie
n'est plus jamais interprétée comme du SQL. Un **test de non-régression**
(`test_security.py`) envoie `' OR '1'='1` et vérifie qu'aucune facture d'un autre utilisateur ne fuit.

**Q : Qu'est-ce que le BOLA ?**
Broken Object Level Authorization (OWASP API1) : Alice lisait la facture de Bob en changeant
l'ID dans l'URL. Correctif : `WHERE id = ? AND owner_id = ?`. Réponse 404 (pas 403) pour ne
pas révéler que la facture existe.
*Remarque honnête : aucun scanner automatique ne l'a détecté — c'est un défaut de logique
métier. D'où les tests d'autorisation écrits à la main.*

**Q : Pourquoi l'image de base Docker posait problème ?**
`python:3.12.0-slim` (Debian 12.2, 2023) : 114 CVE déjà corrigées en amont. Correctif : image
récente **épinglée par digest** (sha256 : immuable, contrairement à un tag), multi-étapes,
utilisateur non-root 10001, `apt-get upgrade` au build. Cas réel rencontré : même l'image du
jour avait 2 CVE zlib déjà corrigées dans Debian → l'upgrade au build les a éliminées.

**Q : Qu'est-ce qu'un SBOM, à quoi sert le tien ?**
Software Bill of Materials : inventaire de tous les composants (CycloneDX, généré par Syft).
Quand une nouvelle CVE sort, on cherche le paquet dans le SBOM au lieu d'auditer le code.
Exigé par le Cyber Resilience Act européen.

---

## 7. Questions pièges

- **« Ton pipeline est vert, donc l'appli est sûre ? »** → Non. Il prouve l'absence des failles
  *que les outils savent détecter*. Le BOLA en est la preuve : il fallait un test manuel. Le
  pipeline complète la revue de code et le pentest, il ne les remplace pas.
- **« Pourquoi épingler les versions des outils ? »** → Un tag est modifiable. En mars 2026, des tags
  de l'action GitHub Trivy ont été redirigés vers un voleur de secrets ; seuls ceux qui épinglaient
  par SHA étaient protégés. Ici : versions fixes + vérification du checksum de Trivy dans le Dockerfile Jenkins.
- **« Combien de temps ajoute la sécurité ? »** → Donne les durées mesurées des builds (section
  Résultats du rapport). Les hooks pre-commit sont limités aux contrôles rapides (< 10 s).
- **« Que ferais-tu ensuite ? »** → Signature d'image (cosign) + vérification à l'admission
  Kubernetes (Kyverno), Vault, Dependency-Track pour suivre le SBOM, gates IaC bloquants après
  la phase d'observation, notifications Slack/Teams.
