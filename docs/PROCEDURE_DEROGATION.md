# Procédure de dérogation (exemption process)

Un contrôle bloquant peut se tromper (faux positif) ou signaler un risque déjà maîtrisé
(secret révoqué, CVE non exploitable dans notre contexte). Cette procédure permet de
débloquer une livraison **sans désactiver le contrôle** et **en gardant la trace** de la décision.

## Principes

1. **Jamais de contournement silencieux** : interdit de modifier `policy.yml`, de supprimer un
   stage ou d'ajouter `|| true` pour faire passer un build. Seul le registre
   `security/exemptions.yml` permet une dérogation.
2. **Une dérogation vise UN résultat précis** : outil + règle/CVE + emplacement. Jamais une
   règle entière ou un outil entier.
3. **Toute dérogation expire.** À expiration, le résultat redevient automatiquement bloquant
   (vérifié par `security/gate.py`).
4. **Quatre yeux** : le développeur demande, une autre personne approuve (lead dev pour un faux
   positif, RSSI pour un risque accepté). La modification passe par une merge request revue
   (CODEOWNERS sur `security/`).

## Étapes

| # | Qui | Action |
|---|-----|--------|
| 1 | Développeur | Analyse le résultat dans le rapport (`Rapports sécurité` du build). Corrige si possible : **la correction reste la voie normale**. |
| 2 | Développeur | Si correction impossible ou faux positif : ouvre un ticket `SEC-xxx` avec preuves (extrait de code, raison, risque résiduel). |
| 3 | Approbateur | Qualifie : faux positif / risque accepté / refus. Fixe la durée (90 jours max pour un faux positif, 180 jours max pour un risque accepté). |
| 4 | Développeur | Ajoute l'entrée dans `security/exemptions.yml` dans une merge request liée au ticket. |
| 5 | Pipeline | Le gate classe le résultat en `EXEMPTED` (visible en bleu dans le rapport, compté dans l'historique). |
| 6 | Revue mensuelle | Les dérogations proches de l'expiration sont revues : prolongation justifiée ou correction. |

## Format d'une entrée

```yaml
- id: EXC-2026-003            # identifiant unique
  tool: gitleaks              # gitleaks | semgrep | bandit | trivy-fs | trivy-image | zap | checkov | sonarqube
  rule: generic-api-key       # règle ou identifiant CVE exact
  location: "app/tests/test_api.py"   # sous-chaîne de l'emplacement (fichier, commit, paquet)
  justification: >-          # pourquoi ce n'est pas (ou plus) un risque
    FAUX POSITIF. Mot de passe fictif d'un test unitaire.
  approved_by: "Lead dev - Y. Shili"  # qui a validé
  ticket: SEC-102             # traçabilité
  created: 2026-11-09
  expires: 2027-02-09         # obligatoire
```

Champs obligatoires : `id`, `tool`, `rule`, `justification`, `approved_by`, `expires`.
Une entrée incomplète est **refusée** par le gate (le résultat reste bloquant), et l'anomalie
apparaît dans le rapport.

## Exemples réels de ce projet

| ID | Cas | Décision |
|----|-----|----------|
| EXC-2026-001/002 | Clé AWS commitée en v1.0, présente dans l'historique Git | Risque accepté **après révocation** de la clé ; réécriture de l'historique planifiée |
| EXC-2026-003 | Mot de passe fictif dans un test unitaire | Faux positif |
| EXC-2026-004 | `projectKey` SonarQube détecté comme clé d'API | Faux positif |