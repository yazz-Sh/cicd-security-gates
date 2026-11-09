// =============================================================================
// ETAT "TO-BE" : pipeline DevSecOps "shift-left" de facturation-api
//
//  checkout -> secrets_scan -> sast -> unit_tests -> scan_dependencies -> iac_scan
//           -> sonarqube -> build -> docker_scan -> deploy_staging -> dast
//           -> security_gate -> deploy_production
//
// Principe : chaque stage produit un rapport JSON (machine) + HTML/SARIF (humain).
// Le script security/gate.py applique la politique security/policy.yml :
//   - un stage dont l'outil trouve un resultat BLOQUANT passe en rouge (FAILURE),
//     mais les scans suivants continuent pour donner une vision complete ;
//   - le stage final security_gate interdit le deploiement en production.
// Execution : automatique a chaque commit (scrutation SCM), ou ciblee en local
// (voir docs/EXECUTION_LOCALE.md).
// =============================================================================
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))   // historique conserve
        disableConcurrentBuilds()
    }

    environment {
        IMAGE          = "facturation-api:${env.JOB_BASE_NAME}-${env.BUILD_NUMBER}"
        STAGING        = "staging-${env.JOB_BASE_NAME}"
        GATE           = '/opt/sast/bin/python security/gate.py'
        HISTORY_FILE   = "/var/jenkins_home/security-history/${env.JOB_BASE_NAME}.jsonl"
        TRIVY_CACHE_DIR = '/var/jenkins_home/.cache/trivy'
        SEMGREP_SEND_METRICS = 'off'
    }

    stages {
        stage('checkout') {
            steps {
                checkout scm
                sh 'rm -rf reports && mkdir -p reports'
            }
        }

        // ---------------------------------------------------------------- 1. secrets
        stage('secrets_scan') {
            steps {
                // Tout l'historique Git est analyse : un secret supprime d'un fichier reste dans l'historique.
                sh '''
                    gitleaks git --redact --no-banner --report-format json  --report-path reports/gitleaks.json  . || true
                    gitleaks git --redact --no-banner --report-format sarif --report-path reports/gitleaks.sarif . || true
                '''
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '$GATE check --tool gitleaks'
                }
            }
        }

        // ---------------------------------------------------------------- 2. SAST
        stage('sast') {
            parallel {
                stage('semgrep') {
                    steps {
                        sh '''
                            semgrep scan --metrics=off --quiet \
                                --config p/python --config p/owasp-top-ten --config security/semgrep \
                                --json-output=reports/semgrep.json --sarif-output=reports/semgrep.sarif \
                                app/facturation || true
                        '''
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            sh '$GATE check --tool semgrep'
                        }
                    }
                }
                stage('bandit') {
                    steps {
                        sh '''
                            bandit -q -r app/facturation -f json  -o reports/bandit.json  || true
                            bandit -q -r app/facturation -f sarif -o reports/bandit.sarif || true
                            bandit -q -r app/facturation -f html  -o reports/bandit.html  || true
                        '''
                        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                            sh '$GATE check --tool bandit'
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------- 3. tests
        stage('unit_tests') {
            steps {
                sh '''
                    python3 -m venv .venv && . .venv/bin/activate
                    pip install -q -r app/requirements.txt -r app/requirements-dev.txt
                    cd app && pytest -q --junitxml=../reports/junit.xml \
                        --cov=facturation --cov-report=xml:../reports/coverage.xml --cov-fail-under=80
                '''
            }
        }

        // ---------------------------------------------------------------- 4. SCA + SBOM
        stage('scan_dependencies') {
            steps {
                sh '''
                    trivy fs --quiet --scanners vuln --format json  -o reports/trivy-fs.json  app
                    trivy fs --quiet --scanners vuln --format sarif -o reports/trivy-fs.sarif app
                    syft dir:app -q -o cyclonedx-json=reports/sbom-source.cdx.json
                '''
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '$GATE check --tool trivy-fs'
                }
            }
        }

        // ---------------------------------------------------------------- 5. IaC (non bloquant)
        stage('iac_scan') {
            steps {
                sh '''
                    checkov -d app -d k8s --framework dockerfile kubernetes --quiet --soft-fail \
                        -o json -o cli --output-file-path reports || true
                '''
                sh '$GATE check --tool checkov || true'
            }
        }

        // ---------------------------------------------------------------- 6. SonarQube
        stage('sonarqube') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner -Dsonar.projectKey=facturation-api-${JOB_BASE_NAME} -Dsonar.projectName=facturation-api-${JOB_BASE_NAME}'
                }
                timeout(time: 5, unit: 'MINUTES') {
                    script {
                        def qg = waitForQualityGate abortPipeline: false
                        writeFile file: 'reports/sonarqube-gate.json', text: "{\"status\": \"${qg.status}\"}"
                    }
                }
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '$GATE check --tool sonarqube'
                }
            }
        }

        // ---------------------------------------------------------------- 7. build + SBOM image
        stage('build') {
            steps {
                sh '''
                    docker build -t $IMAGE app
                    syft docker:$IMAGE -q -o cyclonedx-json=reports/sbom-image.cdx.json
                '''
            }
        }

        // ---------------------------------------------------------------- 8. scan d'image
        stage('docker_scan') {
            steps {
                sh '''
                    trivy image --quiet --format json -o reports/trivy-image.json $IMAGE
                    trivy image --quiet --format template --template @/opt/trivy/contrib/html.tpl \
                        -o reports/trivy-image.html $IMAGE || true
                '''
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '$GATE check --tool trivy-image'
                }
            }
        }

        // ---------------------------------------------------------------- 9. staging isole
        stage('deploy_staging') {
            steps {
                sh '''
                    docker rm -f $STAGING || true
                    docker run -d --name $STAGING --network devsecops $IMAGE
                    for i in $(seq 1 30); do
                        curl -fsS http://$STAGING:8000/health && exit 0
                        sleep 2
                    done
                    echo "staging ne repond pas" && exit 1
                '''
            }
        }

        // ---------------------------------------------------------------- 10. DAST
        stage('dast') {
            steps {
                // ZAP scanne l'API a partir de sa definition OpenAPI (scan actif, environnement staging uniquement)
                sh '''
                    docker run --rm --network devsecops --volumes-from jenkins -u zap zaproxy/zap-stable bash -c "\
                        mkdir -p /zap/wrk && cd /zap/wrk && \
                        zap-api-scan.py -t http://$STAGING:8000/openapi.json -f openapi -J zap.json -r zap.html -I ; \
                        cp /zap/wrk/zap.json /zap/wrk/zap.html $WORKSPACE/reports/" || true
                '''
                catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
                    sh '$GATE check --tool zap'
                }
            }
        }

        // ---------------------------------------------------------------- 11. decision
        stage('security_gate') {
            steps {
                sh '$GATE evaluate'
            }
        }

        // ---------------------------------------------------------------- 12. production
        stage('deploy_production') {
            when { expression { currentBuild.currentResult == 'SUCCESS' } }
            steps {
                sh '''
                    docker rm -f facturation-prod || true
                    docker run -d --name facturation-prod --network devsecops -p 8081:8000 \
                        --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges $IMAGE
                '''
            }
        }
    }

    post {
        always {
            junit allowEmptyResults: true, testResults: 'reports/junit.xml'
            recordIssues enabledForFailure: true, tools: [
                sarif(id: 'semgrep',  name: 'Semgrep',  pattern: 'reports/semgrep.sarif'),
                sarif(id: 'bandit',   name: 'Bandit',   pattern: 'reports/bandit.sarif'),
                sarif(id: 'gitleaks', name: 'Gitleaks', pattern: 'reports/gitleaks.sarif'),
                sarif(id: 'trivy',    name: 'Trivy (dependances)', pattern: 'reports/trivy-fs.sarif')
            ]
            publishHTML([reportDir: 'reports', reportFiles: 'security-gate.html,zap.html,trivy-image.html,bandit.html',
                         reportTitles: 'Quality gate,ZAP (DAST),Trivy (image),Bandit (SAST)',
                         reportName: 'Rapports securite', allowMissing: true, alwaysLinkToLastBuild: true, keepAll: true])
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            sh 'docker rm -f $STAGING || true'
        }
        failure {
            script {
                def summary = fileExists('reports/gate-summary.txt') ? readFile('reports/gate-summary.txt') : 'Echec avant le quality gate.'
                mail to: 'equipe-dev@devsecops.local',
                     subject: "[BLOQUE] ${env.JOB_NAME} #${env.BUILD_NUMBER} - vulnerabilites bloquantes",
                     body: "${summary}\n\nRapports : ${env.BUILD_URL}Rapports_20securite/\nBuild : ${env.BUILD_URL}"
            }
        }
        success {
            mail to: 'equipe-dev@devsecops.local',
                 subject: "[OK] ${env.JOB_NAME} #${env.BUILD_NUMBER} - deploye en production",
                 body: "Quality gate PASS. Rapports : ${env.BUILD_URL}Rapports_20securite/"
        }
    }
}