# Image Jenkins "paved road" : tous les scanners de securite preinstalles,
# chacun en VERSION EPINGLEE (jamais "latest" : cf. compromission de tags 2026).
#  - image de base : tag + empreinte (digest), un tag modifiable ne peut plus changer l'image
#  - binaires telecharges : SHA-256 epingle ici et verifie (build en echec si l'archive change)
#  - outils Python : version exacte (pip ==)
# Les memes versions sont utilisees par .github/workflows/devsecops.yml.
FROM jenkins/jenkins:lts-jdk17@sha256:cce1eeb79902722f3cf7a8831c41e95c39f4a42b9a2981959630cc66539b3c2d

USER root
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.75.0
ARG SYFT_VERSION=1.55.0
ARG SONAR_SCANNER_VERSION=8.2.0.6438
ARG GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG SYFT_SHA256=bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d
ARG SONAR_SCANNER_SHA256=83257bf97a475d626b8ba2b214aeeb37334ca84db1b3e3be5105783e4facb053
ARG SEMGREP_VERSION=1.184.0
ARG BANDIT_VERSION=1.9.4
ARG CHECKOV_VERSION=3.4.3
ARG PYYAML_VERSION=6.0.3

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-pip curl ca-certificates unzip git gnupg \
 && rm -rf /var/lib/apt/lists/*

# Docker CLI (le moteur est celui de l'hote, via le socket monte)
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list \
 && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

# Gitleaks (secrets) - SHA-256 verifie
RUN curl -fsSL -o /tmp/gl.tgz https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
 && echo "${GITLEAKS_SHA256}  /tmp/gl.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks && rm /tmp/gl.tgz

# Trivy (SCA + image) - SHA-256 epingle ici (et non relu dans la release : un attaquant
# qui remplace l'archive peut aussi remplacer le fichier de checksums publie a cote)
RUN cd /tmp \
 && curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
 && echo "${TRIVY_SHA256}  trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/trivy && tar -xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -C /opt/trivy \
 && ln -s /opt/trivy/trivy /usr/local/bin/trivy && rm -f /tmp/trivy_*

# Syft (SBOM CycloneDX) - SHA-256 verifie
RUN curl -fsSL -o /tmp/syft.tgz https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz \
 && echo "${SYFT_SHA256}  /tmp/syft.tgz" | sha256sum -c - \
 && tar -xzf /tmp/syft.tgz -C /usr/local/bin syft && rm /tmp/syft.tgz

# SonarScanner CLI - SHA-256 verifie
RUN curl -fsSL -o /tmp/ss.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
 && echo "${SONAR_SCANNER_SHA256}  /tmp/ss.zip" | sha256sum -c - \
 && unzip -q /tmp/ss.zip -d /opt && mv /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64 /opt/sonar-scanner \
 && ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner && rm /tmp/ss.zip

# Outils Python isoles dans des venv separes (evite les conflits de dependances), versions exactes
RUN python3 -m venv /opt/sast && /opt/sast/bin/pip install --no-cache-dir -q \
        "semgrep==${SEMGREP_VERSION}" "bandit[sarif]==${BANDIT_VERSION}" "pyyaml==${PYYAML_VERSION}" \
 && python3 -m venv /opt/checkov && /opt/checkov/bin/pip install --no-cache-dir -q "checkov==${CHECKOV_VERSION}" \
 && ln -s /opt/sast/bin/semgrep /usr/local/bin/semgrep \
 && ln -s /opt/sast/bin/bandit /usr/local/bin/bandit \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov

# Acces au socket Docker de l'hote + depot monte appartenant a un autre UID
RUN groupadd -f docker && usermod -aG docker jenkins \
 && git config --system --add safe.directory '*'

USER jenkins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt