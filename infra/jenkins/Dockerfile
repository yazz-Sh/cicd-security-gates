# Image Jenkins "paved road" : tous les scanners de securite preinstalles,
# chacun en VERSION EPINGLEE (jamais "latest" : cf. compromission de tags 2026).
FROM jenkins/jenkins:lts-jdk17

USER root
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.75.0
ARG SYFT_VERSION=1.55.0
ARG SONAR_SCANNER_VERSION=8.2.0.6438

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv python3-pip curl ca-certificates unzip git gnupg \
 && rm -rf /var/lib/apt/lists/*

# Docker CLI (le moteur est celui de l'hote, via le socket monte)
RUN install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list \
 && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

# Gitleaks (secrets)
RUN curl -fsSL -o /tmp/gl.tgz https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz \
 && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks && rm /tmp/gl.tgz

# Trivy (SCA + image) - archive verifiee contre le fichier de checksums de la release
RUN cd /tmp \
 && curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
 && curl -fsSLO https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt \
 && grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz$" trivy_${TRIVY_VERSION}_checksums.txt | sha256sum -c - \
 && mkdir -p /opt/trivy && tar -xzf trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz -C /opt/trivy \
 && ln -s /opt/trivy/trivy /usr/local/bin/trivy && rm -f /tmp/trivy_*

# Syft (SBOM CycloneDX)
RUN curl -fsSL -o /tmp/syft.tgz https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz \
 && tar -xzf /tmp/syft.tgz -C /usr/local/bin syft && rm /tmp/syft.tgz

# SonarScanner CLI
RUN curl -fsSL -o /tmp/ss.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
 && unzip -q /tmp/ss.zip -d /opt && mv /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64 /opt/sonar-scanner \
 && ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner && rm /tmp/ss.zip

# Outils Python isoles dans des venv separes (evite les conflits de dependances)
RUN python3 -m venv /opt/sast && /opt/sast/bin/pip install --no-cache-dir -q semgrep "bandit[sarif]" pyyaml \
 && python3 -m venv /opt/checkov && /opt/checkov/bin/pip install --no-cache-dir -q checkov \
 && ln -s /opt/sast/bin/semgrep /usr/local/bin/semgrep \
 && ln -s /opt/sast/bin/bandit /usr/local/bin/bandit \
 && ln -s /opt/checkov/bin/checkov /usr/local/bin/checkov

# Acces au socket Docker de l'hote + depot monte appartenant a un autre UID
RUN groupadd -f docker && usermod -aG docker jenkins \
 && git config --system --add safe.directory '*'

USER jenkins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt