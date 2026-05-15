# ============================================================================
# CyberStrikeAI DevSec — Image Docker tout-en-un
# Contient tous les outils de scan + Python + génération PDF
#
# Build : docker build -t cyberstrike-devsec .
# Usage : docker run --rm -v $(pwd):/workspace cyberstrike-devsec scan
# ============================================================================
FROM ubuntu:24.04

LABEL maintainer="CyberStrikeAI DevSec"
LABEL description="All-in-one security scanning container — PTES methodology"
LABEL version="3.3.0"

# Éviter les prompts interactifs apt
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/root/.local/bin:/usr/local/bin:${PATH}"

WORKDIR /app

# ── Dépendances système ───────────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y -qq \
    # Essentiels
    curl wget git jq unzip tar gnupg ca-certificates \
    lsb-release apt-transport-https software-properties-common \
    # Python
    python3 python3-pip python3-dev pipx \
    # PDF
    pandoc libpango-1.0-0 libpangoft2-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libcairo2 libffi-dev \
    # Outils réseau / scan web
    nmap nikto dirb hydra whatweb gobuster \
    # Outils SMB
    samba-common-bin \
    # Wordlists
    # Divers
    netcat-openbsd dnsutils whois \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Trivy ─────────────────────────────────────────────────────────────────────
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor > /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
    > /etc/apt/sources.list.d/trivy.list \
    && apt-get update -qq && apt-get install -y trivy \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Grype ─────────────────────────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Syft ──────────────────────────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Gitleaks ──────────────────────────────────────────────────────────────────
RUN GL_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/gitleaks/gitleaks/releases/download/${GL_VER}/gitleaks_${GL_VER#v}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

# ── TruffleHog ────────────────────────────────────────────────────────────────
RUN TH_VER=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r '.tag_name' | tr -d 'v') \
    && curl -sSfL \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_linux_amd64.tar.gz" \
    -o /tmp/trufflehog.tar.gz \
    && tar -xz -C /tmp -f /tmp/trufflehog.tar.gz trufflehog \
    && mv /tmp/trufflehog /usr/local/bin/ \
    && rm -f /tmp/trufflehog.tar.gz

# ── OSV-Scanner ───────────────────────────────────────────────────────────────
RUN OSV_VER=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/google/osv-scanner/releases/download/${OSV_VER}/osv-scanner_linux_amd64" \
    -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# ── Nuclei ────────────────────────────────────────────────────────────────────
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name) \
    && NUCLEI_NUM="${NUCLEI_VER#v}" \
    && curl -sSfL \
    "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_NUM}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin \
    && mv /tmp/nuclei_bin/nuclei /usr/local/bin/ \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_bin

# ── Subfinder ─────────────────────────────────────────────────────────────────
RUN SF_VER=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r .tag_name) \
    && SF_NUM="${SF_VER#v}" \
    && curl -sSfL \
    "https://github.com/projectdiscovery/subfinder/releases/download/${SF_VER}/subfinder_${SF_NUM}_linux_amd64.zip" \
    -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip -d /tmp/subfinder_bin \
    && mv /tmp/subfinder_bin/subfinder /usr/local/bin/ \
    && rm -rf /tmp/subfinder.zip /tmp/subfinder_bin

# ── DalFox ────────────────────────────────────────────────────────────────────
RUN DALFOX_VER=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/hahwul/dalfox/releases/download/${DALFOX_VER}/dalfox-linux-amd64.tar.gz" \
    -o /tmp/dalfox.tar.gz \
    && tar -xz -C /tmp -f /tmp/dalfox.tar.gz \
    && mv /tmp/dalfox-linux-amd64 /usr/local/bin/dalfox \
    && rm -f /tmp/dalfox.tar.gz

# ── Feroxbuster ───────────────────────────────────────────────────────────────
RUN FEROX_VER=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/epi052/feroxbuster/releases/download/${FEROX_VER}/x86_64-linux-feroxbuster.tar.gz" \
    | tar -xz -C /usr/local/bin feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster

# ── ffuf ──────────────────────────────────────────────────────────────────────
RUN FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | jq -r .tag_name) \
    && FFUF_NUM="${FFUF_VER#v}" \
    && curl -sSfL \
    "https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_NUM}_linux_amd64.tar.gz" \
    | tar -xz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf

# ── testssl.sh ────────────────────────────────────────────────────────────────
RUN curl -sSfL https://testssl.sh/testssl.sh -o /usr/local/bin/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh

# ── enum4linux-ng ─────────────────────────────────────────────────────────────
RUN curl -sSfL \
    https://raw.githubusercontent.com/cddmp/enum4linux-ng/master/enum4linux-ng.py \
    -o /usr/local/bin/enum4linux-ng.py \
    && echo '#!/bin/bash\npython3 /usr/local/bin/enum4linux-ng.py "$@"' \
    > /usr/local/bin/enum4linux \
    && chmod +x /usr/local/bin/enum4linux /usr/local/bin/enum4linux-ng.py

# ── sqlmap ────────────────────────────────────────────────────────────────────
RUN pipx install sqlmap

# ── OWASP ZAP (Level 3 — scan actif complet) ──────────────────────────────────
RUN apt-get update -qq && apt-get install -y -qq openjdk-17-jre-headless \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN ZAP_VER=$(curl -s https://api.github.com/repos/zaproxy/zaproxy/releases/latest | jq -r '.tag_name') \
    && ZAP_NUM="${ZAP_VER#v}" \
    && curl -sSfL \
    "https://github.com/zaproxy/zaproxy/releases/download/${ZAP_VER}/ZAP_${ZAP_NUM}_Linux.tar.gz" \
    -o /tmp/zap.tar.gz \
    && tar -xz -C /opt -f /tmp/zap.tar.gz \
    && mv /opt/ZAP_${ZAP_NUM} /opt/zaproxy \
    && ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zaproxy \
    && find /opt/zaproxy -name "zap-baseline.py" -exec ln -sf {} /usr/local/bin/zap-baseline.py \; 2>/dev/null || true \
    && rm -f /tmp/zap.tar.gz

# ── Outils d'injection web ──────────────────────────────────────────────────
RUN pipx install xsstrike 2>/dev/null || pip3 install xsstrike -q
RUN pipx install commix 2>/dev/null || pip3 install commix -q
RUN pipx install arjun
RUN apt-get update -qq && apt-get install -y -qq libcurl4-openssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && pip3 install pycurl wfuzz -q
RUN git clone --depth 1 https://github.com/epinna/tplmap /opt/tplmap \
    && pip3 install -r /opt/tplmap/requirements.txt -q \
    && chmod +x /opt/tplmap/tplmap.py \
    && ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap

# ── OSINT / Recon ────────────────────────────────────────────────────────────────
RUN AMASS_VER=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest | jq -r '.tag_name') \
    && curl -sSfL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_linux_amd64.tar.gz" \
    -o /tmp/amass.tar.gz \
    && tar -xzf /tmp/amass.tar.gz -C /tmp/ \
    && find /tmp/ -name "amass" -type f -exec mv {} /usr/local/bin/amass \; \
    && chmod +x /usr/local/bin/amass \
    && rm -rf /tmp/amass.tar.gz /tmp/amass_*

RUN DNSX_VER=$(curl -s https://api.github.com/repos/projectdiscovery/dnsx/releases/latest | jq -r '.tag_name') \
    && DNSX_NUM="${DNSX_VER#v}" \
    && curl -sSfL \
    "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VER}/dnsx_${DNSX_NUM}_linux_amd64.zip" \
    -o /tmp/dnsx.zip \
    && unzip -q /tmp/dnsx.zip -d /tmp/dnsx_bin \
    && mv /tmp/dnsx_bin/dnsx /usr/local/bin/ \
    && rm -rf /tmp/dnsx.zip /tmp/dnsx_bin

RUN git clone --depth 1 https://github.com/laramies/theHarvester /opt/theHarvester \
    && pip3 install /opt/theHarvester -q

# ── Hash cracking ──────────────────────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y -qq hashcat john \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── NoSQL injection ───────────────────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/codingo/NoSQLMap /opt/nosqlmap \
    && echo '#!/bin/bash\npython3 /opt/nosqlmap/nosqlmap.py "$@"' \
    > /usr/local/bin/nosqlmap \
    && chmod +x /usr/local/bin/nosqlmap

# ── Wapiti ────────────────────────────────────────────────────────────────────
RUN pipx install wapiti3

# ── Semgrep ───────────────────────────────────────────────────────────────────
RUN pipx install semgrep

# ── Checkov ───────────────────────────────────────────────────────────────────
RUN pipx install checkov

# ── pip-audit ─────────────────────────────────────────────────────────────────
RUN pipx install pip-audit

# ── weasyprint ────────────────────────────────────────────────────────────────
RUN pipx install weasyprint

# ── Dépendances Python du projet ─────────────────────────────────────────────
COPY requirements.txt scripts/consent/requirements.txt* /tmp/
RUN pip3 install -r /tmp/requirements.txt --break-system-packages -q 2>/dev/null || true \
    && pip3 install reportlab qrcode Pillow requests pdfplumber rich pyyaml \
    --break-system-packages -q 2>/dev/null || true

# ── Copier le projet ──────────────────────────────────────────────────────────
COPY . /app/

# ── Permissions ───────────────────────────────────────────────────────────────
RUN chmod +x /app/scripts/*.sh 2>/dev/null || true \
    && mkdir -p /workspace /reports /app/security-reports

# ── Point d'entrée ────────────────────────────────────────────────────────────
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME ["/workspace", "/reports"]

WORKDIR /app

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["help"]
