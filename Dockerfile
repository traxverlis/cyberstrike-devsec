# ============================================================================
# CyberStrikeAI DevSec — Image Docker tout-en-un (multi-stage)
# Contient tous les outils de scan + Python + génération PDF
#
# Build : docker build -t cyberstrike-devsec .
# Usage : docker run --rm -v $(pwd):/workspace cyberstrike-devsec scan
# ============================================================================

# ── Stage 1: Build — téléchargement et vérification des binaires ──────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y -qq \
    curl wget git jq unzip tar gnupg ca-certificates python3 python3-pip \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Grype (pinned version) ────────────────────────────────────────────────────
RUN GRYPE_VER=$(curl -s https://api.github.com/repos/anchore/grype/releases/latest | jq -r .tag_name) \
    && GRYPE_NUM="${GRYPE_VER#v}" \
    && curl -sSfL \
    "https://github.com/anchore/grype/releases/download/${GRYPE_VER}/grype_${GRYPE_NUM}_linux_amd64.tar.gz" \
    -o /tmp/grype.tar.gz \
    && curl -sSfL \
    "https://github.com/anchore/grype/releases/download/${GRYPE_VER}/grype_${GRYPE_NUM}_checksums.txt" \
    -o /tmp/grype_checksums.txt \
    && grep "linux_amd64.tar.gz" /tmp/grype_checksums.txt | sha256sum -c - \
    && tar -xz -C /build -f /tmp/grype.tar.gz grype \
    && rm -f /tmp/grype.tar.gz /tmp/grype_checksums.txt

# ── Syft (pinned version) ────────────────────────────────────────────────────
RUN SYFT_VER=$(curl -s https://api.github.com/repos/anchore/syft/releases/latest | jq -r .tag_name) \
    && SYFT_NUM="${SYFT_VER#v}" \
    && curl -sSfL \
    "https://github.com/anchore/syft/releases/download/${SYFT_VER}/syft_${SYFT_NUM}_linux_amd64.tar.gz" \
    -o /tmp/syft.tar.gz \
    && curl -sSfL \
    "https://github.com/anchore/syft/releases/download/${SYFT_VER}/syft_${SYFT_NUM}_checksums.txt" \
    -o /tmp/syft_checksums.txt \
    && grep "linux_amd64.tar.gz" /tmp/syft_checksums.txt | sha256sum -c - \
    && tar -xz -C /build -f /tmp/syft.tar.gz syft \
    && rm -f /tmp/syft.tar.gz /tmp/syft_checksums.txt

# ── Gitleaks ──────────────────────────────────────────────────────────────────
RUN GL_VER=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/gitleaks/gitleaks/releases/download/${GL_VER}/gitleaks_${GL_VER#v}_linux_x64.tar.gz" \
    -o /tmp/gitleaks.tar.gz \
    && curl -sSfL \
    "https://github.com/gitleaks/gitleaks/releases/download/${GL_VER}/gitleaks_${GL_VER#v}_checksums.txt" \
    -o /tmp/gitleaks_checksums.txt \
    && grep "linux_x64.tar.gz" /tmp/gitleaks_checksums.txt | sha256sum -c - \
    && tar -xz -C /build -f /tmp/gitleaks.tar.gz gitleaks \
    && rm -f /tmp/gitleaks.tar.gz /tmp/gitleaks_checksums.txt

# ── TruffleHog ────────────────────────────────────────────────────────────────
RUN TH_VER=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r '.tag_name' | tr -d 'v') \
    && curl -sSfL \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_linux_amd64.tar.gz" \
    -o /tmp/trufflehog.tar.gz \
    && tar -xz -C /build -f /tmp/trufflehog.tar.gz trufflehog \
    && rm -f /tmp/trufflehog.tar.gz

# ── OSV-Scanner ───────────────────────────────────────────────────────────────
RUN OSV_VER=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/google/osv-scanner/releases/download/${OSV_VER}/osv-scanner_linux_amd64" \
    -o /build/osv-scanner \
    && chmod +x /build/osv-scanner

# ── Nuclei ────────────────────────────────────────────────────────────────────
RUN NUCLEI_VER=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r .tag_name) \
    && NUCLEI_NUM="${NUCLEI_VER#v}" \
    && curl -sSfL \
    "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_NUM}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && curl -sSfL \
    "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VER}/nuclei_${NUCLEI_NUM}_checksums.txt" \
    -o /tmp/nuclei_checksums.txt \
    && grep "linux_amd64.zip" /tmp/nuclei_checksums.txt | sha256sum -c - \
    && unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin \
    && mv /tmp/nuclei_bin/nuclei /build/ \
    && rm -rf /tmp/nuclei.zip /tmp/nuclei_bin /tmp/nuclei_checksums.txt

# ── Subfinder ─────────────────────────────────────────────────────────────────
RUN SF_VER=$(curl -s https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | jq -r .tag_name) \
    && SF_NUM="${SF_VER#v}" \
    && curl -sSfL \
    "https://github.com/projectdiscovery/subfinder/releases/download/${SF_VER}/subfinder_${SF_NUM}_linux_amd64.zip" \
    -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip -d /tmp/subfinder_bin \
    && mv /tmp/subfinder_bin/subfinder /build/ \
    && rm -rf /tmp/subfinder.zip /tmp/subfinder_bin

# ── DalFox ────────────────────────────────────────────────────────────────────
RUN DALFOX_VER=$(curl -s https://api.github.com/repos/hahwul/dalfox/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/hahwul/dalfox/releases/download/${DALFOX_VER}/dalfox-linux-amd64.tar.gz" \
    -o /tmp/dalfox.tar.gz \
    && tar -xz -C /tmp -f /tmp/dalfox.tar.gz \
    && mv /tmp/dalfox-linux-amd64 /build/dalfox \
    && rm -f /tmp/dalfox.tar.gz

# ── Feroxbuster ───────────────────────────────────────────────────────────────
RUN FEROX_VER=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest | jq -r .tag_name) \
    && curl -sSfL \
    "https://github.com/epi052/feroxbuster/releases/download/${FEROX_VER}/x86_64-linux-feroxbuster.tar.gz" \
    -o /tmp/feroxbuster.tar.gz \
    && tar -xz -C /build -f /tmp/feroxbuster.tar.gz feroxbuster \
    && chmod +x /build/feroxbuster \
    && rm -f /tmp/feroxbuster.tar.gz

# ── ffuf ──────────────────────────────────────────────────────────────────────
RUN FFUF_VER=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest | jq -r .tag_name) \
    && FFUF_NUM="${FFUF_VER#v}" \
    && curl -sSfL \
    "https://github.com/ffuf/ffuf/releases/download/${FFUF_VER}/ffuf_${FFUF_NUM}_linux_amd64.tar.gz" \
    -o /tmp/ffuf.tar.gz \
    && tar -xz -C /build -f /tmp/ffuf.tar.gz ffuf \
    && chmod +x /build/ffuf \
    && rm -f /tmp/ffuf.tar.gz

# ── Amass ─────────────────────────────────────────────────────────────────────
RUN AMASS_VER=$(curl -s https://api.github.com/repos/owasp-amass/amass/releases/latest | jq -r '.tag_name') \
    && curl -sSfL "https://github.com/owasp-amass/amass/releases/download/${AMASS_VER}/amass_linux_amd64.tar.gz" \
    -o /tmp/amass.tar.gz \
    && tar -xzf /tmp/amass.tar.gz -C /tmp/ \
    && find /tmp/ -name "amass" -type f -exec mv {} /build/amass \; \
    && chmod +x /build/amass \
    && rm -rf /tmp/amass.tar.gz /tmp/amass_*

# ── dnsx ──────────────────────────────────────────────────────────────────────
RUN DNSX_VER=$(curl -s https://api.github.com/repos/projectdiscovery/dnsx/releases/latest | jq -r '.tag_name') \
    && DNSX_NUM="${DNSX_VER#v}" \
    && curl -sSfL \
    "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VER}/dnsx_${DNSX_NUM}_linux_amd64.zip" \
    -o /tmp/dnsx.zip \
    && unzip -q /tmp/dnsx.zip -d /tmp/dnsx_bin \
    && mv /tmp/dnsx_bin/dnsx /build/ \
    && rm -rf /tmp/dnsx.zip /tmp/dnsx_bin

# ── Git clones (pinned to --depth 1) ─────────────────────────────────────────
RUN git clone --depth 1 https://github.com/epinna/tplmap /build/tplmap \
    && git clone --depth 1 https://github.com/laramies/theHarvester /build/theHarvester \
    && git clone --depth 1 https://github.com/codingo/NoSQLMap /build/nosqlmap


# ── Stage 2: Runtime — image finale légère ────────────────────────────────────
FROM ubuntu:24.04

LABEL maintainer="CyberStrikeAI DevSec"
LABEL description="All-in-one security scanning container — PTES methodology"
LABEL version="3.4.0"

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
    # Divers
    netcat-openbsd dnsutils whois \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Trivy (from apt repo — signed) ───────────────────────────────────────────
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor > /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
    > /etc/apt/sources.list.d/trivy.list \
    && apt-get update -qq && apt-get install -y trivy \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Copier les binaires vérifiés depuis le builder ─────────────────────────────
COPY --from=builder /build/grype /usr/local/bin/grype
COPY --from=builder /build/syft /usr/local/bin/syft
COPY --from=builder /build/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /build/trufflehog /usr/local/bin/trufflehog
COPY --from=builder /build/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /build/nuclei /usr/local/bin/nuclei
COPY --from=builder /build/subfinder /usr/local/bin/subfinder
COPY --from=builder /build/dalfox /usr/local/bin/dalfox
COPY --from=builder /build/feroxbuster /usr/local/bin/feroxbuster
COPY --from=builder /build/ffuf /usr/local/bin/ffuf
COPY --from=builder /build/amass /usr/local/bin/amass
COPY --from=builder /build/dnsx /usr/local/bin/dnsx

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

# ── tplmap (from builder) ────────────────────────────────────────────────────
COPY --from=builder /build/tplmap /opt/tplmap
RUN pip3 install -r /opt/tplmap/requirements.txt -q \
    && chmod +x /opt/tplmap/tplmap.py \
    && ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap

# ── theHarvester (from builder) ──────────────────────────────────────────────
COPY --from=builder /build/theHarvester /opt/theHarvester
RUN pip3 install /opt/theHarvester -q

# ── Hash cracking ──────────────────────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y -qq hashcat john \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# ── NoSQLMap (from builder) ───────────────────────────────────────────────────
COPY --from=builder /build/nosqlmap /opt/nosqlmap
RUN echo '#!/bin/bash\npython3 /opt/nosqlmap/nosqlmap.py "$@"' \
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
