# CI/CD Integration Guide — CyberStrikeAI DevSec

This guide covers integrating CyberStrikeAI security scanning into the most common CI/CD platforms.

---

## Table of Contents

1. [GitHub Actions](#github-actions)
2. [GitLab CI](#gitlab-ci)
3. [Azure DevOps](#azure-devops)
4. [Jenkins](#jenkins)
5. [Secret Management](#secret-management)

---

## GitHub Actions

### Complete Workflow

Create `.github/workflows/security-scan.yml` in your repository:

```yaml
name: Security Scan — CyberStrikeAI

on:
  push:
    branches: [main, develop, "release/**"]
  pull_request:
    branches: [main, develop]

permissions:
  contents: read
  pull-requests: write
  security-events: write

env:
  CYBERSTRIKE_VERSION: "1.0.0"

jobs:
  security-scan:
    name: DevSec Full Scan
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      # ── Checkout ──────────────────────────────────────────────────────────
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0   # full history for secret scanning

      # ── Install tools ─────────────────────────────────────────────────────
      - name: Install security tools
        run: |
          # Grype (CVE scanner)
          curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

          # Trivy
          sudo apt-get install -y wget apt-transport-https gnupg lsb-release
          wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
          echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
          sudo apt-get update && sudo apt-get install -y trivy

          # Semgrep
          pip install semgrep

          # Gitleaks
          curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -s)_x64.tar.gz | tar -xz -C /usr/local/bin

          # Syft (SBOM)
          curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

          # OSV-Scanner
          go install github.com/google/osv-scanner/cmd/osv-scanner@latest

      # ── CyberStrikeAI MCP setup ───────────────────────────────────────────
      - name: Configure CyberStrikeAI
        env:
          NVD_API_KEY: ${{ secrets.NVD_API_KEY }}
          CYBERSTRIKE_LICENSE: ${{ secrets.CYBERSTRIKE_LICENSE }}
        run: |
          mkdir -p ~/.cyberstrike
          cat > ~/.cyberstrike/config.yaml <<EOF
          nvd_api_key: "${NVD_API_KEY}"
          license: "${CYBERSTRIKE_LICENSE}"
          output_format: json
          severity_threshold: HIGH
          fail_on_critical: true
          EOF

      # ── CVE Scan ──────────────────────────────────────────────────────────
      - name: CVE Scan (Grype + Trivy)
        id: cve-scan
        continue-on-error: true
        run: |
          echo "## Running CVE scans..."
          mkdir -p scan-results

          # Grype filesystem scan
          grype dir:. \
            --output json \
            --file scan-results/grype-results.json \
            --add-cpes-if-none

          # Trivy filesystem scan
          trivy fs . \
            --format json \
            --output scan-results/trivy-results.json \
            --severity HIGH,CRITICAL \
            --exit-code 1 || echo "TRIVY_EXIT=$?" >> $GITHUB_ENV

          # Parse summary
          CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' scan-results/grype-results.json 2>/dev/null || echo 0)
          HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' scan-results/grype-results.json 2>/dev/null || echo 0)
          echo "cve_critical=$CRITICAL" >> $GITHUB_OUTPUT
          echo "cve_high=$HIGH" >> $GITHUB_OUTPUT

      # ── SAST Scan ─────────────────────────────────────────────────────────
      - name: SAST Scan (Semgrep)
        id: sast-scan
        continue-on-error: true
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
        run: |
          semgrep ci \
            --config auto \
            --json \
            --output scan-results/semgrep-results.json || true

          FINDINGS=$(jq '.results | length' scan-results/semgrep-results.json 2>/dev/null || echo 0)
          echo "sast_findings=$FINDINGS" >> $GITHUB_OUTPUT

      # ── Secret Scan ───────────────────────────────────────────────────────
      - name: Secret Scan (Gitleaks)
        id: secret-scan
        continue-on-error: true
        run: |
          gitleaks detect \
            --source . \
            --report-format json \
            --report-path scan-results/gitleaks-results.json \
            --exit-code 1 || echo "GITLEAKS_EXIT=1" >> $GITHUB_ENV

          SECRETS=$(jq '. | length' scan-results/gitleaks-results.json 2>/dev/null || echo 0)
          echo "secrets_found=$SECRETS" >> $GITHUB_OUTPUT

      # ── OWASP Dependency Check ────────────────────────────────────────────
      - name: OWASP Dependency Check
        id: owasp-scan
        continue-on-error: true
        run: |
          # Generate SBOM first
          syft dir:. -o cyclonedx-json=scan-results/sbom.json

          # OSV scan against SBOM
          osv-scanner --sbom=scan-results/sbom.json \
            --format json > scan-results/osv-results.json 2>&1 || true

      # ── Generate Report ───────────────────────────────────────────────────
      - name: Generate Consolidated Report
        id: report
        run: |
          cat > scan-results/summary.json <<EOF
          {
            "scan_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
            "commit": "${{ github.sha }}",
            "branch": "${{ github.ref_name }}",
            "cve_critical": ${{ steps.cve-scan.outputs.cve_critical || 0 }},
            "cve_high": ${{ steps.cve-scan.outputs.cve_high || 0 }},
            "sast_findings": ${{ steps.sast-scan.outputs.sast_findings || 0 }},
            "secrets_found": ${{ steps.secret-scan.outputs.secrets_found || 0 }}
          }
          EOF

          # Determine overall status
          CRITICAL=${{ steps.cve-scan.outputs.cve_critical || 0 }}
          SECRETS=${{ steps.secret-scan.outputs.secrets_found || 0 }}

          if [ "$CRITICAL" -gt "0" ] || [ "$SECRETS" -gt "0" ]; then
            echo "scan_status=FAILED" >> $GITHUB_OUTPUT
            echo "scan_emoji=❌" >> $GITHUB_OUTPUT
          else
            echo "scan_status=PASSED" >> $GITHUB_OUTPUT
            echo "scan_emoji=✅" >> $GITHUB_OUTPUT
          fi

      # ── PR Comment ────────────────────────────────────────────────────────
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const status = '${{ steps.report.outputs.scan_status }}';
            const emoji = '${{ steps.report.outputs.scan_emoji }}';
            const cveCritical = '${{ steps.cve-scan.outputs.cve_critical || 0 }}';
            const cveHigh = '${{ steps.cve-scan.outputs.cve_high || 0 }}';
            const sast = '${{ steps.sast-scan.outputs.sast_findings || 0 }}';
            const secrets = '${{ steps.secret-scan.outputs.secrets_found || 0 }}';

            const body = `## ${emoji} CyberStrikeAI Security Scan — ${status}

            | Check | Result |
            |-------|--------|
            | 🔴 CVE Critical | ${cveCritical} |
            | 🟠 CVE High | ${cveHigh} |
            | 🔍 SAST Findings | ${sast} |
            | 🔑 Secrets Exposed | ${secrets} |

            <details>
            <summary>📋 How to interpret these results</summary>

            - **CVE Critical/High**: Known vulnerabilities in dependencies. Prioritize Critical fixes before merge.
            - **SAST Findings**: Static analysis issues (SQL injection, XSS, etc.) — review each manually.
            - **Secrets Exposed**: Hardcoded credentials or tokens — remove immediately and rotate secrets.

            Full JSON reports are available in the [workflow artifacts](${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}).
            </details>

            > Scanned commit \`${{ github.sha }}\` on \`${{ github.ref_name }}\``;

            // Find and update existing comment or create new one
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });

            const botComment = comments.find(c =>
              c.user.type === 'Bot' && c.body.includes('CyberStrikeAI Security Scan')
            );

            if (botComment) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: botComment.id,
                body: body,
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: body,
              });
            }

      # ── Upload Artifacts ──────────────────────────────────────────────────
      - name: Upload scan results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-scan-results-${{ github.run_number }}
          path: scan-results/
          retention-days: 30

      # ── Upload to GitHub Security tab ─────────────────────────────────────
      - name: Upload Trivy SARIF to GitHub Security
        if: always()
        run: |
          trivy fs . \
            --format sarif \
            --output scan-results/trivy.sarif \
            --severity HIGH,CRITICAL || true

      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: scan-results/trivy.sarif

      # ── Fail if critical issues ───────────────────────────────────────────
      - name: Fail on critical findings
        if: steps.report.outputs.scan_status == 'FAILED'
        run: |
          echo "❌ Security scan FAILED — Critical CVEs or secrets found."
          echo "Review the artifacts and PR comment for details."
          exit 1
```

### Security Badge

Add to your `README.md`:

```markdown
![Security Scan](https://github.com/<ORG>/<REPO>/actions/workflows/security-scan.yml/badge.svg)
```

### Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `NVD_API_KEY` | National Vulnerability Database API key (free at nvd.nist.gov) |
| `CYBERSTRIKE_LICENSE` | CyberStrikeAI license key |
| `SEMGREP_APP_TOKEN` | Semgrep Cloud token (optional, for dashboard) |

---

## GitLab CI

### Complete `.gitlab-ci.yml`

```yaml
# CyberStrikeAI DevSec Pipeline
stages:
  - build
  - security
  - report

variables:
  SCAN_OUTPUT_DIR: "security-reports"
  SEVERITY_THRESHOLD: "HIGH"

# ── Template: common setup ────────────────────────────────────────────────────
.security-base:
  image: ubuntu:22.04
  before_script:
    - apt-get update -qq && apt-get install -y -qq curl wget jq python3-pip golang-go
    - mkdir -p $SCAN_OUTPUT_DIR
    # Install Grype
    - curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
    # Install Trivy
    - wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
    - echo "deb https://aquasecurity.github.io/trivy-repo/deb jammy main" >> /etc/apt/sources.list.d/trivy.list
    - apt-get update -qq && apt-get install -y -qq trivy
    # Install Semgrep
    - pip3 install -q semgrep
    # Install Gitleaks
    - |
      GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)
      curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin

# ── Stage: CVE Scanning ───────────────────────────────────────────────────────
cve-scan:
  extends: .security-base
  stage: security
  variables:
    GIT_DEPTH: 0
  script:
    - echo "Running CVE scan with Grype..."
    - |
      grype dir:. \
        --output json \
        --file $SCAN_OUTPUT_DIR/grype-results.json \
        --add-cpes-if-none || true
    - echo "Running CVE scan with Trivy..."
    - |
      trivy fs . \
        --format json \
        --output $SCAN_OUTPUT_DIR/trivy-results.json \
        --severity HIGH,CRITICAL || true
    - |
      CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' $SCAN_OUTPUT_DIR/grype-results.json 2>/dev/null || echo 0)
      echo "Critical CVEs found: $CRITICAL"
      echo "CVE_CRITICAL=$CRITICAL" >> cve.env
    - |
      # Fail pipeline on critical CVEs
      if [ "$CRITICAL" -gt "0" ]; then
        echo "❌ Critical CVEs detected — failing pipeline."
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - $SCAN_OUTPUT_DIR/grype-results.json
      - $SCAN_OUTPUT_DIR/trivy-results.json
    reports:
      dotenv: cve.env
    expire_in: 30 days

# ── Stage: SAST ───────────────────────────────────────────────────────────────
sast-scan:
  extends: .security-base
  stage: security
  script:
    - echo "Running SAST with Semgrep..."
    - |
      semgrep scan \
        --config auto \
        --json \
        --output $SCAN_OUTPUT_DIR/semgrep-results.json \
        . || true
    - |
      FINDINGS=$(jq '.results | length' $SCAN_OUTPUT_DIR/semgrep-results.json 2>/dev/null || echo 0)
      echo "SAST findings: $FINDINGS"
      echo "SAST_FINDINGS=$FINDINGS" >> sast.env
  artifacts:
    when: always
    paths:
      - $SCAN_OUTPUT_DIR/semgrep-results.json
    reports:
      dotenv: sast.env
    expire_in: 30 days

# ── Stage: Secret Scan ────────────────────────────────────────────────────────
secret-scan:
  extends: .security-base
  stage: security
  variables:
    GIT_DEPTH: 0
  script:
    - echo "Scanning for secrets with Gitleaks..."
    - |
      gitleaks detect \
        --source . \
        --report-format json \
        --report-path $SCAN_OUTPUT_DIR/gitleaks-results.json \
        --exit-code 1 || GITLEAKS_EXIT=$?
    - |
      SECRETS=$(jq '. | length' $SCAN_OUTPUT_DIR/gitleaks-results.json 2>/dev/null || echo 0)
      echo "Secrets found: $SECRETS"
      if [ "$SECRETS" -gt "0" ]; then
        echo "❌ Secrets detected — rotate credentials immediately!"
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - $SCAN_OUTPUT_DIR/gitleaks-results.json
    expire_in: 30 days

# ── Stage: Consolidated Report ────────────────────────────────────────────────
security-report:
  stage: report
  image: alpine:latest
  needs:
    - cve-scan
    - sast-scan
    - secret-scan
  when: always
  before_script:
    - apk add --no-cache jq curl
  script:
    - echo "Generating consolidated security report..."
    - mkdir -p $SCAN_OUTPUT_DIR
    - |
      cat > $SCAN_OUTPUT_DIR/summary.json <<EOF
      {
        "scan_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "commit": "$CI_COMMIT_SHA",
        "branch": "$CI_COMMIT_REF_NAME",
        "pipeline_id": "$CI_PIPELINE_ID",
        "project": "$CI_PROJECT_NAME"
      }
      EOF
    - cat $SCAN_OUTPUT_DIR/summary.json
    # Post comment on Merge Request if applicable
    - |
      if [ -n "$CI_MERGE_REQUEST_IID" ]; then
        NOTE="## 🔒 CyberStrikeAI Security Scan Results\n\nPipeline: $CI_PIPELINE_ID | Commit: $CI_COMMIT_SHORT_SHA\n\nCheck artifacts for full JSON reports."
        curl --silent --request POST \
          --header "PRIVATE-TOKEN: $GITLAB_BOT_TOKEN" \
          --data-urlencode "body=$NOTE" \
          "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes" || true
      fi
  artifacts:
    when: always
    paths:
      - $SCAN_OUTPUT_DIR/
    expire_in: 90 days
```

### GitLab CI/CD Variables

Go to **Settings → CI/CD → Variables** and add:

| Variable | Value | Protected | Masked |
|----------|-------|-----------|--------|
| `NVD_API_KEY` | Your NVD key | ✅ | ✅ |
| `CYBERSTRIKE_LICENSE` | License key | ✅ | ✅ |
| `GITLAB_BOT_TOKEN` | Personal/project token with API scope | ✅ | ✅ |
| `SEMGREP_APP_TOKEN` | Semgrep token | ✅ | ✅ |

---

## Azure DevOps

### Complete `azure-pipelines.yml`

```yaml
# CyberStrikeAI Security Pipeline — Azure DevOps
trigger:
  branches:
    include:
      - main
      - develop
      - release/*
  paths:
    exclude:
      - "*.md"
      - docs/**

pr:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: "ubuntu-latest"

variables:
  - group: cyberstrike-secrets   # Variable group in Azure DevOps Library
  - name: SCAN_OUTPUT_DIR
    value: $(Build.ArtifactStagingDirectory)/security-reports

stages:
  # ── Stage: Security Scanning ───────────────────────────────────────────────
  - stage: SecurityScan
    displayName: "🔒 Security Scanning"
    jobs:
      # ── Job: CVE Scan ──────────────────────────────────────────────────────
      - job: CVEScan
        displayName: "CVE Vulnerability Scan"
        steps:
          - checkout: self
            fetchDepth: 0

          - script: |
              mkdir -p $(SCAN_OUTPUT_DIR)

              # Install Grype
              curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

              # Install Trivy
              sudo apt-get update -qq
              sudo apt-get install -y wget apt-transport-https
              wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
              echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
              sudo apt-get update -qq && sudo apt-get install -y trivy
            displayName: "Install CVE Tools"

          - script: |
              echo "##[section]Running Grype CVE scan..."
              grype dir:$(Build.SourcesDirectory) \
                --output json \
                --file $(SCAN_OUTPUT_DIR)/grype-results.json || true

              echo "##[section]Running Trivy CVE scan..."
              trivy fs $(Build.SourcesDirectory) \
                --format json \
                --output $(SCAN_OUTPUT_DIR)/trivy-results.json \
                --severity HIGH,CRITICAL || true

              # Count findings
              CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' $(SCAN_OUTPUT_DIR)/grype-results.json 2>/dev/null || echo 0)
              HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' $(SCAN_OUTPUT_DIR)/grype-results.json 2>/dev/null || echo 0)

              echo "##vso[task.setvariable variable=cveCritical;isOutput=true]$CRITICAL"
              echo "##vso[task.setvariable variable=cveHigh;isOutput=true]$HIGH"

              echo "Critical CVEs: $CRITICAL | High CVEs: $HIGH"

              if [ "$CRITICAL" -gt "0" ]; then
                echo "##vso[task.logissue type=error]Critical CVEs detected: $CRITICAL"
                echo "##vso[task.complete result=Failed;]Critical CVEs found."
              fi
            name: RunCVEScan
            displayName: "Run CVE Scans"
            env:
              NVD_API_KEY: $(NVD_API_KEY)

          - task: PublishTestResults@2
            condition: always()
            displayName: "Publish CVE Results"
            inputs:
              testResultsFormat: "JUnit"
              testResultsFiles: "$(SCAN_OUTPUT_DIR)/trivy-results.json"
              failTaskOnFailedTests: false
              testRunTitle: "CVE Scan Results"

      # ── Job: SAST ──────────────────────────────────────────────────────────
      - job: SASTScan
        displayName: "SAST — Semgrep"
        steps:
          - checkout: self

          - script: pip install semgrep
            displayName: "Install Semgrep"

          - script: |
              mkdir -p $(SCAN_OUTPUT_DIR)
              semgrep scan \
                --config auto \
                --json \
                --output $(SCAN_OUTPUT_DIR)/semgrep-results.json \
                $(Build.SourcesDirectory) || true

              FINDINGS=$(jq '.results | length' $(SCAN_OUTPUT_DIR)/semgrep-results.json 2>/dev/null || echo 0)
              echo "SAST findings: $FINDINGS"
              echo "##vso[task.setvariable variable=sastFindings;isOutput=true]$FINDINGS"

              # Convert to SARIF for Azure Test Plans
              semgrep scan \
                --config auto \
                --sarif \
                --output $(SCAN_OUTPUT_DIR)/semgrep.sarif \
                $(Build.SourcesDirectory) || true
            name: RunSAST
            displayName: "Run Semgrep SAST"
            env:
              SEMGREP_APP_TOKEN: $(SEMGREP_APP_TOKEN)

          - task: PublishBuildArtifacts@1
            condition: always()
            displayName: "Publish SAST SARIF"
            inputs:
              pathToPublish: "$(SCAN_OUTPUT_DIR)/semgrep.sarif"
              artifactName: "sast-sarif"

      # ── Job: Secret Scan ───────────────────────────────────────────────────
      - job: SecretScan
        displayName: "Secret Scan — Gitleaks"
        steps:
          - checkout: self
            fetchDepth: 0

          - script: |
              GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)
              curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin
            displayName: "Install Gitleaks"

          - script: |
              mkdir -p $(SCAN_OUTPUT_DIR)
              gitleaks detect \
                --source $(Build.SourcesDirectory) \
                --report-format json \
                --report-path $(SCAN_OUTPUT_DIR)/gitleaks-results.json \
                --exit-code 1 || LEAK_EXIT=$?

              SECRETS=$(jq '. | length' $(SCAN_OUTPUT_DIR)/gitleaks-results.json 2>/dev/null || echo 0)
              if [ "$SECRETS" -gt "0" ]; then
                echo "##vso[task.logissue type=error]Secrets detected: $SECRETS — rotate credentials immediately!"
                echo "##vso[task.complete result=Failed;]Secrets found."
              fi
            name: RunSecretScan
            displayName: "Run Gitleaks"

  # ── Stage: Publish Reports ─────────────────────────────────────────────────
  - stage: PublishResults
    displayName: "📊 Publish Results"
    dependsOn: SecurityScan
    condition: always()
    jobs:
      - job: PublishArtifacts
        displayName: "Publish All Security Artifacts"
        steps:
          - task: PublishBuildArtifacts@1
            displayName: "Publish Security Reports"
            inputs:
              pathToPublish: "$(Build.ArtifactStagingDirectory)/security-reports"
              artifactName: "security-reports-$(Build.BuildNumber)"
              publishLocation: "Container"
```

### Azure DevOps Variable Group

In **Pipelines → Library**, create a variable group named `cyberstrike-secrets`:

| Variable | Secret |
|----------|--------|
| `NVD_API_KEY` | ✅ |
| `CYBERSTRIKE_LICENSE` | ✅ |
| `SEMGREP_APP_TOKEN` | ✅ |

---

## Jenkins

### Complete `Jenkinsfile`

```groovy
// CyberStrikeAI DevSec Pipeline — Jenkins
pipeline {
    agent {
        label 'linux'
    }

    environment {
        NVD_API_KEY         = credentials('nvd-api-key')
        CYBERSTRIKE_LICENSE = credentials('cyberstrike-license')
        SEMGREP_APP_TOKEN   = credentials('semgrep-app-token')
        SONAR_TOKEN         = credentials('sonarqube-token')
        SONAR_HOST_URL      = 'https://sonarqube.your-company.com'
        SCAN_DIR            = "${WORKSPACE}/security-reports"
    }

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '10'))
    }

    triggers {
        // Poll SCM every 5 minutes (or use webhook)
        pollSCM('H/5 * * * *')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p ${SCAN_DIR}'
            }
        }

        stage('Install Tools') {
            steps {
                sh '''
                    # Grype
                    if ! command -v grype &>/dev/null; then
                        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
                    fi

                    # Trivy
                    if ! command -v trivy &>/dev/null; then
                        sudo apt-get update -qq
                        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
                        sudo apt-get update -qq && sudo apt-get install -y trivy
                    fi

                    # Semgrep
                    pip3 install -q semgrep || pip install -q semgrep

                    # Gitleaks
                    if ! command -v gitleaks &>/dev/null; then
                        GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r .tag_name)
                        curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin
                    fi

                    # Syft (SBOM)
                    if ! command -v syft &>/dev/null; then
                        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
                    fi

                    echo "✅ All tools installed"
                    grype version
                    trivy --version
                    semgrep --version
                    gitleaks version
                    syft version
                '''
            }
        }

        // ── Parallel Security Scans ──────────────────────────────────────────
        stage('Security Scans') {
            parallel {

                stage('CVE Scan') {
                    stages {
                        stage('Grype CVE') {
                            steps {
                                sh '''
                                    echo "=== Grype CVE Scan ==="
                                    grype dir:${WORKSPACE} \
                                        --output json \
                                        --file ${SCAN_DIR}/grype-results.json \
                                        --add-cpes-if-none || true

                                    CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' ${SCAN_DIR}/grype-results.json 2>/dev/null || echo 0)
                                    echo "Grype: Critical CVEs = $CRITICAL"
                                '''
                            }
                        }
                        stage('Trivy CVE') {
                            steps {
                                sh '''
                                    echo "=== Trivy CVE Scan ==="
                                    trivy fs ${WORKSPACE} \
                                        --format json \
                                        --output ${SCAN_DIR}/trivy-results.json \
                                        --severity HIGH,CRITICAL || true

                                    # Also generate SARIF for SonarQube import
                                    trivy fs ${WORKSPACE} \
                                        --format sarif \
                                        --output ${SCAN_DIR}/trivy.sarif \
                                        --severity HIGH,CRITICAL || true
                                '''
                            }
                        }
                    }
                }

                stage('SAST Scan') {
                    steps {
                        sh '''
                            echo "=== Semgrep SAST Scan ==="
                            semgrep scan \
                                --config auto \
                                --json \
                                --output ${SCAN_DIR}/semgrep-results.json \
                                ${WORKSPACE} || true

                            # SARIF for SonarQube
                            semgrep scan \
                                --config auto \
                                --sarif \
                                --output ${SCAN_DIR}/semgrep.sarif \
                                ${WORKSPACE} || true

                            FINDINGS=$(jq '.results | length' ${SCAN_DIR}/semgrep-results.json 2>/dev/null || echo 0)
                            echo "Semgrep: $FINDINGS findings"
                        '''
                        withSonarQubeEnv('SonarQube') {
                            sh '''
                                # Forward Semgrep SARIF to SonarQube if available
                                sonar-scanner \
                                    -Dsonar.projectKey=${JOB_NAME} \
                                    -Dsonar.sources=. \
                                    -Dsonar.externalIssuesReportPaths=${SCAN_DIR}/semgrep.sarif \
                                    -Dsonar.login=${SONAR_TOKEN} || true
                            '''
                        }
                    }
                }

                stage('OWASP Dependency Check') {
                    steps {
                        sh '''
                            echo "=== OWASP / OSV Scan ==="
                            # Generate SBOM
                            syft dir:${WORKSPACE} \
                                -o cyclonedx-json=${SCAN_DIR}/sbom.json

                            # Scan with OSV
                            if command -v osv-scanner &>/dev/null; then
                                osv-scanner \
                                    --sbom=${SCAN_DIR}/sbom.json \
                                    --format json > ${SCAN_DIR}/osv-results.json 2>&1 || true
                            fi

                            echo "SBOM and OSV scan complete."
                        '''
                    }
                }

                stage('Secret Scan') {
                    steps {
                        sh '''
                            echo "=== Gitleaks Secret Scan ==="
                            gitleaks detect \
                                --source ${WORKSPACE} \
                                --report-format json \
                                --report-path ${SCAN_DIR}/gitleaks-results.json \
                                --exit-code 0 || true

                            SECRETS=$(jq '. | length' ${SCAN_DIR}/gitleaks-results.json 2>/dev/null || echo 0)
                            echo "Gitleaks: $SECRETS potential secrets found"

                            if [ "$SECRETS" -gt "0" ]; then
                                echo "⚠️  WARNING: Potential secrets detected!"
                            fi
                        '''
                    }
                }

            } // parallel
        } // Security Scans

        stage('Generate Report') {
            steps {
                sh '''
                    CVE_CRITICAL=$(jq '[.matches[] | select(.vulnerability.severity=="Critical")] | length' ${SCAN_DIR}/grype-results.json 2>/dev/null || echo 0)
                    CVE_HIGH=$(jq '[.matches[] | select(.vulnerability.severity=="High")] | length' ${SCAN_DIR}/grype-results.json 2>/dev/null || echo 0)
                    SAST=$(jq '.results | length' ${SCAN_DIR}/semgrep-results.json 2>/dev/null || echo 0)
                    SECRETS=$(jq '. | length' ${SCAN_DIR}/gitleaks-results.json 2>/dev/null || echo 0)

                    cat > ${SCAN_DIR}/summary.json <<EOF
{
  "scan_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "build": "${BUILD_NUMBER}",
  "branch": "${GIT_BRANCH}",
  "commit": "${GIT_COMMIT}",
  "cve_critical": $CVE_CRITICAL,
  "cve_high": $CVE_HIGH,
  "sast_findings": $SAST,
  "secrets_found": $SECRETS,
  "status": "$([ "$CVE_CRITICAL" -gt "0" ] || [ "$SECRETS" -gt "0" ] && echo FAILED || echo PASSED)"
}
EOF
                    cat ${SCAN_DIR}/summary.json
                '''
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    def summary = readJSON file: "${SCAN_DIR}/summary.json"
                    def critical = summary.cve_critical as Integer
                    def secrets  = summary.secrets_found as Integer

                    if (critical > 0 || secrets > 0) {
                        currentBuild.result = 'FAILURE'
                        error("❌ Security gate failed — Critical CVEs: ${critical}, Secrets: ${secrets}")
                    } else {
                        echo "✅ Security gate passed."
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'security-reports/**', allowEmptyArchive: true
            publishHTML(target: [
                allowMissing         : true,
                alwaysLinkToLastBuild: true,
                keepAll              : true,
                reportDir            : 'security-reports',
                reportFiles          : 'summary.json',
                reportName           : 'Security Scan Summary'
            ])
        }
        failure {
            emailext(
                subject: "❌ Security Scan FAILED — ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                body: """
Security scan failed for build ${env.BUILD_NUMBER}.

Branch: ${env.GIT_BRANCH}
Commit: ${env.GIT_COMMIT}

Check the build artifacts for full details:
${env.BUILD_URL}artifact/security-reports/

Review and fix all Critical CVEs and exposed secrets before merging.
                """,
                to: "${env.CHANGE_AUTHOR_EMAIL}",
                mimeType: 'text/plain'
            )
        }
        success {
            echo "✅ All security checks passed."
        }
    }
}
```

### Jenkins Credentials Setup

In **Manage Jenkins → Credentials**, add:

| ID | Type | Description |
|----|------|-------------|
| `nvd-api-key` | Secret text | NVD API key |
| `cyberstrike-license` | Secret text | CyberStrikeAI license |
| `semgrep-app-token` | Secret text | Semgrep token |
| `sonarqube-token` | Secret text | SonarQube auth token |

### Required Jenkins Plugins

- Pipeline
- Email Extension
- SonarQube Scanner
- HTML Publisher
- Credentials Binding

---

## Secret Management

### General Principles

1. **Never hardcode secrets** in pipeline YAML or Jenkinsfiles.
2. **Use platform-native secret stores** (GitHub Secrets, GitLab CI Variables, Azure Key Vault, Jenkins Credentials).
3. **Rotate secrets** immediately if detected by Gitleaks.
4. **Limit secret scope** — use environment-specific secrets (dev/staging/prod).

### Fail/Pass Logic

| Condition | Default Behavior |
|-----------|-----------------|
| Critical CVEs found | ❌ Fail pipeline |
| High CVEs only | ⚠️ Warning, pass |
| Secrets found | ❌ Fail pipeline |
| SAST findings | ⚠️ Warning (configurable) |

Override in config:
```yaml
# ~/.cyberstrike/config.yaml
fail_on_critical: true
fail_on_secrets: true
fail_on_high: false
sast_fail_threshold: 10  # fail if more than N SAST findings
```

### Notification Channels

- **GitHub**: Automatic PR comments (via `actions/github-script`)
- **GitLab**: MR notes via API
- **Azure DevOps**: Build annotations + artifact publishing
- **Jenkins**: Email via `emailext` plugin + Slack (add `slackSend` step)

For Slack notifications (all platforms), add:
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"❌ Security scan failed on '"$BRANCH"' — Critical CVEs: '"$CRITICAL"'"}' \
  "$SLACK_WEBHOOK_URL"
```
