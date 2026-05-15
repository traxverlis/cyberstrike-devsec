# GitHub Copilot as AI Backend for CyberStrikeAI DevSec

CyberStrikeAI supports any OpenAI-compatible provider. GitHub Copilot exposes exactly this interface, making it a zero-cost option if you already have a Copilot subscription.

## Prerequisites

- Active GitHub Copilot subscription (Individual, Business, or Enterprise)
- Personal Access Token with `copilot` scope (or use your existing Copilot token)

## Available Models via GitHub Copilot

| Model | Best For | Context |
|-------|----------|---------|
| `gpt-4o` | General analysis, report generation | 128k |
| `gpt-4o-mini` | Fast CI/CD scans, quick triage | 128k |
| `claude-sonnet-4.5` | Deep code review, COBOL analysis | 200k |
| `claude-haiku-3.5` | Ultra-fast pipeline scans | 200k |
| `o3-mini` | Complex vulnerability reasoning | 128k |
| `gemini-2.0-flash` | Speed-optimized scans | 1M |

## Configuration

### CyberStrikeAI config.yaml

```yaml
ai:
  provider: "openai-compatible"
  base_url: "https://api.githubcopilot.com"
  api_key: "${GITHUB_COPILOT_TOKEN}"
  model: "claude-sonnet-4.5"       # recommended for DevSec
  fallback_model: "gpt-4o"
  max_tokens: 4096
  temperature: 0.1                  # low temp for security analysis
  timeout: 120
```

### Environment Variables

```bash
# Linux / macOS
export GITHUB_COPILOT_TOKEN="ghp_your_token_here"

# Windows PowerShell
$env:GITHUB_COPILOT_TOKEN = "ghp_your_token_here"

# Windows CMD
set GITHUB_COPILOT_TOKEN=ghp_your_token_here
```

### Docker

```yaml
# docker-compose.yml
services:
  cyberstrike:
    environment:
      - GITHUB_COPILOT_TOKEN=${GITHUB_COPILOT_TOKEN}
      - AI_BASE_URL=https://api.githubcopilot.com
      - AI_MODEL=claude-sonnet-4.5
```

### GitHub Actions

```yaml
- name: DevSec Scan
  env:
    GITHUB_COPILOT_TOKEN: ${{ secrets.GITHUB_TOKEN }}  # Copilot uses GITHUB_TOKEN
    AI_BASE_URL: https://api.githubcopilot.com
    AI_MODEL: gpt-4o-mini  # fast model for CI
```

> **Note:** In GitHub Actions, Copilot uses the built-in `GITHUB_TOKEN` — no extra secret needed.

## Recommended Model Strategy

```
CI/CD Quick Scan    → gpt-4o-mini or claude-haiku-3.5   (speed)
Full DevSec Audit   → claude-sonnet-4.5                  (quality)
COBOL Analysis      → claude-sonnet-4.5                  (best for legacy)
Report Generation   → gpt-4o                             (writing quality)
Executive Summary   → gpt-4o                             (natural language)
```

## Model Selection per Role

Edit `roles/devsec-team.yaml` to specify model per role:

```yaml
name: "DevSec Team"
ai_model: "claude-sonnet-4.5"
ai_base_url: "https://api.githubcopilot.com"
```

Edit `roles/devsec-ci-pipeline.yaml` for fast CI:

```yaml
name: "DevSec CI Pipeline"
ai_model: "gpt-4o-mini"
ai_base_url: "https://api.githubcopilot.com"
```

## Getting Your Token

1. Go to https://github.com/settings/tokens/new
2. Select scopes: `copilot` (or use a fine-grained token)
3. Copy the token and set `GITHUB_COPILOT_TOKEN`

Or use the GitHub CLI:
```bash
gh auth token
```

## Verifying the Connection

```bash
# Test connectivity
curl -s https://api.githubcopilot.com/models \
  -H "Authorization: Bearer $GITHUB_COPILOT_TOKEN" \
  -H "Content-Type: application/json" | jq '.[].id'
```

## Why GitHub Copilot?

- ✅ **Zero extra cost** if you already have a subscription
- ✅ **Multi-model** — GPT-4o, Claude, Gemini from one token
- ✅ **Native GitHub integration** — works seamlessly in Actions
- ✅ **No data retention** — Copilot API doesn't train on your code
- ✅ **Enterprise-ready** — SOC2, GDPR compliant


## Token automatique depuis OpenClaw

Si tu utilises OpenClaw, le script `scripts/copilot-token.sh` récupère
automatiquement le token depuis la configuration OpenClaw :

```bash
export GITHUB_COPILOT_TOKEN=$(./scripts/copilot-token.sh)
./scripts/scan.sh --ai
```

## Endpoint Copilot Business

```yaml
# config.yaml
base_url: "https://api.business.githubcopilot.com"
api_key: "${GITHUB_COPILOT_TOKEN}"
model: "gpt-4o"
```

Les en-têtes requis par l'API Copilot Business sont automatiquement ajoutés
par `ai_analyzer.py` (Editor-Version, Copilot-Integration-Id).
