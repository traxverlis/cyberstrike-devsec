#!/usr/bin/env bash
# Récupère un token de session GitHub Copilot depuis les credentials OpenClaw
TOKEN=$(cat ~/.openclaw/agents/main/agent/auth-profiles.json 2>/dev/null | \
  python3 -c "import json,sys; d=json.load(sys.stdin); print(d['profiles']['github-copilot:github']['token'])" 2>/dev/null)

if [[ -z "$TOKEN" ]]; then
  echo "❌ Token GitHub Copilot introuvable" >&2
  exit 1
fi

SESSION_TOKEN=$(curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.github.com/copilot_internal/v2/token" 2>/dev/null | \
  python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)

echo "$SESSION_TOKEN"
