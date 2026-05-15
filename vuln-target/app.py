"""
vuln-target/app.py — Site HTTP intentionnellement vulnérable
Usage: python3 app.py
Target de test pour CyberStrikeAI DevSec Level 2

⚠️  NE PAS DÉPLOYER EN PRODUCTION ⚠️

Failles intentionnelles :
  - SQL Injection      → GET /search?q=
  - XSS réfléchi      → GET /greet?name=
  - Secret en clair   → GET /debug
  - Path traversal    → GET /file?name=
  - Commande OS       → GET /ping?host=
  - Headers absents   → tous les endpoints (pas de CSP, HSTS, etc.)
  - Info disclosure   → GET /admin (credentials en dur)
"""

import sqlite3, os, subprocess
from flask import Flask, request, render_template_string, jsonify

app = Flask(__name__)

# ── Secret hardcodé (intentionnel) ──────────────────────────────────────────
SECRET_API_KEY = "sk-prod-xK92mNpQ7rT4vL8wY3zA1bC6dE0fG5hI"
DB_PASSWORD    = "SuperSecret123!"
JWT_SECRET     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret"

# ── Base SQLite en mémoire ───────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)")
    c.execute("INSERT INTO users VALUES (1,'Alice','alice@example.com','admin')")
    c.execute("INSERT INTO users VALUES (2,'Bob','bob@example.com','user')")
    c.execute("INSERT INTO users VALUES (3,'Charlie','charlie@example.com','user')")
    conn.commit()
    return conn

# ── Template de base ─────────────────────────────────────────────────────────
BASE = """
<!DOCTYPE html>
<html>
<head>
  <title>VulnApp — CyberStrikeAI Test Target</title>
  <style>
    body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 2em; }}
    h1 {{ color: #e94560; }}
    h2 {{ color: #0f3460; background:#16213e; padding:.5em; }}
    a  {{ color: #e94560; }}
    pre {{ background: #0f3460; padding: 1em; border-radius: 4px; overflow-x:auto; }}
    .warn {{ color: #f5a623; font-weight: bold; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border: 1px solid #0f3460; padding: .5em 1em; }}
    th {{ background: #0f3460; }}
    .vuln {{ background: #3a1a1a; }}
  </style>
</head>
<body>
  <h1>🎯 VulnApp — CyberStrikeAI DevSec Test Target</h1>
  <p class="warn">⚠️ Site intentionnellement vulnérable — NE PAS déployer en prod</p>
  {content}
</body>
</html>
"""

# ── Index ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    content = """
    <h2>Endpoints disponibles</h2>
    <table>
      <tr><th>Endpoint</th><th>Faille</th><th>Exemple</th></tr>
      <tr class="vuln"><td><a href="/search?q=Alice">/search?q=</a></td><td>🔴 SQL Injection</td><td>/search?q=' OR '1'='1</td></tr>
      <tr class="vuln"><td><a href="/greet?name=World">/greet?name=</a></td><td>🔴 XSS réfléchi</td><td>/greet?name=&lt;script&gt;alert(1)&lt;/script&gt;</td></tr>
      <tr class="vuln"><td><a href="/debug">/debug</a></td><td>🔴 Secret/Info disclosure</td><td>/debug</td></tr>
      <tr class="vuln"><td><a href="/file?name=passwd">/file?name=</a></td><td>🔴 Path traversal</td><td>/file?name=../../../etc/passwd</td></tr>
      <tr class="vuln"><td><a href="/ping?host=127.0.0.1">/ping?host=</a></td><td>🔴 Command injection</td><td>/ping?host=127.0.0.1;id</td></tr>
      <tr class="vuln"><td><a href="/admin">/admin</a></td><td>🟡 Credentials en dur</td><td>/admin</td></tr>
      <tr><td><a href="/api/users">/api/users</a></td><td>🟡 IDOR / No auth</td><td>/api/users</td></tr>
    </table>
    """
    return render_template_string(BASE.format(content=content))

# ── SQL Injection ─────────────────────────────────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        conn = get_db()
        # ❌ VULNERABLE: concaténation directe sans paramétrage
        query = f"SELECT * FROM users WHERE name LIKE '%{q}%' OR email LIKE '%{q}%'"
        rows = conn.execute(query).fetchall()
        results = "".join(f"<tr><td>{r['id']}</td><td>{r['name']}</td><td>{r['email']}</td><td>{r['role']}</td></tr>" for r in rows)
        content = f"""
        <h2>🔍 Recherche : {q}</h2>
        <pre>Query: {query}</pre>
        <table><tr><th>ID</th><th>Nom</th><th>Email</th><th>Rôle</th></tr>{results}</table>
        <p><a href="/">← Retour</a></p>
        """
    except Exception as e:
        content = f"<h2>Erreur SQL</h2><pre>{e}</pre><p><a href='/'>← Retour</a></p>"
    return render_template_string(BASE.format(content=content))

# ── XSS réfléchi ──────────────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    # ❌ VULNERABLE: input injecté directement dans le HTML sans échappement
    content = f"""
    <h2>👋 Bonjour !</h2>
    <p>Bienvenue, <b>{name}</b> ! Ravi de vous voir.</p>
    <form action="/greet" method="get">
      <input name="name" value="{name}" style="padding:.5em;width:300px">
      <button type="submit">Saluer</button>
    </form>
    <p><a href="/">← Retour</a></p>
    """
    return render_template_string(BASE.format(content=content))

# ── Secret / Info disclosure ──────────────────────────────────────────────────
@app.route("/debug")
def debug():
    content = f"""
    <h2>🔧 Debug Info</h2>
    <pre>
API_KEY    = {SECRET_API_KEY}
DB_PASS    = {DB_PASSWORD}
JWT_SECRET = {JWT_SECRET}
SERVER     = Flask/3.x Python/{os.sys.version.split()[0]}
ENV        = production
CWD        = {os.getcwd()}
USER       = {os.environ.get('USER','unknown')}
    </pre>
    <p><a href="/">← Retour</a></p>
    """
    return render_template_string(BASE.format(content=content))

# ── Path traversal ────────────────────────────────────────────────────────────
@app.route("/file")
def read_file():
    name = request.args.get("name", "readme.txt")
    # ❌ VULNERABLE: pas de validation du chemin
    base_dir = "/tmp/vulnapp_files"
    os.makedirs(base_dir, exist_ok=True)
    # Créer des fichiers de démo
    for fn, fc in [("readme.txt","Bienvenue sur VulnApp!"), ("config.txt","debug=true\nlog_level=verbose")]:
        open(os.path.join(base_dir, fn), "w").write(fc)

    path = os.path.join(base_dir, name)
    try:
        with open(path) as f:
            data = f.read()
        content = f"<h2>📄 Fichier : {name}</h2><pre>{data}</pre><p><a href='/'>← Retour</a></p>"
    except Exception as e:
        content = f"<h2>Erreur</h2><pre>{e}</pre><p><a href='/'>← Retour</a></p>"
    return render_template_string(BASE.format(content=content))

# ── Command injection ─────────────────────────────────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    try:
        # ❌ VULNERABLE: shell=True avec input utilisateur
        result = subprocess.check_output(f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5)
        output = result.decode()
    except subprocess.TimeoutExpired:
        output = "Timeout"
    except Exception as e:
        output = str(e)
    content = f"""
    <h2>📡 Ping : {host}</h2>
    <pre>{output}</pre>
    <form action="/ping" method="get">
      <input name="host" value="{host}" style="padding:.5em;width:300px">
      <button type="submit">Ping</button>
    </form>
    <p><a href="/">← Retour</a></p>
    """
    return render_template_string(BASE.format(content=content))

# ── Credentials en dur ────────────────────────────────────────────────────────
@app.route("/admin")
def admin():
    content = f"""
    <h2>🔐 Admin Panel</h2>
    <pre>
# Identifiants hardcodés (intentionnel)
admin_user = "admin"
admin_pass = "admin123"
backup_key = "bkp-9f2e1d8c7b6a5"
    </pre>
    <p>Connecté en tant que : <b>admin</b> (aucune vérification d'auth)</p>
    <p><a href="/">← Retour</a></p>
    """
    return render_template_string(BASE.format(content=content))

# ── API sans auth ─────────────────────────────────────────────────────────────
@app.route("/api/users")
def api_users():
    conn = get_db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    # ❌ VULNERABLE: expose tout sans authentification
    return jsonify([dict(r) for r in rows])

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🎯 VulnApp démarré sur http://localhost:5000")
    print("⚠️  Site intentionnellement vulnérable — test uniquement")
    app.run(host="0.0.0.0", port=5000, debug=False)
