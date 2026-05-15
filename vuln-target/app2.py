"""
vuln-target/app2.py — Appli web vulnérable v2 (cible de test IA)
Failles : SQLi, XSS stocké, IDOR, auth bypassable, secret hardcodé
Usage: python3 app2.py  →  http://localhost:5001
"""
from flask import Flask, request, render_template_string, redirect, jsonify, session
import sqlite3, os, hashlib

app = Flask(__name__)
app.secret_key = "supersecret123"   # ❌ secret hardcodé

# ── DB en mémoire ────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("/tmp/vulnapp2.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS notes  (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, content TEXT)")
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin','admin@corp.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','alice123','user','alice@corp.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3,'bob','bob123','user','bob@corp.com')")
    c.execute("INSERT OR IGNORE INTO notes VALUES (1,1,'Secret Plan','Budget Q4: 2.4M€ — confidentiel')")
    c.execute("INSERT OR IGNORE INTO notes VALUES (2,2,'Alice note','Ma note perso')")
    conn.commit(); conn.close()

init_db()

STYLE = """<style>
body{font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:0}
.nav{background:#161b22;padding:1em 2em;display:flex;gap:1em;align-items:center}
.nav a{color:#58a6ff;text-decoration:none}.nav b{color:#f0883e;margin-left:auto}
.box{max-width:900px;margin:2em auto;padding:0 1em}
h1{color:#f0883e}h2{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:.3em}
input,textarea{background:#21262d;color:#e6edf3;border:1px solid #30363d;padding:.5em;border-radius:4px;width:100%}
button,input[type=submit]{background:#238636;color:#fff;border:none;padding:.5em 1.5em;border-radius:4px;cursor:pointer;width:auto}
pre{background:#161b22;padding:1em;border-radius:4px;overflow-x:auto}
table{border-collapse:collapse;width:100%}th{background:#21262d;padding:.5em 1em;text-align:left}
td{border:1px solid #30363d;padding:.5em 1em}.warn{color:#f85149;font-weight:bold}
.ok{color:#3fb950}.card{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1em;margin:.5em 0}
</style>"""

BASE = STYLE + """<div class="nav">
  <a href="/">🏠 Home</a>
  <a href="/login">🔐 Login</a>
  <a href="/notes">📝 Notes</a>
  <a href="/users">👥 Users</a>
  <a href="/search">🔍 Search</a>
  <a href="/comment">💬 Comments</a>
  <b class="warn">⚠️ Intentionally Vulnerable</b>
</div><div class="box">"""

@app.route("/")
def index():
    return BASE + """
<h1>🎯 VulnApp v2 — Test Target</h1>
<p class="warn">Site intentionnellement vulnérable — ne pas déployer en production</p>
<table>
<tr><th>Endpoint</th><th>Faille</th><th>Exemple d'attaque</th></tr>
<tr><td><a href="/search?q=alice">/search?q=</a></td><td>🔴 SQL Injection</td><td>/search?q=' OR '1'='1' --</td></tr>
<tr><td><a href="/comment">/comment (POST)</a></td><td>🔴 XSS Stocké</td><td>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</td></tr>
<tr><td><a href="/notes?user_id=1">/notes?user_id=</a></td><td>🔴 IDOR</td><td>Accès aux notes d'un autre user sans auth</td></tr>
<tr><td><a href="/login">/login</a></td><td>🔴 SQLi + Auth Bypass</td><td>username: admin'-- password: anything</td></tr>
<tr><td><a href="/api/users">/api/users</a></td><td>🟠 No Auth API</td><td>Liste tous les users avec emails</td></tr>
</table></div>"""

# ── SQL Injection + Auth Bypass ───────────────────────────────────────────────
@app.route("/login", methods=["GET","POST"])
def login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")
        conn = sqlite3.connect("/tmp/vulnapp2.db")
        # ❌ VULNERABLE: pas de paramétrage
        q = f"SELECT * FROM users WHERE username='{u}' AND password='{p}'"
        row = conn.execute(q).fetchone()
        conn.close()
        if row:
            session["user"] = row[1]; session["role"] = row[3]
            return redirect("/notes")
        error = f"<p class='warn'>Identifiants incorrects</p><pre>Query: {q}</pre>"
    return BASE + f"""
<h2>🔐 Connexion</h2>{error}
<form method="post">
  <label>Username</label><input name="username" placeholder="Essaie: admin'--"><br><br>
  <label>Password</label><input name="password" type="password" placeholder="N'importe quoi"><br><br>
  <input type="submit" value="Connexion">
</form></div>"""

# ── IDOR — accès aux notes sans autorisation ─────────────────────────────────
@app.route("/notes")
def notes():
    # ❌ VULNERABLE: user_id contrôlé par l'utilisateur, aucune vérif de session
    user_id = request.args.get("user_id", "2")
    conn = sqlite3.connect("/tmp/vulnapp2.db")
    rows = conn.execute(f"SELECT * FROM notes WHERE user_id={user_id}").fetchall()
    conn.close()
    cards = "".join(f"<div class='card'><b>{r[2]}</b><p>{r[3]}</p></div>" for r in rows)
    return BASE + f"""
<h2>📝 Notes de l'utilisateur #{user_id}</h2>
<p>Changer <code>?user_id=1</code> pour voir les notes de l'admin</p>
{cards or "<p>Aucune note</p>"}</div>"""

# ── XSS Stocké ───────────────────────────────────────────────────────────────
COMMENTS = []

@app.route("/comment", methods=["GET","POST"])
def comment():
    if request.method == "POST":
        name = request.form.get("name","Anonyme")
        text = request.form.get("text","")
        # ❌ VULNERABLE: stocké sans échappement
        COMMENTS.append({"name": name, "text": text})
    # ❌ VULNERABLE: affiché sans échappement via render_template_string
    items = "".join(f"<div class='card'><b>{c['name']}</b><p>{c['text']}</p></div>" for c in COMMENTS)
    return BASE + f"""
<h2>💬 Commentaires</h2>
<form method="post">
  <input name="name" placeholder="Nom"><br><br>
  <textarea name="text" rows="3" placeholder="Essaie: &lt;script&gt;alert(1)&lt;/script&gt;"></textarea><br><br>
  <input type="submit" value="Poster">
</form>
{items or "<p>Aucun commentaire</p>"}</div>"""

# ── SQL Injection (recherche) ─────────────────────────────────────────────────
@app.route("/search")
def search():
    q = request.args.get("q","")
    conn = sqlite3.connect("/tmp/vulnapp2.db")
    # ❌ VULNERABLE
    query = f"SELECT id,username,email,role FROM users WHERE username LIKE '%{q}%' OR email LIKE '%{q}%'"
    try:
        rows = conn.execute(query).fetchall()
        results = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in rows)
        out = f"<pre>Query: {query}</pre><table><tr><th>ID</th><th>User</th><th>Email</th><th>Role</th></tr>{results}</table>"
    except Exception as e:
        out = f"<pre class='warn'>Erreur SQL: {e}\nQuery: {query}</pre>"
    conn.close()
    return BASE + f"<h2>🔍 Recherche: {q}</h2>{out}</div>"

# ── No-Auth API ───────────────────────────────────────────────────────────────
@app.route("/api/users")
def api_users():
    conn = sqlite3.connect("/tmp/vulnapp2.db")
    rows = conn.execute("SELECT id,username,email,role FROM users").fetchall()
    conn.close()
    # ❌ VULNERABLE: expose données sans auth
    return jsonify([{"id":r[0],"username":r[1],"email":r[2],"role":r[3]} for r in rows])

# ── Users listing ─────────────────────────────────────────────────────────────
@app.route("/users")
def users():
    conn = sqlite3.connect("/tmp/vulnapp2.db")
    rows = conn.execute("SELECT id,username,email,role FROM users").fetchall()
    conn.close()
    items = "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>{r[2]}</td><td>{r[3]}</td></tr>" for r in rows)
    return BASE + f"""
<h2>👥 Utilisateurs</h2>
<p class="warn">Accessible sans authentification</p>
<table><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th></tr>{items}</table></div>"""

if __name__ == "__main__":
    print("🎯 VulnApp v2 démarré → http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
