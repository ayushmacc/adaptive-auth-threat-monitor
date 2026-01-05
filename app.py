from flask import Flask, render_template, request, redirect, session, abort, Response
import sqlite3, bcrypt, time, re, csv
from datetime import datetime

app = Flask(__name__)
app.secret_key = "enterprise_zero_trust_key"

ADMIN_PASSWORD = "Admin@123"

# ================= DATABASE =================

def get_db():
    return sqlite3.connect("database.db", check_same_thread=False)

def init_db():
    db = get_db()
    cur = db.cursor()

    # Registered users
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password BLOB,
        trust INTEGER DEFAULT 100,
        last_ip TEXT,
        last_device TEXT,
        last_login TEXT,
        behavior TEXT
    )
    """)

    # Unregistered / attacker activity
    cur.execute("""
    CREATE TABLE IF NOT EXISTS threat_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attempted_email TEXT,
        ip TEXT,
        device TEXT,
        time TEXT,
        threat_score INTEGER,
        reason TEXT
    )
    """)

    # Blocked entities
    cur.execute("""
    CREATE TABLE IF NOT EXISTS blocked_entities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        value TEXT UNIQUE,
        entity_type TEXT
    )
    """)

    db.commit()
    db.close()

init_db()

# ================= HELPERS =================

def valid_email(email):
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)

def is_blocked(value):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT 1 FROM blocked_entities WHERE value=?", (value,))
    blocked = cur.fetchone()
    db.close()
    return blocked is not None

def threat_score_for_unknown(ip, device, hour):
    score = 40
    reasons = []

    if hour < 6:
        score += 20
        reasons.append("Unusual access time")

    if "bot" in device.lower() or "curl" in device.lower():
        score += 30
        reasons.append("Automated tool detected")

    if "mobile" in device.lower():
        score += 10
        reasons.append("New device")

    return score, ", ".join(reasons)

# ================= GLOBAL BLOCK ENFORCEMENT =================

@app.before_request
def enforce_blocks():
    ip = request.remote_addr
    if is_blocked(ip):
        abort(403)

# ================= USER REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]

        if not valid_email(email):
            return "Invalid email format"

        if is_blocked(email):
            abort(403)

        password = bcrypt.hashpw(
            request.form["password"].encode(),
            bcrypt.gensalt()
        )

        db = get_db()
        cur = db.cursor()
        try:
            cur.execute(
                "INSERT INTO users (email, password) VALUES (?, ?)",
                (email, password)
            )
            db.commit()
        except:
            return "User already exists"

        return redirect("/")

    return render_template("register.html")

# ================= USER LOGIN =================

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"].encode()

        if not valid_email(email):
            return "Invalid email format"

        if is_blocked(email):
            abort(403)

        ip = request.remote_addr
        device = request.headers.get("User-Agent")
        hour = datetime.now().hour
        now = time.ctime()

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cur.fetchone()

        # ---- UNREGISTERED ACTOR ----
        if not user:
            score, reason = threat_score_for_unknown(ip, device, hour)
            cur.execute("""
                INSERT INTO threat_logs
                (attempted_email, ip, device, time, threat_score, reason)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (email, ip, device, now, score, reason))
            db.commit()
            return "Invalid credentials"

        # ---- REGISTERED USER ----
        if bcrypt.checkpw(password, user[2]):
            cur.execute("""
                UPDATE users
                SET last_ip=?, last_device=?, last_login=?, behavior=?
                WHERE email=?
            """, (ip, device, now, "Normal login", email))
            db.commit()

            session["user"] = email
            return redirect("/success")
        else:
            cur.execute("""
                UPDATE users SET trust=trust-20, behavior=?
                WHERE email=?
            """, ("Failed login", email))
            db.commit()
            return "Invalid credentials"

    return render_template("login.html")

# ================= SUCCESS =================

@app.route("/success")
def success():
    if "user" not in session:
        return redirect("/")
    return render_template("success.html", user=session["user"])

# ================= ADMIN LOGIN =================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form["password"] == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin/dashboard")
        return "Invalid admin password"

    return render_template("admin_login.html")

# ================= ADMIN DASHBOARD =================

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        return redirect("/admin")

    db = get_db()
    cur = db.cursor()

    cur.execute("SELECT email, trust, last_ip, behavior FROM users")
    users = cur.fetchall()

    cur.execute("""
        SELECT attempted_email, ip, threat_score, reason
        FROM threat_logs ORDER BY threat_score DESC
    """)
    threats = cur.fetchall()

    cur.execute("SELECT value FROM blocked_entities")
    blocked = cur.fetchall()

    return render_template(
        "admin_dashboard.html",
        users=users,
        threats=threats,
        blocked=blocked
    )

# ================= ADMIN BLOCK =================

@app.route("/admin/block", methods=["POST"])
def admin_block():
    if not session.get("admin"):
        abort(403)

    value = request.form["value"]
    entity_type = request.form["type"]

    db = get_db()
    cur = db.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO blocked_entities (value, entity_type)
        VALUES (?, ?)
    """, (value, entity_type))
    db.commit()

    return redirect("/admin/dashboard")

# ================= AUDIT LOG EXPORT (CSV) =================

@app.route("/admin/export/<log_type>")
def export_logs(log_type):
    if not session.get("admin"):
        abort(403)

    db = get_db()
    cur = db.cursor()

    if log_type == "users":
        cur.execute("""
            SELECT email, trust, last_ip, last_device, last_login, behavior
            FROM users
        """)
        rows = cur.fetchall()
        headers = ["Email", "Trust", "IP", "Device", "Login Time", "Behavior"]
        filename = "registered_users_audit.csv"

    elif log_type == "threats":
        cur.execute("""
            SELECT attempted_email, ip, device, time, threat_score, reason
            FROM threat_logs
        """)
        rows = cur.fetchall()
        headers = ["Email Attempted", "IP", "Device", "Time", "Threat Score", "Reason"]
        filename = "threat_activity_audit.csv"

    else:
        abort(404)

    def generate():
        yield ",".join(headers) + "\n"
        for row in rows:
            yield ",".join([str(i) if i else "" for i in row]) + "\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

# ================= LOGOUT =================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ================= RUN =================

print("🔥 Adaptive Authentication & Threat Monitoring System Running")

if __name__ == "__main__":
    app.run(debug=True)
