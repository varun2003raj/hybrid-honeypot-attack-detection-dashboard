 
import sqlite3
from flask import Flask, render_template, request, session, redirect
from datetime import datetime
from zoneinfo import ZoneInfo
# ---------------- AUTO RISK SCORING ENGINE ----------------
def auto_risk_score(text):
    text = text.lower()
    score = 0

    if "whoami" in text:
        score += 3
    if "ls" in text:
        score += 2
    if "pwd" in text:
        score += 1
    if "cat" in text:
        score += 4
    if "or 1=1" in text:
        score += 8
    if "<script>" in text:
        score += 8
    if "../" in text:
        score += 8
    if "rm -rf" in text:
        score += 10

    return score

def ssh_risk_score(log_line):
    log_line = log_line.lower()
    score = 0

    if "whoami" in log_line:
        score += 3
    if "ls" in log_line:
        score += 2
    if "pwd" in log_line:
        score += 1
    if "cat" in log_line:
        score += 5
    if "/etc/passwd" in log_line:
        score += 10
    if "rm -rf" in log_line:
        score += 15
    if "chmod" in log_line:
        score += 5

    return score

# -----------sql xss attack ----------------

def detect_attack(text):
    text = text.lower()

    XSS = ["<script>", "</script>", "alert(", "onerror="]
    SQLI = [" or 1=1", "--", "drop", "select", "union"]
    LFI = ["../", "..\\", "/etc/passwd"]
    CMD = [";", "&&", "|", "whoami", "ls", "cat"]

    # XSS FIRST
    if any(p in text for p in XSS):
        return "XSS Attack", 35

    # SQLi
    if any(p in text for p in SQLI):
        return "SQL Injection", 40

    # LFI
    if any(p in text for p in LFI):
        return "LFI Attack", 45

    # Command Injection
    if any(p in text for p in CMD):
        return "Command Injection", 50

    return "Clean", 0

app = Flask(__name__, template_folder="template")
app.secret_key = "secret123"

attempts = {}
blocked_ips = []
alerts = []

# ---------------- DATABASE INIT ----------------
def init_db():
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        time TEXT,
        ip TEXT,
        username TEXT,
        password TEXT,
        risk INTEGER,
        status TEXT,
        reason TEXT,
        attack_type TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()
def add_alert(ip, attack_type, risk, reason):
    global alerts

    alerts.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "attack_type": attack_type,
        "risk": risk,
        "reason": reason
    })
# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("login.html")

# ---------------- LOGIN ----------------

@app.route("/login", methods=["POST"])
def login():
    username = request.values.get("username", "").strip()
    password = request.values.get("password", "").strip()
    ip_address = request.remote_addr
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    risk_score = 0
    status = "NORMAL ATTEMPT"

    reason = "Normal activity"

    # ---------------- ATTACK DETECTION ----------------
    full_input = username + " " + password
    attack_type, attack_risk = detect_attack(full_input)
    show_popup = False
    if attack_type != "Clean":
        show_popup = True
    # ---------------- MILESTONE 20 AUTO RISK ADD ----------------
    auto_score = auto_risk_score(full_input)
    risk_score += auto_score

    # empty check
    if username == "" and password == "":
        return render_template("login.html", error="Enter username and password")

    if username == "":
        return render_template("login.html", error="Enter username")

    if password == "":
        return render_template("login.html", error="Enter password")
    # blocked IP
    if ip_address in blocked_ips:
        risk_score = 100
        status = "BLOCKED IP"
        reason = "IP previously blocked"

        return "Access Denied. Your IP is blocked."

    # attempt tracking
    if ip_address not in attempts:
        attempts[ip_address] = 1
    else:
        attempts[ip_address] += 1

# suspicious username
    if username.lower() in ["admin", "root", "administrator", "test"] and not (username == "admin" and password == "admin123"):
        reason = "Suspicious username used"

    # risk logic

    # 🚫 6th attempt → BLOCK IMMEDIATELY
    if attempts[ip_address] >= 6:

        if ip_address not in blocked_ips:
            blocked_ips.append(ip_address)

        risk_score = 100
        status = "BLOCKED IP"
        reason = "Too many attempts - IP blocked"

        # save block log immediately
        conn = sqlite3.connect("honeypot.db")
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO logs (time, ip, username, password, risk, status, reason, attack_type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            time,
            ip_address,
            username,
            password,
            risk_score,
            status,
            reason,
            attack_type
        ))

        conn.commit()
        conn.close()

        return "Access Denied. Your IP is blocked."

    # ✅ 5th attempt → allow honeypot login
    elif attempts[ip_address] == 5:
        status = "HONEYPOT ACCESS"
        risk_score = 80
        reason = "Attacker allowed into honeypot"

    # ⚠️ 4th attempt → brute force alert
    elif attempts[ip_address] == 4:
        status = "BRUTE FORCE DETECTED"
        risk_score = 70
        reason = "Multiple failed attempts detected"

    # ⚠️ 2–3 attempts
    elif attempts[ip_address] >= 2:
        status = "SUSPICIOUS ACTIVITY"
        risk_score = 40

    # normal
    else:
        status = "NORMAL ATTEMPT"
        risk_score = 10

    # 🔥 Override status if attack detected
    if attack_type != "Clean":

        if attack_type == "SQL Injection":
            status = "SQL INJECTION ATTEMPT"

        elif attack_type == "XSS Attack":
            status = "XSS ATTEMPT"

        elif attack_type == "LFI Attack":
            status = "LFI ATTEMPT"

        elif attack_type == "Command Injection":
            status = "COMMAND INJECTION"

        reason = f"{attack_type} detected"

        # increase risk but keep realistic
        risk_score += attack_risk

    # ---------------- ADD ATTACK RISK ----------------
    if username == "admin" and password == "admin123":
        status = "REAL LOGIN SUCCESS"
        risk_score = 0
        reason = "Valid admin login"


    # 🔒 LIMIT RISK
    if risk_score > 100:
        risk_score = 100
    # 🚨 ALERT TRIGGER
    if risk_score >= 40 and username != "admin":
        add_alert(
            ip_address,
            attack_type if attack_type != "Clean" else status,
            risk_score,
            reason
        )

# ---------------- SAVE TO DATABASE ----------------
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs (time, ip, username, password, risk, status, reason, attack_type)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (time, ip_address, username, password, risk_score, status, reason, attack_type))

    conn.commit()
    conn.close()

    # REAL LOGIN
    if username == "admin" and password == "admin123":
        attempts[ip_address] = 0
        session["logged_in"] = True

        # 🔥 FIX: prevent popup spam

        return render_template(
            "dashboard.html",
            username=username,
            show_popup=show_popup
        )

    if attempts[ip_address] == 5:
        session["logged_in"] = True

        # 🔥 FIX: prevent popup spam

        return render_template(
            "dashboard.html",
            username=username,
            show_popup=show_popup
        )

    if attack_type == "Clean":
        add_alert(
            ip_address,
            "FAILED LOGIN",
            20,
            "Invalid username or password attempt"
        )

    return render_template("login.html", error="Invalid username or password")

# ---------------- ADMIN ----------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        password = request.form.get("password")

        if password == "admin@123":
            conn = sqlite3.connect("honeypot.db")
            cursor = conn.cursor()

            cursor.execute("""
            SELECT time, ip, username, password, risk, status, reason, attack_type
            FROM logs
            ORDER BY id DESC
            """)

            logs = cursor.fetchall()
            conn.close()

            return render_template("admin.html", logs=logs)

        return render_template("admin_login.html", error="Wrong Password")

    return render_template("admin_login.html")

# ===== MILESTONE 15: CSV EXPORT =====
@app.route("/export")
def export_csv():

    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT time, ip, username, password, risk, status, reason, attack_type
    FROM logs
    ORDER BY id DESC
    """)

    data = cursor.fetchall()
    conn.close()

    import csv
    from flask import Response

    def generate():
        yield "time,ip,username,password,risk,status,reason,attack_type\n"
        for row in data:
            yield ",".join(str(x) for x in row) + "\n"

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=honeypot_logs.csv"})

# ===== DAILY SUMMARY =====
@app.route("/summary")
def summary():

    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT status, COUNT(*) 
    FROM logs 
    GROUP BY status
    """)

    stats = cursor.fetchall()
    conn.close()

    return render_template("summary.html", stats=stats)



# ---------------- FAKE ADMIN TRAPS ----------------
@app.route("/wp-admin")
@app.route("/phpmyadmin")
@app.route("/administrator")
@app.route("/admin-panel")
def fake_admin_trap():

    ip_address = request.remote_addr
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs (time, ip, username, password, risk, status, reason, attack_type)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        time,
        ip_address,
        "VISITOR",
        "-",
        80,
        "TRAP HIT",
        "Sensitive admin page scan detected",
        "ADMIN TRAP"
    ))

    conn.commit()
    conn.close()
#fake terminal trap that portion
    return "<h2>Admin Panel</h2><p>Access Denied</p>"

# ---------------- FAKE TERMINAL TRAP ----------------
# ---------------- FAKE TERMINAL PAGE ----------------

@app.route("/terminal")
def terminal():
    if not session.get("logged_in"):
        return redirect("/")
    return render_template("terminal.html")

# ---------------- TERMINAL API (MAIN LOGIC) ----------------
@app.route("/terminal_api", methods=["POST"])
def terminal_api():

    data = request.get_json()
    cmd = data.get("cmd", "").strip()

    ip_address = request.remote_addr
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---------------- LOG TO DATABASE ----------------
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO logs (time, ip, username, password, risk, status, reason, attack_type)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        time,
        ip_address,
        "VISITOR",
        cmd,
        90,
        "TERMINAL TRAP",
        "Fake terminal command captured",
        "COMMAND TRAP"
    ))

    conn.commit()
    conn.close()

    # ---------------- COMMAND OUTPUT ----------------
    if cmd == "whoami":
        output = "root"

    elif cmd == "pwd":
        output = "/root"

    elif cmd == "hostname":
        output = "kali-server"

    elif cmd == "uname":
        output = "Linux"

    elif cmd == "uname -a":
        output = "Linux kali-server 6.1.0-amd64 x86_64 GNU/Linux"

    elif cmd == "ls":
        output = "secret.txt logs.sh backup.zip"

    elif cmd == "ls -la":
        output = ". .. .bashrc secret.txt logs.sh backup.zip"

    elif cmd == "id":
        output = "uid=0(root) gid=0(root)"

    elif cmd == "ifconfig":
        output = "eth0 inet 192.168.1.10"

    elif cmd == "ip a":
        output = "eth0 inet 192.168.1.10/24"

    elif cmd == "ps":
        output = "1 init\n245 sshd\n512 apache2"

    elif cmd == "netstat":
        output = "tcp 0 0 0.0.0.0:22 LISTEN"

    elif cmd == "df -h":
        output = "/dev/sda1 50G 20G 28G"

    elif cmd == "free -m":
        output = "Mem: 2048 1024 1024"

    elif cmd == "uptime":
        output = "up 5 days"

    elif cmd == "date":
        output = "Sun May 03 11:45:00 IST 2026"

    elif cmd == "cat /etc/passwd":
        output = "root:x:0:0:root:/root:/bin/bash"

    elif cmd == "sudo su":
        output = "already root"

    elif cmd == "rm -rf /":
        output = "permission denied"

    elif cmd == "exit":
        output = "logout"

    elif cmd == "clear":
        return {"clear": True}

    else:
        output = "command not found"

    return {"output": output}

# ---------------FILE UPLOAD TRAP-----

@app.route("/upload", methods=["GET", "POST"])
def upload():

    if request.method == "POST":

        file = request.files.get("file")
        ip_address = request.remote_addr
        time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if file:
            filename = file.filename.lower()

            # suspicious extensions
            dangerous = [".php", ".exe", ".sh", ".py", ".jsp"]

            if any(filename.endswith(ext) for ext in dangerous):
                risk = 90
                status = "FILE UPLOAD ATTACK"
                reason = "Suspicious file uploaded"
                attack_type = "FILE UPLOAD"
            else:
                risk = 30
                status = "FILE UPLOAD"
                reason = "Normal file upload"
                attack_type = "FILE UPLOAD"

            # save to DB
            conn = sqlite3.connect("honeypot.db")
            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO logs (time, ip, username, password, risk, status, reason, attack_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                time,
                ip_address,
                "VISITOR",
                filename,
                risk,
                status,
                reason,
                attack_type
            ))

            conn.commit()
            conn.close()

            return "<h3>File uploaded successfully</h3>"

    return render_template("upload.html")

@app.route("/alerts")
def show_alerts():
    return render_template("alerts.html", alerts=alerts)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ---------------- SSH LOGS VIEWER ----------------
import subprocess

@app.route("/ssh_logs")
def ssh_logs():

    import os

    result = os.popen(
        "docker logs --tail 100 cowrie 2>&1"
    ).read()

    raw_logs = result.splitlines()[-20:]

    ssh_data = []
    alerts_local = []

    for line in reversed(raw_logs):

        if line.strip() == "":
            continue

        try:
            utc_time = line.split(" ")[0]

            try:
                dt = datetime.strptime(
                    utc_time,
                    "%Y-%m-%dT%H:%M:%S.%f+0000"
                )
            except:
                dt = datetime.strptime(
                    utc_time,
                    "%Y-%m-%dT%H:%M:%S+0000"
                )


            dt = dt.replace(tzinfo=ZoneInfo("UTC"))

            ist_time = dt.astimezone(
                ZoneInfo("Asia/Kolkata")
            )

            ist_time_str = ist_time.strftime(
                "%d-%m-%Y %I:%M:%S %p IST"
            )

            line = " ".join(line.split(" ")[1:])

            line = f"{ist_time_str} | {line}"

        except:
            pass


        if "Command found:" in line:
            continue

        risk = ssh_risk_score(line)

        ssh_data.append({
            "log": line,
            "risk": risk
        })

        if risk >= 3:
            alerts_local.append({
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "SSH ATTACK",
                "risk": risk,
                "reason": "Suspicious SSH command detected"
            })

    print(ssh_data)

    return render_template(
        "ssh_logs.html",
        ssh_data=ssh_data,
        alerts=alerts_local
    )

@app.route("/hybrid_dashboard")
def hybrid_dashboard():

    # WEB LOGS
    conn = sqlite3.connect("honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT time, ip, username, risk, status, reason, attack_type
    FROM logs
    ORDER BY id DESC
    LIMIT 20
    """)

    web_logs = cursor.fetchall()
    conn.close()

    # SSH LOGS
    result = subprocess.run(
        ["docker", "logs", "cowrie"],
        capture_output=True,
        text=True
    )

    raw_logs = result.stdout.split("\n")[-30:]
    raw_logs.reverse()

    ssh_logs = []

    for line in raw_logs:

        if line.strip() == "":
            continue

        try:
            utc_time = line.split(" ")[0]

            try:
                dt = datetime.strptime(
                    utc_time,
                    "%Y-%m-%dT%H:%M:%S.%f+0000"
                )
            except:
                dt = datetime.strptime(
                    utc_time,
                    "%Y-%m-%dT%H:%M:%S+0000"
                )

            dt = dt.replace(tzinfo=ZoneInfo("UTC"))

            ist_time = dt.astimezone(
                ZoneInfo("Asia/Kolkata")
            )

            ist_time_str = ist_time.strftime(
                "%d-%m-%Y %I:%M:%S %p IST"
            )

            line = " ".join(line.split(" ")[1:])

            line = f"{ist_time_str} | {line}"

        except:
            pass

        ssh_logs.append(line)

    return render_template(
        "hybrid_dashboard.html",
        web_logs=web_logs,
        ssh_logs=ssh_logs
    )

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
