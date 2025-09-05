from flask import Flask, render_template, request, redirect, session, url_for
import time
import pickle
import json
import os
import requests
from datetime import datetime
import random
from abuse_check import get_full_ip_analysis, batch_analyze_ips

app = Flask(__name__)
app.secret_key = "secret_key"

# Load the AI model
model = pickle.load(open("intrusion_model.pkl", "rb"))

# AbuseIPDB settings
ABUSEIPDB_API_KEY = "e44a649fbd881df243036ab4234032e9673c41993acd2689826a2056fc7dec159b6de091db24af05"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Honey credentials - common usernames/passwords that attackers might try
HONEY_CREDENTIALS = [
    {"username": "test", "password": "test123", "level": "low"},
    {"username": "admin", "password": "password", "level": "admin"},
    {"username": "administrator", "password": "admin", "level": "admin"},
    {"username": "root", "password": "toor", "level": "system"},
    {"username": "demo", "password": "demo", "level": "low"},
    {"username": "user1", "password": "user1", "level": "low"},
    {"username": "guest", "password": "guest", "level": "guest"},
    {"username": "dbadmin", "password": "mysql", "level": "database"}
]

# In-memory structures
attempts = {}
blocked_ips = {}

# Load blocked IPs from file
if os.path.exists("blocked_ips.json"):
    with open("blocked_ips.json", "r") as f:
        blocked_ips = json.load(f)

def save_blocked_ips():
    with open("blocked_ips.json", "w") as f:
        json.dump(blocked_ips, f)

def log_login(ip, status, username):
    log_entry = {
        "ip": ip,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user": username,
        "status": status
    }
    os.makedirs("logs", exist_ok=True)
    with open("logs/access.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def is_abusive_ip(ip):
    try:
        response = requests.get(ABUSEIPDB_URL, headers={"Key": ABUSEIPDB_API_KEY}, params={"ipAddress": ip})
        result = response.json()
        score = result["data"]["abuseConfidenceScore"]
        return score >= 50
    except:
        return False

def is_honey_credential(username, password):
    """Check if the provided credentials match any of our honey credentials"""
    for cred in HONEY_CREDENTIALS:
        if cred["username"] == username and cred["password"] == password:
            return cred
    return None

@app.route("/", methods=["GET", "POST"])
def login():
    ip = request.remote_addr
    start_time = session.get("start_time", time.time())
    elapsed = time.time() - start_time

    # Restore blocking mechanism
    if ip in blocked_ips and time.time() < blocked_ips[ip]:
        return render_template("login.html", error="Can't login. Please try after 30 minutes.")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        attempts[ip] = attempts.get(ip, 0) + 1

        # Check if these are honey credentials
        honey_cred = is_honey_credential(username, password)
        if honey_cred:
            log_login(ip, f"Honey Credential Hit ({honey_cred['level']})", username)
            session['logged_in'] = True
            session['username'] = username
            session['honey_level'] = honey_cred['level']
            session['honey_user'] = True
            # Redirect to the appropriate honeypot based on privilege level
            return redirect(url_for('honeypot_user_dashboard'))

        # Check AbuseIPDB
        if is_abusive_ip(ip):
            blocked_ips[ip] = time.time() + 1800
            save_blocked_ips()
            log_login(ip, "Confirmed Attacker (AbuseIPDB)", username)
            return render_template("login.html", error="Login failed. Cannot proceed further.")

        # AI prediction
        prediction = model.predict([[attempts[ip], elapsed]])[0]

        # Handle excessive time or attempts
        if elapsed > 30 or attempts[ip] >= 4:
            blocked_ips[ip] = time.time() + 1800
            save_blocked_ips()
            log_login(ip, "Suspected Attacker (delay/attempts)", username)
            return render_template("login.html", error="Can't login. Please try after 30 minutes.")

        if prediction == 1:
            log_login(ip, "Suspected Attacker (AI)", username)
            return render_template("login.html", error="Can't login. Please try after 30 minutes.")

        if username == "user" and password == "user123":
            log_login(ip, "Normal User Attempt", username)
            # Revert back to not allowing user login
            return render_template("login.html", error="Login failed. Please try again.")

        if username == "admin" and password == "admin123":
            log_login(ip, "Admin Login", username)
            session['logged_in'] = True
            session['username'] = username
            return redirect(url_for('dashboard'))

        log_login(ip, "Login unauthorized", username)
        return render_template("login.html", error="Login unauthorized.")

    session["start_time"] = time.time()
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    # Check if user is logged in
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    logs = []
    if os.path.exists("logs/access.log"):
        with open("logs/access.log") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    entry["status_class"] = (
                        "attacker" if "Attacker" in entry["status"] else
                        "suspicious" if "Suspected" in entry["status"] else
                        "normal"
                    )
                    logs.append(entry)
                except:
                    continue
    return render_template("dashboard.html", logs=logs)

@app.route("/ip-checker", methods=["GET", "POST"])
def ip_checker():
    # Restore auth restriction
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    ip_info = None
    batch_results = None
    if request.method == "POST":
        # Check if it's a single IP or batch analysis
        if "ip" in request.form:
            ip_to_check = request.form["ip"]
            # Use the enhanced IP intelligence function
            ip_info = get_full_ip_analysis(ip_to_check)
        elif "ip_list" in request.form:
            # Handle batch analysis
            ip_list = [ip.strip() for ip in request.form["ip_list"].split("\n") if ip.strip()]
            if ip_list:
                batch_results = batch_analyze_ips(ip_list)

    return render_template("ip_checker.html", ip_info=ip_info, batch_results=batch_results)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

# Honeypot Routes
@app.route("/admin/config", methods=["GET", "POST"])
def honeypot_admin():
    """Fake admin configuration page that logs all access attempts"""
    ip = request.remote_addr
    log_honeypot_hit(ip, "admin config", request.method, request.form if request.method == "POST" else None)
    
    if request.method == "POST":
        return render_template("honeypot/admin_success.html")
    
    return render_template("honeypot/admin_config.html")

@app.route("/api/v1/users", methods=["GET"])
def honeypot_api_users():
    """Fake API endpoint that returns user data - honeypot to detect scraping attempts"""
    ip = request.remote_addr
    log_honeypot_hit(ip, "API users endpoint", "GET", None)
    
    # Return fake user data as JSON
    fake_users = [
        {"id": 1, "username": "admin", "email": "admin@example.com", "role": "admin"},
        {"id": 2, "username": "test", "email": "test@example.com", "role": "user"},
        {"id": 3, "username": "guest", "email": "guest@example.com", "role": "guest"}
    ]
    return json.dumps({"users": fake_users}), 200, {'Content-Type': 'application/json'}

@app.route("/api/v1/login", methods=["POST"])
def honeypot_api_login():
    """Fake API login endpoint - honeypot to detect bruteforce attempts"""
    ip = request.remote_addr
    data = request.get_json(silent=True) or {}
    log_honeypot_hit(ip, "API login endpoint", "POST", data)
    
    # Always return auth failed with fake token
    return json.dumps({"status": "error", "message": "Invalid credentials"}), 401, {'Content-Type': 'application/json'}

@app.route("/backup/files")
def honeypot_backup():
    """Fake backup files directory - honeypot to detect directory traversal attempts"""
    ip = request.remote_addr
    params = dict(request.args)
    log_honeypot_hit(ip, "backup files", "GET", params)
    
    return render_template("honeypot/backup_files.html")

@app.route("/phpmyadmin")
def honeypot_phpmyadmin():
    """Fake phpMyAdmin page to trap attackers looking for default installations"""
    ip = request.remote_addr
    log_honeypot_hit(ip, "phpMyAdmin", "GET", None)
    
    # Redirect to login page after logging the attempt
    return redirect(url_for('login'))

def log_honeypot_hit(ip, honeypot_type, method, data):
    """Log honeypot access attempts"""
    # Check if IP is already known to be malicious
    is_suspicious = is_abusive_ip(ip) or ip in blocked_ips
    
    # Record honeypot hit
    honeypot_entry = {
        "ip": ip,
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "honeypot": honeypot_type,
        "method": method,
        "data": str(data) if data else "None",
        "is_suspicious": is_suspicious
    }
    
    os.makedirs("logs/honeypot", exist_ok=True)
    with open("logs/honeypot/access.log", "a") as f:
        f.write(json.dumps(honeypot_entry) + "\n")
    
    # Auto-block IPs that hit multiple honeypots
    honeypot_hits = count_honeypot_hits(ip)
    if honeypot_hits >= 2 and ip not in blocked_ips:
        blocked_ips[ip] = time.time() + 3600  # Block for 1 hour
        save_blocked_ips()

def count_honeypot_hits(ip):
    """Count how many honeypots this IP has triggered"""
    count = 0
    if os.path.exists("logs/honeypot/access.log"):
        with open("logs/honeypot/access.log") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if entry["ip"] == ip:
                        count += 1
                except:
                    continue
    return count

# Honeypot Management Dashboard
@app.route("/honeypot-dashboard")
def honeypot_dashboard():
    # Only show to logged in users
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    # Load all honeypot logs
    logs = []
    if os.path.exists("logs/honeypot/access.log"):
        with open("logs/honeypot/access.log") as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except:
                    continue
    
    # Prepare stats
    stats = {
        "total_hits": len(logs),
        "unique_ips": len(set(log["ip"] for log in logs)),
        "blocked_count": len(blocked_ips),
        "honeypot_types": {}
    }
    
    # Count hits per honeypot type
    for log in logs:
        honeypot = log.get("honeypot", "unknown")
        stats["honeypot_types"][honeypot] = stats["honeypot_types"].get(honeypot, 0) + 1
    
    return render_template("honeypot/dashboard.html", logs=logs, stats=stats)

# New credential-based honeypot routes
@app.route("/user-dashboard")
def honeypot_user_dashboard():
    """Fake user dashboard for honey credential logins"""
    # Ensure this is a honey user
    if not session.get('honey_user'):
        return redirect(url_for('login'))
    
    ip = request.remote_addr
    level = session.get('honey_level', 'low')
    username = session.get('username', 'unknown')
    
    # Log the access
    log_honeypot_hit(ip, f"credential-based dashboard ({level})", "GET", {"username": username})
    
    # Add a slight delay to waste attacker time (0.5-2 seconds)
    time.sleep(0.5 + random.random() * 1.5)
    
    # Get current time for templates
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Show different dashboards based on privilege level
    if level == "admin" or level == "system":
        return render_template("honeypot/admin_dashboard.html", username=username, level=level, now=now)
    elif level == "database":
        return render_template("honeypot/db_dashboard.html", username=username, now=now)
    else:
        return render_template("honeypot/user_dashboard.html", username=username, now=now)

@app.route("/user-settings", methods=["GET", "POST"])
def honeypot_user_settings():
    """Fake user settings page for honey credential logins"""
    # Ensure this is a honey user
    if not session.get('honey_user'):
        return redirect(url_for('login'))
    
    ip = request.remote_addr
    level = session.get('honey_level', 'low')
    username = session.get('username', 'unknown')
    
    # Log the access and any submitted data
    form_data = request.form if request.method == "POST" else None
    log_honeypot_hit(ip, "user settings page", request.method, form_data)
    
    # Add slight delay
    time.sleep(0.5 + random.random() * 1.5)
    
    # Get current time for templates
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Process form if submitted
    message = None
    if request.method == "POST":
        # Pretend to update settings but don't actually do anything
        message = "Settings updated successfully!"
    
    return render_template("honeypot/user_settings.html", username=username, level=level, message=message, now=now)

@app.route("/system-config", methods=["GET", "POST"])
def honeypot_system_config():
    """Fake system configuration page only accessible to admin/system level honey users"""
    # Ensure this is a honey user with appropriate privileges
    if not session.get('honey_user'):
        return redirect(url_for('login'))
    
    level = session.get('honey_level', '')
    if level not in ["admin", "system"]:
        # Get current time for access_denied template
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return render_template("honeypot/access_denied.html", now=now)
    
    ip = request.remote_addr
    username = session.get('username', 'unknown')
    
    # Log the access and any submitted data
    form_data = request.form if request.method == "POST" else None
    log_honeypot_hit(ip, "system configuration page", request.method, form_data)
    
    # Add slight delay
    time.sleep(1 + random.random() * 2)
    
    # Get current time for templates
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Process form if submitted
    message = None
    if request.method == "POST":
        # Pretend to update system config but don't actually do anything
        message = "System configuration updated. Changes will take effect after next restart."
    
    return render_template("honeypot/system_config.html", username=username, level=level, message=message, now=now)

@app.route("/database-admin", methods=["GET", "POST"])
def honeypot_database_admin():
    """Fake database administration page only accessible to database level honey users"""
    # Ensure this is a honey user with appropriate privileges
    if not session.get('honey_user'):
        return redirect(url_for('login'))
    
    level = session.get('honey_level', '')
    if level != "database" and level not in ["admin", "system"]:
        # Get current time for access_denied template
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return render_template("honeypot/access_denied.html", now=now)
    
    ip = request.remote_addr
    username = session.get('username', 'unknown')
    
    # Log the access and any submitted data
    form_data = request.form if request.method == "POST" else None
    log_honeypot_hit(ip, "database admin page", request.method, form_data)
    
    # Add slight delay
    time.sleep(1 + random.random() * 2)
    
    # Get current time for templates
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create fake database tables and data
    fake_tables = [
        {"name": "users", "rows": 152, "last_modified": "2023-11-15"},
        {"name": "products", "rows": 347, "last_modified": "2023-12-01"},
        {"name": "orders", "rows": 1289, "last_modified": "2024-01-20"},
        {"name": "customers", "rows": 203, "last_modified": "2023-12-10"},
        {"name": "inventory", "rows": 518, "last_modified": "2024-01-05"}
    ]
    
    # Process form if submitted
    message = None
    if request.method == "POST":
        action = request.form.get("action")
        table = request.form.get("table")
        
        if action == "query":
            # Log the SQL query attempt - this could be valuable for seeing what attackers try
            sql_query = request.form.get("sql_query", "")
            log_honeypot_hit(ip, "database query", "POST", {"sql": sql_query})
            
            # Check if this appears to be an SQL injection attempt
            if "'" in sql_query or ";" in sql_query or "--" in sql_query or "/*" in sql_query:
                message = "Error 1064: You have an error in your SQL syntax"
            else:
                message = "Query executed successfully. 0 rows returned."
        
        elif action == "backup":
            message = f"Backup of table '{table}' has been scheduled."
    
    return render_template("honeypot/db_admin.html", username=username, level=level, 
                           message=message, tables=fake_tables, now=now)

@app.route("/file-manager")
def honeypot_file_manager():
    """Fake file manager page that appears to show server files"""
    # Ensure this is a honey user
    if not session.get('honey_user'):
        return redirect(url_for('login'))
    
    ip = request.remote_addr
    level = session.get('honey_level', 'low')
    username = session.get('username', 'unknown')
    
    # Only allow higher privilege users to access
    if level not in ["admin", "system"]:
        # Get current time for access_denied template
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return render_template("honeypot/access_denied.html", now=now)
    
    # Log the access
    log_honeypot_hit(ip, "file manager page", "GET", {"username": username})
    
    # Add a delay
    time.sleep(1 + random.random() * 1.5)
    
    # Get current time for templates
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate fake file listings
    fake_files = [
        {"name": "config.ini", "size": "4.2 KB", "modified": "2023-12-05", "type": "file"},
        {"name": "backup", "size": "", "modified": "2023-11-20", "type": "dir"},
        {"name": "logs", "size": "", "modified": "2024-01-22", "type": "dir"},
        {"name": "uploads", "size": "", "modified": "2024-01-15", "type": "dir"},
        {"name": "server.py", "size": "18.7 KB", "modified": "2023-10-30", "type": "file"},
        {"name": "database.sqlite", "size": "3.2 MB", "modified": "2024-01-21", "type": "file"},
        {"name": ".env", "size": "0.5 KB", "modified": "2023-09-15", "type": "file"},
        {"name": "requirements.txt", "size": "1.1 KB", "modified": "2023-09-15", "type": "file"}
    ]
    
    return render_template("honeypot/file_manager.html", username=username, level=level, files=fake_files, now=now)

@app.route("/files/view")
def honeypot_view_file():
    """Fake file viewer that shows fake file content"""
    # Ensure this is a honey user
    if not session.get('honey_user'):
        return redirect(url_for('login'))
    
    ip = request.remote_addr
    filename = request.args.get("file", "")
    
    # Log the access and the file being requested
    log_honeypot_hit(ip, "file viewer", "GET", {"filename": filename})
    
    # Add delay
    time.sleep(0.8 + random.random() * 1.2)
    
    # Get current time for templates
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate fake file content based on the requested filename
    content = "File not found or permission denied."
    
    if filename == "config.ini":
        content = """[database]
host = localhost
port = 5432
name = app_db
user = db_user
password = DB_PASSWORD_REDACTED

[server]
host = 0.0.0.0
port = 8080
debug = False
log_level = INFO

[security]
secret_key = REDACTED
token_expiry = 86400
allowed_ips = 127.0.0.1,10.0.0.0/8"""
    elif filename == ".env":
        content = """DB_PASSWORD=db_secure_password123
API_KEY=sk_test_abcdefghijklmnopqrstuvwxyz
SECRET_KEY=a1b2c3d4e5f6g7h8i9j0
DEBUG=False"""
    elif filename == "server.py":
        content = """import flask
from flask import Flask, request, session
import os
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_dev_key')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Connect to database
        conn = sqlite3.connect('database.sqlite')
        cur = conn.cursor()
        
        # Get user from database
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        
        if user and user[2] == hashlib.sha256(password.encode()).hexdigest():
            session['logged_in'] = True
            session['username'] = username
            return redirect('/dashboard')
    
    return render_template('login.html')

# More routes..."""
    
    return render_template("honeypot/file_viewer.html", filename=filename, content=content, now=now)

if __name__ == "__main__":
    app.run(debug=True)
