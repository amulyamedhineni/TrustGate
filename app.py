from flask import Flask, render_template, request, redirect, session, url_for
import pyotp, qrcode, os, io, json, time
from datetime import timedelta, datetime
from utils.auth import load_json, save_json, generate_device_id
import requests
import base64

app = Flask(__name__)
app.secret_key = "trustgate_secret_key"
app.permanent_session_lifetime = timedelta(minutes=10)

USERS_FILE = "data/users.json"
DEVICES_FILE = "data/devices.json"
LOGS_FILE = "data/logs.json"

# ---------------------- Home ----------------------
@app.route("/")
def home():
    return redirect("/login")

# ---------------------- Signup ----------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        uname = request.form["username"]
        pwd = request.form["password"]
        users = load_json(USERS_FILE)
        if not isinstance(users, dict):
            users = {}

        if uname in users:
            return render_template("signup.html", error="Username already exists")

        otp_secret = pyotp.random_base32()
        users[uname] = {
            "password": pwd,
            "otp_secret": otp_secret,
            "role": "user"
        }
        save_json(USERS_FILE, users)
        session["temp_user"] = uname
        return redirect("/verify")

    return render_template("signup.html")

# ---------------------- Login ----------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        uname = request.form["username"]
        pwd = request.form["password"]
        users = load_json(USERS_FILE)
        if not isinstance(users, dict):
            users = {}

        if uname not in users or users[uname]["password"] != pwd:
            return render_template("login.html", error="Invalid credentials")

        session["temp_user"] = uname
        return redirect("/verify")

    return render_template("login.html")

# ---------------------- OTP Verify ----------------------
@app.route("/verify", methods=["GET", "POST"])
def verify():
    users = load_json(USERS_FILE)
    if not isinstance(users, dict):
        users = {}

    uname = session.get("temp_user")
    if not uname or uname not in users:
        return redirect("/login")

    secret = users[uname]["otp_secret"]
    totp = pyotp.TOTP(secret)

    if request.method == "POST":
        code = request.form["otp"]
        if totp.verify(code):
            session["user"] = uname
            session.pop("temp_user", None)
            return redirect("/dashboard")
        return render_template("verify.html", error="Invalid OTP")

    # Generate QR Code
    uri = totp.provisioning_uri(name=uname, issuer_name="TrustGate")
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    qr_data = base64.b64encode(buffer.getvalue()).decode()
    return render_template("verify.html", qr=qr_data)

# ---------------------- Dashboard ----------------------
@app.route("/dashboard")
def dashboard():
    uname = session.get("user")
    if not uname:
        return redirect("/login")

    users = load_json(USERS_FILE)
    if not isinstance(users, dict):
        users = {}

    user_data = users.get(uname, {})
    role = user_data.get("role", "user")

    ip = request.remote_addr
    try:
        geo = requests.get(f"http://ip-api.com/json/{ip}").json()
        location = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"
    except:
        location = "Unknown"

    log_entry = {
        "user": uname,
        "ip": ip,
        "location": location,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    logs = load_json(LOGS_FILE)
    if not isinstance(logs, list):
        logs = []
    logs.append(log_entry)
    save_json(LOGS_FILE, logs)

    return render_template("dashboard.html", user=uname, role=role, location=location)

# ---------------------- Logout ----------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# ---------------------- Register Device ----------------------
@app.route("/register-device", methods=["POST"])
def register_device():
    data = request.json
    uname = data.get("username")
    fingerprint = data.get("device_id")

    if not uname or not fingerprint:
        return {"status": "ERROR", "message": "Missing fields"}

    devices = load_json(DEVICES_FILE)
    if not isinstance(devices, dict):
        devices = {}

    if uname not in devices:
        devices[uname] = []

    if fingerprint not in devices[uname]:
        devices[uname].append(fingerprint)
        save_json(DEVICES_FILE, devices)
        return {"status": "REGISTERED", "message": "Device added"}
    else:
        return {"status": "EXISTS", "message": "Device already trusted"}

# ---------------------- Main ----------------------
if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    for f in [USERS_FILE, DEVICES_FILE, LOGS_FILE]:
        if not os.path.exists(f):
            with open(f, "w") as file:
                json.dump({} if "users" in f or "devices" in f else [], file)

    app.run(debug=True)
