from flask import Flask, request, render_template_string, redirect, url_for, session, make_response
import os
import sqlite3
import bcrypt
import time

from security import (
    ensure_schema, DB,
    is_user_blocked, is_ip_blocked,
    record_failed_user_attempt, record_failed_ip_attempt,
    reset_user_attempts,
    log_event, send_email_alert,
    create_otp, verify_otp,
    MAX_USER_ATTEMPTS, MAX_IP_ATTEMPTS, USER_BLOCK_TIME, IP_BLOCK_TIME
)

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "dev_secret_change_me")


def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_user(username: str):
    ensure_schema()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT username, password, email, is_admin FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return row  # (u, hash, email, is_admin) or None


def require_admin():
    return session.get("is_admin") == 1


LOGIN_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Secure Sign-in</title>
<style>
  body{
    margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
    background:
      radial-gradient(1000px 500px at 10% 10%, rgba(34,197,94,.2), transparent 60%),
      radial-gradient(900px 500px at 90% 30%, rgba(6,182,212,.16), transparent 60%),
      linear-gradient(180deg,#050816,#0b1220);
    color:#e5e7eb;
  }
  .wrap{width:min(540px,100%);}
  .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;}
  .brand{display:flex;gap:10px;align-items:center;}
  .mark{width:42px;height:42px;border-radius:14px;background:linear-gradient(135deg,#22c55e,#06b6d4);
        display:grid;place-items:center;color:#04130a;font-weight:900;}
  .chip{font-size:12px;color:#9ca3af;border:1px solid rgba(255,255,255,.12);
        background:rgba(0,0,0,.18);padding:8px 10px;border-radius:999px;}
  .card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
        border-radius:20px;padding:20px;box-shadow:0 24px 80px rgba(0,0,0,.5);backdrop-filter: blur(12px);}
  .title{font-size:20px;font-weight:900;margin:0 0 6px;}
  .sub{margin:0 0 16px;color:#9ca3af;font-size:13px;line-height:1.5;}
  label{display:block;color:#9ca3af;font-size:12px;margin:0 0 6px;}

  .input{
    width:100%;
    padding:12px;
    border-radius:14px;
    border:1px solid rgba(255,255,255,.12);
    background:rgba(0,0,0,.25);
    color:#e5e7eb;
    outline:none;
    box-sizing:border-box;
  }
  .input:focus{border-color:rgba(34,197,94,.65);box-shadow:0 0 0 4px rgba(34,197,94,.14);}

  /* ✅ FIXED PASSWORD WRAP + PERFECT BUTTON ALIGNMENT */
  .passwordWrap{
    position:relative;
    margin-top:12px;
    width:100%;
  }
  .passwordWrap .input{
    padding-right:72px; /* space for Show button */
  }
  .toggle{
    position:absolute;
    right:10px;
    top:50%;
    transform:translateY(-50%);
    height:32px;
    display:flex;
    align-items:center;
    justify-content:center;
    border:1px solid rgba(255,255,255,.12);
    background:rgba(0,0,0,.25);
    color:#9ca3af;
    padding:0 12px;
    border-radius:10px;
    cursor:pointer;
    font-size:12px;
  }
  .toggle:hover{
    background:rgba(255,255,255,.08);
    border-color:rgba(255,255,255,.18);
  }

  .actions{display:flex;justify-content:space-between;align-items:center;margin-top:10px;font-size:12px;color:#9ca3af;}
  .actions a{color:#06b6d4;text-decoration:none;}
  .btn{width:100%;margin-top:14px;padding:12px;border-radius:14px;border:0;
       background:linear-gradient(90deg,#22c55e,#06b6d4);color:#05110b;font-weight:900;cursor:pointer;}
  .msg{margin-top:14px;padding:12px;border-radius:14px;border:1px solid rgba(255,255,255,.12);
       background:rgba(0,0,0,.25);font-size:13px;line-height:1.45;}
  .ok{border-color:rgba(34,197,94,.35);}
  .err{border-color:rgba(239,68,68,.35);}
  .warn{border-color:rgba(245,158,11,.35);}
  .pills{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px;}
  .pill{font-size:11px;border:1px solid rgba(255,255,255,.12);border-radius:999px;padding:6px 10px;color:#9ca3af;background:rgba(0,0,0,.18);}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div class="mark">SS</div>
      <div>
        <div style="font-weight:900">Secure Sign-in</div>
        <div style="font-size:12px;color:#9ca3af"> AuthSentry A Brute-Force Defense Simulator (Level 2)</div>
      </div>
    </div>
    <div class="chip">🛡️ Lockout Enabled</div>
  </div>

  <div class="card">
    <div class="title">Login</div>
    <p class="sub">User + IP rate limiting, forensic logging, OTP (2FA), and admin unblock panel.</p>

    <form method="POST" autocomplete="off">
      <label>Username</label>
      <input class="input" name="username" placeholder="admin" required value="{{prefill_user}}"/>

      <div class="passwordWrap">
        <label>Password</label>
        <input class="input" id="pw" name="password" type="password" required/>
        

      <div class="actions">
        <label style="display:flex;gap:8px;align-items:center;margin:0;">
          <input type="checkbox" name="remember" {{remember_checked}}/>
          Remember username
        </label>
        <a href="#" onclick="demoFill(); return false;">Use demo admin</a>
      </div>

      <button class="btn" type="submit">Sign in</button>
    </form>

    {% if msg %}
      <div class="msg {{cls}}">{{msg}}</div>
    {% endif %}

    <div class="pills">
      <div class="pill">User Attempts: {{max_user}}</div>
      <div class="pill">IP Attempts: {{max_ip}}</div>
      <div class="pill">User Block: {{user_block}}s</div>
      <div class="pill">IP Block: {{ip_block}}s</div>
      <div class="pill">2FA: OTP</div>
      <div class="pill">SOC: Streamlit</div>
    </div>
  </div>
</div>

<script>
function togglePw(){
  const pw = document.getElementById("pw");
  const btn = document.querySelector(".toggle");
  if(pw.type === "password"){
    pw.type="text";
    btn.textContent="Hide";
  } else {
    pw.type="password";
    btn.textContent="Show";
  }
}
function demoFill(){
  document.querySelector('input[name="username"]').value="admin";
  document.getElementById("pw").value="admin123";
}
</script>
</body>
</html>
"""

OTP_HTML = """<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>OTP</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
    background: linear-gradient(180deg,#050816,#0b1220);color:#e5e7eb;}
  .card{width:min(520px,100%);background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
        border-radius:18px;padding:18px;box-shadow:0 24px 70px rgba(0,0,0,.5);}
  label{display:block;color:#9ca3af;font-size:12px;margin:0 0 6px;}
  .input{width:100%;padding:12px;border-radius:14px;border:1px solid rgba(255,255,255,.12);
         background:rgba(0,0,0,.25);color:#e5e7eb;outline:none;box-sizing:border-box;}
  .btn{width:100%;margin-top:14px;padding:12px;border-radius:14px;border:0;
       background:linear-gradient(90deg,#22c55e,#06b6d4);color:#05110b;font-weight:900;cursor:pointer;}
  .msg{margin-top:12px;padding:10px;border-radius:12px;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.25);}
  .dev{margin-top:10px;color:#9ca3af;font-size:12px;border:1px dashed rgba(255,255,255,.18);
       padding:10px;border-radius:12px;background:rgba(0,0,0,.18);}
  a{color:#06b6d4;text-decoration:none;}
</style></head>
<body>
<div class="card">
  <h2 style="margin:0 0 8px;">🔑 OTP Verification</h2>
  <div style="color:#9ca3af;font-size:12px;">Enter the 6-digit OTP to complete login.</div>

  <form method="POST" autocomplete="off">
    <label style="margin-top:14px;">OTP</label>
    <input class="input" name="otp" placeholder="123456" required />
    <button class="btn" type="submit">Verify</button>
  </form>

  {% if msg %}<div class="msg">{{msg}}</div>{% endif %}
  {% if dev_otp %}
    <div class="dev"><b>DEV OTP:</b> {{dev_otp}} (demo only)</div>
  {% endif %}
  <div style="margin-top:10px;"><a href="/">Back to login</a></div>
</div>
</body></html>
"""

SUCCESS_HTML = """<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Success</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
    background: linear-gradient(180deg,#050816,#0b1220);color:#e5e7eb;}
  .card{width:min(620px,100%);background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
        border-radius:18px;padding:18px;box-shadow:0 24px 70px rgba(0,0,0,.5);}
  a{color:#06b6d4;text-decoration:none;}
</style></head>
<body>
<div class="card">
  <h2 style="margin:0 0 8px;">✅ Login Completed</h2>
  <div style="color:#9ca3af">User: <b>{{user}}</b></div>
  <div style="margin-top:12px;">
    {% if is_admin %}
      Admin Panel: <a href="/admin">/admin</a>
    {% else %}
      (You are not admin)
    {% endif %}
  </div>
  <div style="margin-top:12px;">
    Open Streamlit SOC dashboard: <b>streamlit run dashboard.py</b>
  </div>
  <div style="margin-top:12px;">
    <a href="/logout">Logout</a>
  </div>
</div>
</body></html>
"""

ADMIN_HTML = """<!doctype html>
<html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Admin Panel</title>
<style>
  body{margin:0;min-height:100vh;padding:24px;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;
    background: linear-gradient(180deg,#050816,#0b1220);color:#e5e7eb;}
  .card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12);
    border-radius:18px;padding:18px;box-shadow:0 24px 70px rgba(0,0,0,.5);margin-bottom:16px;}
  table{width:100%;border-collapse:collapse;margin-top:10px;}
  th,td{border-bottom:1px solid rgba(255,255,255,.10);padding:10px;text-align:left;font-size:13px;}
  th{color:#9ca3af;font-weight:700;}
  .btn{padding:8px 10px;border-radius:12px;border:1px solid rgba(255,255,255,.12);
    background:rgba(0,0,0,.22);color:#e5e7eb;cursor:pointer;}
  .top{display:flex;justify-content:space-between;align-items:center;gap:10px;}
  a{color:#06b6d4;text-decoration:none;}
</style></head>
<body>
<div class="top">
  <h2 style="margin:0;">🧰 Admin Panel</h2>
  <div><a href="/">Login</a> • <a href="/logout">Logout</a></div>
</div>

<div class="card">
  <div style="color:#9ca3af">Unblock users / IPs. Forensic logs available in Streamlit dashboard.</div>
</div>

<div class="card">
  <h3 style="margin:0;">Blocked Users</h3>
  <form method="POST" action="/admin/unblock-user">
    <table>
      <thead><tr><th>Username</th><th>Blocked Until (epoch)</th><th>Action</th></tr></thead>
      <tbody>
        {% for r in blocked_users %}
          <tr>
            <td>{{r[0]}}</td>
            <td>{{r[1]}}</td>
            <td><button class="btn" name="username" value="{{r[0]}}">Unblock</button></td>
          </tr>
        {% endfor %}
        {% if not blocked_users %}
          <tr><td colspan="3" style="color:#9ca3af">No blocked users</td></tr>
        {% endif %}
      </tbody>
    </table>
  </form>
</div>

<div class="card">
  <h3 style="margin:0;">Blocked IPs</h3>
  <form method="POST" action="/admin/unblock-ip">
    <table>
      <thead><tr><th>IP</th><th>Blocked Until (epoch)</th><th>Action</th></tr></thead>
      <tbody>
        {% for r in blocked_ips %}
          <tr>
            <td>{{r[0]}}</td>
            <td>{{r[1]}}</td>
            <td><button class="btn" name="ip" value="{{r[0]}}">Unblock</button></td>
          </tr>
        {% endfor %}
        {% if not blocked_ips %}
          <tr><td colspan="3" style="color:#9ca3af">No blocked IPs</td></tr>
        {% endif %}
      </tbody>
    </table>
  </form>
</div>

</body></html>
"""


@app.before_request
def _init():
    ensure_schema()


@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    cls = ""
    prefill_user = request.cookies.get("remember_user", "")
    remember_checked = "checked" if prefill_user else ""

    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        remember = request.form.get("remember") == "on"

        # IP block
        ip_blocked, ip_rem = is_ip_blocked(ip)
        if ip_blocked:
            msg = f"⛔ IP blocked. Try again in {ip_rem}s."
            cls = "warn"
            log_event(username, ip, ua, False, "IP_BLOCKED")
        else:
            # user block
            user_blocked, user_rem = is_user_blocked(username)
            if user_blocked:
                msg = f"⛔ Account locked. Try again in {user_rem}s."
                cls = "warn"
                log_event(username, ip, ua, False, "USER_BLOCKED")
            else:
                user = get_user(username)
                if user and bcrypt.checkpw(password.encode(), user[1]):
                    # OTP stage
                    session["pending_user"] = username
                    session["pending_is_admin"] = int(user[3] or 0)

                    otp_code, ttl = create_otp(username)

                    # optional email
                    send_email_alert(
                        "OTP Generated (Simulator)",
                        f"User: {username}\nIP: {ip}\nOTP (demo): {otp_code}\nValid: {ttl}s"
                    )

                    log_event(username, ip, ua, True, "PASSWORD_OK_OTP_SENT")
                    session["dev_otp"] = otp_code

                    resp = redirect(url_for("otp"))
                    if remember:
                        resp.set_cookie("remember_user", username, max_age=60 * 60 * 24 * 30)
                    else:
                        resp.set_cookie("remember_user", "", expires=0)
                    return resp

                # bad password -> record
                ucount, ublocked_now = record_failed_user_attempt(username)
                ipcount, ipblocked_now = record_failed_ip_attempt(ip)

                if ipblocked_now:
                    send_email_alert("IP Blocked Alert", f"IP {ip} blocked after {ipcount}/{MAX_IP_ATTEMPTS} attempts.")
                if ublocked_now:
                    send_email_alert("User Blocked Alert", f"User {username} blocked after {ucount}/{MAX_USER_ATTEMPTS} attempts.")

                log_event(username, ip, ua, False, f"BAD_PASSWORD u={ucount} ip={ipcount}")

                if ipblocked_now:
                    msg = f"⛔ IP locked for {IP_BLOCK_TIME}s due to repeated failures."
                    cls = "warn"
                elif ublocked_now:
                    msg = f"⛔ Account locked for {USER_BLOCK_TIME}s due to repeated failures."
                    cls = "warn"
                else:
                    msg = f"❌ Invalid credentials. User: {ucount}/{MAX_USER_ATTEMPTS} • IP: {ipcount}/{MAX_IP_ATTEMPTS}"
                    cls = "err"

        # render same page with message
        resp = make_response(render_template_string(
            LOGIN_HTML,
            msg=msg, cls=cls,
            prefill_user=username if remember else "",
            remember_checked="checked" if remember else "",
            max_user=MAX_USER_ATTEMPTS,
            max_ip=MAX_IP_ATTEMPTS,
            user_block=USER_BLOCK_TIME,
            ip_block=IP_BLOCK_TIME
        ))

        if remember:
            resp.set_cookie("remember_user", username, max_age=60 * 60 * 24 * 30)
        else:
            resp.set_cookie("remember_user", "", expires=0)

        return resp

    return render_template_string(
        LOGIN_HTML,
        msg=msg, cls=cls,
        prefill_user=prefill_user,
        remember_checked=remember_checked,
        max_user=MAX_USER_ATTEMPTS,
        max_ip=MAX_IP_ATTEMPTS,
        user_block=USER_BLOCK_TIME,
        ip_block=IP_BLOCK_TIME
    )


@app.route("/otp", methods=["GET", "POST"])
def otp():
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    pending = session.get("pending_user")
    if not pending:
        return redirect(url_for("login"))

    msg = ""
    dev_otp = session.get("dev_otp")

    if request.method == "POST":
        code = request.form["otp"].strip()
        ok, reason = verify_otp(pending, code)
        if ok:
            session["user"] = pending
            session["is_admin"] = session.get("pending_is_admin", 0)
            session.pop("pending_user", None)
            session.pop("pending_is_admin", None)
            session.pop("dev_otp", None)

            reset_user_attempts(session["user"])
            log_event(session["user"], ip, ua, True, "OTP_OK_LOGIN_COMPLETE")

            return render_template_string(SUCCESS_HTML, user=session["user"], is_admin=1 if require_admin() else 0)

        msg = f"❌ {reason}"
        log_event(pending, ip, ua, False, f"OTP_FAIL: {reason}")

    return render_template_string(OTP_HTML, msg=msg, dev_otp=dev_otp)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
def admin():
    if not require_admin():
        return "403 Forbidden (admin only)", 403

    now = time.time()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    cur.execute("SELECT username, blocked_until FROM attempts WHERE blocked_until IS NOT NULL AND blocked_until > ?", (now,))
    blocked_users = cur.fetchall()

    cur.execute("SELECT ip, blocked_until FROM ip_attempts WHERE blocked_until IS NOT NULL AND blocked_until > ?", (now,))
    blocked_ips = cur.fetchall()

    conn.close()
    return render_template_string(ADMIN_HTML, blocked_users=blocked_users, blocked_ips=blocked_ips)


@app.route("/admin/unblock-user", methods=["POST"])
def admin_unblock_user():
    if not require_admin():
        return "403 Forbidden (admin only)", 403
    username = request.form.get("username", "").strip()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE attempts SET count=0, blocked_until=NULL WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))


@app.route("/admin/unblock-ip", methods=["POST"])
def admin_unblock_ip():
    if not require_admin():
        return "403 Forbidden (admin only)", 403
    ip = request.form.get("ip", "").strip()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE ip_attempts SET count=0, blocked_until=NULL WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=True)
