import sqlite3
import time
import pandas as pd
import streamlit as st

from security import ensure_schema, DB

st.set_page_config(page_title=" AuthSentry SOC Dashboard", layout="wide")

ensure_schema()

# Auto refresh
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()

def auto_refresh(seconds: int):
    if time.time() - st.session_state.last_refresh >= seconds:
        st.session_state.last_refresh = time.time()
        st.rerun()

st.sidebar.title("⚙️ Controls")
refresh_sec = st.sidebar.slider("Auto refresh (sec)", 2, 30, 5)
show_only_blocked = st.sidebar.checkbox("Only blocked (users + IPs)", False)
auto_refresh(refresh_sec)

st.markdown("""
<style>
  .block-container{padding-top:1rem;}
  .glass{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.10);
         border-radius:16px;padding:14px;}
</style>
""", unsafe_allow_html=True)

st.title("🛰️ AuthSentry SOC Dashboard — Brute Force Simulator (Level 2)")
st.caption("User lockouts + IP lockouts + forensic logs (SQLite).")

now = time.time()
conn = sqlite3.connect(DB)

attempts = pd.read_sql_query("SELECT username, count, blocked_until, last_attempt FROM attempts", conn)
ip_attempts = pd.read_sql_query("SELECT ip, count, blocked_until, last_attempt FROM ip_attempts", conn)
logs = pd.read_sql_query(
    "SELECT ts, username, ip, user_agent, success, reason FROM login_logs ORDER BY ts DESC LIMIT 200",
    conn
)
conn.close()

attempts["blocked"] = attempts["blocked_until"].notnull() & (attempts["blocked_until"] > now)
attempts["blocked_remaining_sec"] = attempts["blocked_until"].apply(lambda x: int(x-now) if pd.notnull(x) and x > now else 0)

ip_attempts["blocked"] = ip_attempts["blocked_until"].notnull() & (ip_attempts["blocked_until"] > now)
ip_attempts["blocked_remaining_sec"] = ip_attempts["blocked_until"].apply(lambda x: int(x-now) if pd.notnull(x) and x > now else 0)

if show_only_blocked:
    attempts_view = attempts[attempts["blocked"] == True].copy()
    ip_view = ip_attempts[ip_attempts["blocked"] == True].copy()
else:
    attempts_view = attempts.copy()
    ip_view = ip_attempts.copy()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Tracked Users", int(len(attempts)))
c2.metric("Tracked IPs", int(len(ip_attempts)))
c3.metric("Blocked Users Now", int(attempts["blocked"].sum()))
c4.metric("Blocked IPs Now", int(ip_attempts["blocked"].sum()))

st.divider()

colA, colB = st.columns(2)

with colA:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.subheader("👤 Users — Attempts & Lockouts")
    st.dataframe(
        attempts_view[["username","count","blocked","blocked_remaining_sec"]]
          .sort_values(["blocked","count"], ascending=[False, False]),
        use_container_width=True
    )
    st.markdown("</div>", unsafe_allow_html=True)

with colB:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.subheader("🌐 IPs — Attempts & Lockouts")
    st.dataframe(
        ip_view[["ip","count","blocked","blocked_remaining_sec"]]
          .sort_values(["blocked","count"], ascending=[False, False]),
        use_container_width=True
    )
    st.markdown("</div>", unsafe_allow_html=True)

st.divider()

cA, cB = st.columns(2)
with cA:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.subheader("📊 User Failed Attempts (Bar)")
    if len(attempts):
        st.bar_chart(attempts.set_index("username")[["count"]].sort_values("count", ascending=False))
    st.markdown("</div>", unsafe_allow_html=True)

with cB:
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.subheader("📊 IP Failed Attempts (Bar)")
    if len(ip_attempts):
        st.bar_chart(ip_attempts.set_index("ip")[["count"]].sort_values("count", ascending=False))
    st.markdown("</div>", unsafe_allow_html=True)

st.divider()

st.markdown('<div class="glass">', unsafe_allow_html=True)
st.subheader("🧾 Forensic Logs (last 200)")
if len(logs):
    logs["time"] = logs["ts"].apply(lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(t))))
    logs["success"] = logs["success"].apply(lambda x: "✅" if int(x) == 1 else "❌")
    st.dataframe(logs[["time","username","ip","success","reason","user_agent"]], use_container_width=True)
else:
    st.info("No logs yet.")
st.markdown("</div>", unsafe_allow_html=True)
