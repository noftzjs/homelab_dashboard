import os
import json
import sqlite3
import socket
import platform
import subprocess
import time
import re
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import plotly.express as px
import requests
import streamlit as st

# --- 1. Page Configuration ---
st.set_page_config(
    page_title="Infrastructure & Alarm Center",
    page_icon="HL",
    layout="wide"
)

DB_NAME = "homelab_inventory.db"
JSON_FILE = "devices.json"
TEMPLATE_FILE = "devices.template.json"

# --- 2. Database Initializer & Migration Engine ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            vendor TEXT,
            type TEXT,
            port INTEGER,
            path TEXT,
            custom_url TEXT,
            is_monitored INTEGER DEFAULT 1,
            last_seen TEXT
        )
    """)
    
    # Safe Auto-Migration for missing columns
    cursor.execute("PRAGMA table_info(devices)")
    existing_columns = [column[1] for column in cursor.fetchall()]
    
    migrations = {"path": "TEXT", "custom_url": "TEXT"}
    for col_name, col_type in migrations.items():
        if col_name not in existing_columns:
            cursor.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}")
            
    conn.commit()
    conn.close()

init_db()

# --- 3. JSON Seed Helper ---
def seed_db_from_json(file_path: str) -> bool:
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, "r") as f:
            devices = json.load(f)
            
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        for dev in devices:
            cursor.execute("""
                INSERT OR IGNORE INTO devices (name, ip, type, port, path, custom_url, vendor, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, 'Unknown', 'Never')
            """, (
                str(dev.get("name", "Unknown Node")),
                str(dev.get("ip")),
                str(dev.get("type", "General")),
                dev.get("port"),
                dev.get("path"),
                dev.get("custom_url")
            ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Error loading JSON: {e}")
        return False

# --- 4. Subnet Sweep for New User Setup ---
def ping_quick(ip: str) -> str | None:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = '500' if platform.system().lower() == 'windows' else '1'
    
    command = ['ping', param, '1', timeout_param, timeout_val, str(ip)]
    try:
        res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=1.2)
        if res.returncode == 0:
            return str(ip)
    except Exception:
        pass
    return None

def auto_discover_subnet(cidr: str):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
    except ValueError:
        st.error("Invalid CIDR format! Use standard notation like 192.168.1.0/24")
        return

    st.info(f"Sweeping {len(hosts)} addresses on `{cidr}`...")
    progress_bar = st.progress(0)
    
    found_ips = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        for i, result in enumerate(executor.map(ping_quick, hosts)):
            if result:
                found_ips.append(result)
            progress_bar.progress((i + 1) / len(hosts))

    if not found_ips:
        st.warning("No active hosts responded to the sweep.")
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for ip in found_ips:
        mac = get_mac_from_arp(ip)
        vendor = lookup_mac_vendor(mac) if mac != "N/A" else "Unknown Vendor"
        default_name = f"Discovered Host ({ip.split('.')[-1]})"
        
        cursor.execute("""
            INSERT OR IGNORE INTO devices (name, ip, mac, vendor, type, port, last_seen)
            VALUES (?, ?, ?, ?, 'Unassigned', NULL, ?)
        """, (default_name, ip, mac, vendor, now))
        
    conn.commit()
    conn.close()
    st.success(f"Discovered and imported {len(found_ips)} active devices!")

# --- 5. Utilities & Launch Link Builders ---
def build_launch_url(ip: str, port: int | None = None, path: str | None = None, custom_url: str | None = None) -> str | None:
    if custom_url and str(custom_url).strip():
        return str(custom_url).strip()

    formatted_path = f"/{str(path).lstrip('/')}" if path else ""

    NON_WEB_PORTS = {22, 53, 139, 445, 3306, 5432, 6379}
    if not port or port in NON_WEB_PORTS or port == 80:
        return f"http://{ip}{formatted_path}"
    if port == 443:
        return f"https://{ip}{formatted_path}"

    KNOWN_HTTPS_PORTS = {8006, 8443, 9443, 9090}
    scheme = "https" if port in KNOWN_HTTPS_PORTS else "http"

    return f"{scheme}://{ip}:{port}{formatted_path}"

@st.cache_data(ttl=3600)
def lookup_mac_vendor(mac_address: str) -> str:
    if not mac_address or mac_address == "N/A":
        return "Unknown Vendor"
    try:
        res = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=2)
        if res.status_code == 200:
            return res.text.strip()
    except Exception:
        pass
    return "Unknown Vendor"

def get_mac_from_arp(ip: str) -> str:
    try:
        cmd = ['arp', '-a', ip] if platform.system().lower() == 'windows' else ['arp', '-n', ip]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        mac_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        if mac_match:
            return mac_match.group(0).upper()
    except Exception:
        pass
    return "N/A"

def ping_ip(ip: str, timeout_sec: float = 1.0) -> tuple[bool, float]:
    if not ip or not str(ip).strip() or str(ip).strip().upper() in ["N/A", "NONE", "NULL", "NAN", "UNCONFIGURED"]:
        return False, 0.0

    ip_str = str(ip).strip()
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = str(int(timeout_sec * 1000)) if platform.system().lower() == 'windows' else str(int(timeout_sec))
    
    command = ['ping', param, '1', timeout_param, timeout_val, ip_str]
    start_time = time.time()
    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout_sec + 0.5)
        latency = round((time.time() - start_time) * 1000, 1)
        if output.returncode == 0:
            return True, latency
    except Exception:
        pass
    return False, 0.0

def check_tcp_port(ip: str, port: int, timeout_sec: float = 1.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_sec)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def scan_single_device(device: dict) -> dict:
    raw_ip = device.get("ip")
    ip = str(raw_ip).strip() if raw_ip and not pd.isna(raw_ip) else ""

    # Clean port parsing (Prevents PyArrow float NaN errors)
    raw_port = device.get("port")
    if raw_port and not pd.isna(raw_port) and str(raw_port).strip().upper() not in ["", "NONE", "NAN", "NULL"]:
        try:
            port_val = int(raw_port)
            target_port_str = str(port_val)
        except (ValueError, TypeError):
            port_val = None
            target_port_str = "ICMP Only"
    else:
        port_val = None
        target_port_str = "ICMP Only"

    # Check for unconfigured / missing IP addresses
    if not ip or ip.upper() in ["N/A", "NONE", "NULL", "NAN", "UNCONFIGURED"]:
        return {
            "ID": int(device["id"]),
            "Device Name": str(device["name"]),
            "IP Address": "Unconfigured",
            "MAC Address": str(device.get("mac") or "N/A"),
            "Vendor": str(device.get("vendor") or "Unknown"),
            "Type": str(device.get("type") or "Unassigned"),
            "Target Port": "N/A",
            "Status": "⚪ Unconfigured",
            "Latency (ms)": 0.0,
            "Quick Launch": "N/A",
            "Last Checked": datetime.now().strftime("%H:%M:%S")
        }

    path = device.get("path")
    custom_url = device.get("custom_url")
    mac = str(device.get("mac") or "N/A")
    vendor = str(device.get("vendor") or "Unknown")

    is_online, latency = ping_ip(ip)
    
    if is_online and (mac == "N/A" or vendor == "Unknown"):
        discovered_mac = get_mac_from_arp(ip)
        if discovered_mac != "N/A":
            mac = discovered_mac
            vendor = lookup_mac_vendor(mac)
            conn = sqlite3.connect(DB_NAME)
            conn.execute("UPDATE devices SET mac = ?, vendor = ? WHERE ip = ?", (mac, vendor, ip))
            conn.commit()
            conn.close()

    service_status = True
    if port_val and is_online:
        service_status = check_tcp_port(ip, port_val)
        
    if not is_online:
        final_status = "🔴 Offline"
    elif port_val and not service_status:
        final_status = "⚠️ Port Closed"
    else:
        final_status = "🟢 Online"
    
    web_link = build_launch_url(ip=ip, port=port_val, path=path, custom_url=custom_url)

    # Strictly coerce every value to explicit primitives
    return {
        "ID": int(device["id"]),
        "Device Name": str(device["name"]),
        "IP Address": str(ip),
        "MAC Address": str(mac),
        "Vendor": str(vendor),
        "Type": str(device["type"]),
        "Target Port": str(target_port_str),
        "Status": str(final_status),
        "Latency (ms)": float(latency) if "🟢" in final_status else 0.0,
        "Quick Launch": str(web_link) if web_link else "N/A",
        "Last Checked": str(datetime.now().strftime("%H:%M:%S"))
    }

def scan_all_devices_parallel() -> pd.DataFrame:
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, ip, mac, vendor, type, port, path, custom_url FROM devices WHERE is_monitored = 1")
    columns = [col[0] for col in cursor.description]
    devices = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()

    if not devices:
        return pd.DataFrame()

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(scan_single_device, devices))

    df = pd.DataFrame(results)

    # --- Strict DataFrame Column Type Enforcement (PyArrow Protection) ---
    df["ID"] = df["ID"].astype(int)
    df["Device Name"] = df["Device Name"].astype(str)
    df["IP Address"] = df["IP Address"].astype(str)
    df["MAC Address"] = df["MAC Address"].astype(str)
    df["Vendor"] = df["Vendor"].astype(str)
    df["Type"] = df["Type"].astype(str)
    df["Target Port"] = df["Target Port"].astype(str)
    df["Status"] = df["Status"].astype(str)
    df["Latency (ms)"] = pd.to_numeric(df["Latency (ms)"], errors="coerce").fillna(0.0).astype(float)
    df["Quick Launch"] = df["Quick Launch"].astype(str)
    df["Last Checked"] = df["Last Checked"].astype(str)

    return df

def send_alert_webhook(webhook_url: str, message: str):
    if webhook_url:
        payload = {"content": f"**HOMELAB ALARM DETECTED**\n{message}"}
        try:
            requests.post(webhook_url, json=payload, timeout=3)
        except Exception:
            pass

# --- 6. FIRST-RUN ONBOARDING WIZARD ---
conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM devices")
db_count = cursor.fetchone()[0]
conn.close()

if db_count == 0:
    st.title("Welcome to Home Lab Monitor Setup")
    st.markdown("No device inventory found in your local database. Choose a method below to populate your hardware stack.")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("Option 1: Auto-Scan Local Subnet")
        st.caption("Discover all active nodes on your LAN automatically.")
        target_subnet = st.text_input("Enter Subnet CIDR:", value="192.168.1.0/24")
        if st.button("Run Subnet Auto-Discovery"):
            with st.spinner("Scanning network range..."):
                auto_discover_subnet(target_subnet)
            st.rerun()

    with col_b:
        st.subheader("Option 2: Load Sample JSON Template")
        st.caption("Load placeholder entries from `devices.template.json` or `devices.json`.")
        if st.button("Load Default JSON Data"):
            if seed_db_from_json(JSON_FILE) or seed_db_from_json(TEMPLATE_FILE):
                st.success("Loaded default inventory from JSON!")
                st.rerun()
            else:
                st.error("No valid JSON file found in root directory.")

    st.stop()

# --- 7. MAIN DASHBOARD UI & CONTROLS ---
st.title("Home Lab Infrastructure & Alarm Center")

# Sidebar Controls
st.sidebar.title("⚡ Monitoring Controls")
auto_refresh = st.sidebar.toggle("Enable Live Auto-Refresh", value=False)
refresh_speed = st.sidebar.slider("Refresh Speed (Seconds):", min_value=2, max_value=30, value=10)
latency_threshold = st.sidebar.number_input("High Latency Threshold (ms):", value=100)

st.sidebar.divider()
st.sidebar.subheader("Notification Webhook")
webhook_url = st.sidebar.text_input("Discord/Slack/Ntfy Webhook URL:", type="password")

# NON-NESTED TOP LEVEL NAVIGATION TABS
tab_matrix, tab_chart, tab_inventory = st.tabs([
    "🌐 Hardware Status Matrix", 
    "📈 Response Latency", 
    "⚙️ Inventory Manager"
])

run_interval = refresh_speed if auto_refresh else None

# --- TAB 1: LIVE MATRIX (FRAGMENT) ---
with tab_matrix:
    @st.fragment(run_every=run_interval)
    def render_matrix_view():
        if auto_refresh:
            st.caption(f"Auto-refresh active ({refresh_speed}s interval)")

        with st.spinner("Scanning network inventory..."):
            results_df = scan_all_devices_parallel()

        if results_df.empty:
            st.warning("No devices found in database. Go to 'Inventory Manager' to add hardware.")
            return

        # Alarm Engine
        offline_devices = results_df[results_df["Status"].str.contains("Offline|Port Closed")]
        high_latency_devices = results_df[(results_df["Status"].str.contains("Online")) & (results_df["Latency (ms)"] > latency_threshold)]

        if not offline_devices.empty or not high_latency_devices.empty:
            st.error("**ACTIVE ALARM DETECTED**")
            alarm_messages = []
            
            for _, row in offline_devices.iterrows():
                msg = f"• **{row['Device Name']}** (`{row['IP Address']}`) is **{row['Status']}**!"
                st.write(msg)
                alarm_messages.append(msg)
                
            for _, row in high_latency_devices.iterrows():
                msg = f"• **{row['Device Name']}** (`{row['IP Address']}`) High Latency: **{row['Latency (ms)']} ms**!"
                st.write(msg)
                alarm_messages.append(msg)

            if webhook_url and st.button("Send Alert Webhook Now"):
                send_alert_webhook(webhook_url, "\n".join(alarm_messages))
        else:
            st.success("✅ **All Systems Nominal** — Zero Active Alarms")

        # Metric Tiles
        st.divider()
        col1, col2, col3, col4 = st.columns(4)

        total_nodes = len(results_df)
        online_nodes = len(results_df[results_df["Status"].str.contains("Online")])
        avg_latency = results_df[results_df["Status"].str.contains("Online")]["Latency (ms)"].mean()

        col1.metric("Monitored Devices", total_nodes)
        col2.metric("Online Nodes", f"{online_nodes} / {total_nodes}")
        col3.metric("System Health", f"{(online_nodes/total_nodes)*100:.0f}%")
        col4.metric("Avg Ping Latency", f"{avg_latency:.1f} ms" if not pd.isna(avg_latency) else "N/A")

        st.divider()
        st.subheader("Live Status Directory")
        st.dataframe(
            results_df,
            column_config={
                "Quick Launch": st.column_config.LinkColumn("Web UI", display_text="Open Web UI"),
                "Latency (ms)": st.column_config.NumberColumn("Ping Latency", format="%.1f ms"),
            },
            width='stretch',
            hide_index=True
        )

    render_matrix_view()

# --- TAB 2: RESPONSE LATENCY CHART (FRAGMENT) ---
with tab_chart:
    @st.fragment(run_every=run_interval)
    def render_chart_view():
        if auto_refresh:
            st.caption(f"🔄 Auto-refresh active ({refresh_speed}s interval)")

        results_df = scan_all_devices_parallel()
        online_df = results_df[results_df["Status"].str.contains("Online")] if not results_df.empty else pd.DataFrame()

        st.subheader("Latency Telemetry")
        if not online_df.empty:
            fig_bar = px.bar(
                online_df,
                x="Device Name",
                y="Latency (ms)",
                color="Latency (ms)",
                color_continuous_scale="Viridis",
                title="Ping Latency across Hardware (ms)"
            )
            st.plotly_chart(fig_bar, width='stretch')
        else:
            st.info("No active online nodes to display latency telemetry.")

    render_chart_view()

# --- TAB 3: INVENTORY MANAGER (STATIC, NO FRAGMENT) ---
with tab_inventory:
    st.subheader("Manage Database Inventory")
    st.caption("Auto-refresh is completely isolated from this tab so edits will never be interrupted.")

    conn = sqlite3.connect(DB_NAME)
    db_df = pd.read_sql_query("SELECT * FROM devices", conn)
    conn.close()

    # --- Sanitize Database DataFrame for st.data_editor ---
    string_cols = ["name", "ip", "mac", "vendor", "type", "path", "custom_url", "last_seen"]
    for col in string_cols:
        if col in db_df.columns:
            db_df[col] = db_df[col].fillna("").astype(str)

    edited_df = st.data_editor(
        db_df,
        num_rows="dynamic",
        width='stretch',
        key="db_editor",
        disabled=["id"]
    )

    if st.button("Save Database Changes"):
        conn = sqlite3.connect(DB_NAME)
        edited_df.to_sql("devices", conn, if_exists="replace", index=False)
        conn.close()
        st.success("Hardware inventory database successfully updated!")
        st.rerun()