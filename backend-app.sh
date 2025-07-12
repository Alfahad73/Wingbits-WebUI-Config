#!/bin/bash

# Write the Flask backend application (app.py)
# This script generates the Python Flask application file for the web panel.

set -e

echo "Writing backend files..."

INSTALL_DIR="/opt/wingbits-station-web"
BACKEND_DIR="$INSTALL_DIR/backend"

cat > "$BACKEND_DIR/app.py" << 'EOF'
import os
import subprocess
import re
import glob
import time
import json
import platform
import socket
import psutil
import functools # Import functools for the decorator
import uuid # Import uuid for generating session tokens
import threading # For running commands in a separate thread
import sys # Import sys for stderr

# Redirect all stdout and stderr to /dev/null immediately for Flask app logs
# This will prevent any Flask-related output from being logged by systemd-journald
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

from werkzeug.security import generate_password_hash, check_password_hash # For password hashing
from flask import jsonify, make_response
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS # Enable CORS for all routes

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Path to the authentication file
AUTH_FILE_PATH = "/opt/wingbits-station-web/conf/auth.json"
CONFIG_FILE_PATH = "/opt/wingbits-station-web/conf/config.json" # Path to the config file

# In-memory token for the current session (for a single-user panel)
# In a multi-user environment, this would be a dictionary mapping tokens to user IDs
CURRENT_SESSION_TOKEN = None 

# Global variable to store update process info
# UPDATE_LOG_FILE = "/var/log/wingbits/client_update.log" # This file will no longer be used
UPDATE_PROCESS = None # Stores the Popen object or a flag

# Global variable to hold last network reading for live stats (not monthly archive)
LAST_NET_STATS = {"time": 0, "iface": None, "rx_bytes": 0, "tx_bytes": 0}

# Get port and other configurations from config file or use defaults
WEB_PANEL_RUN_PORT = 5000 # Default port
DISABLE_UPDATE_LOG = True # Always set to True as per user's request
if os.path.exists(CONFIG_FILE_PATH):
    try:
        with open(CONFIG_FILE_PATH, 'r') as f:
            config = json.load(f)
            WEB_PANEL_RUN_PORT = config.get('port', 5000)
            # We explicitly override disable_update_log to True here based on user's request
            DISABLE_UPDATE_LOG = True 
    except (json.JSONDecodeError, IOError):
        # Error reading config, use defaults and disable logs
        print(f"Warning: Could not read or parse config file at {CONFIG_FILE_PATH}. Using default port {WEB_PANEL_RUN_PORT} and disabling all update logs.", file=sys.stderr)
        DISABLE_UPDATE_LOG = True # Ensure it's true on error too

# IMPORTANT: Browsers block certain ports (e.g., 5060 for SIP) due to security concerns.
# If you encounter "ERR_UNSAFE_PORT", choose a different port like 8000, 8080, or 8888.


# ---------- Multilingual descriptions support ----------
DESCRIPTIONS = {
    "readsb_status": {
        "ar": "عرض حالة خدمة readsb.",
        "en": "Show the status of the readsb service."
    },
    "readsb_restart": {
        "ar": "إعادة تشغيل خدمة readsb.",
        "en": "Restart the readsb service."
    },
    "readsb_logs": {
        "ar": "عرض آخر 50 سطر من سجلات readsb.",
        "en": "Show last 50 lines of readsb logs."
    },
    "readsb_set_gain": {
        "ar": "ضبط كسب الاستقبال (Gain) للـ readsb.",
        "en": "Set gain value for readsb."
    },
    "readsb_toggle_verbose": {
        "ar": "تفعيل/تعطيل وضع الإسهاب (Verbose) لـ readsb.",
        "en": "Enable/Disable verbose mode for readsb."
    },
    "wingbits_status": {
        "ar": "عرض حالة خدمة wingbits.",
        "en": "Show the status of the wingbits service."
    },
    "wingbits_restart": {
        "ar": "إعادة تشغيل خدمة wingbits.",
        "en": "Restart the wingbits service."
    },
    "wingbits_logs": {
        "ar": "عرض آخر 2000 سطر من سجلات wingbits.",
        "en": "Show last 2000 lines of wingbits logs."
    },
    "wingbits_update_client": {
        "ar": "تحديث عميل Wingbits.",
        "en": "Update Wingbits client."
    },
    "wingbits_geosigner_info": {
        "ar": "عرض معلومات GeoSigner.",
        "en": "Show GeoSigner information."
    },
    "wingbits_version": {
        "ar": "عرض إصدار Wingbits.",
        "en": "Show Wingbits version."
    },
    "tar1090_restart": {
        "ar": "إعادة تشغيل خدمة tar1090.",
        "en": "Restart tar1090 service."
    },
    "tar1090_route_info": {
        "ar": "تفعيل أو تعطيل معلومات مسار الرحلة في tar1090.",
        "en": "Enable/Disable route info in tar1090."
    },
    "graphs1090_restart": {
        "ar": "إعادة تشغيل خدمة graphs1090.",
        "en": "Restart graphs1090 service."
    },
    "graphs1090_colorscheme": {
        "ar": "تغيير مخطط الألوان للـ graphs1090.",
        "en": "Set color scheme for graphs1090."
    },
    "pi_restart": {
        "ar": "إعادة تشغيل الجهاز بالكامل.",
        "en": "Reboot the device."
    },
    "pi_shutdown": {
        "ar": "إيقاف تشغيل الجهاز بالكامل.",
        "en": "Shutdown the device."
    },
    "wingbits_debug": {
        "ar": "عرض معلومات تصحيح أخطاء Wingbits.",
        "en": "Show Wingbits debug information."
    },
    "update_in_progress": {
        "ar": "تحديث قيد التقدم بالفعل.",
        "en": "An update is already in progress."
    },
    "update_started": {
        "ar": "بدأ تحديث عميل Wingbits في الخلفية.",
        "en": "Wingbits client update started in the background."
    },
    "wingbits_update_logs": {
        "ar": "سجلات تحديث عميل Wingbits.",
        "en": "Wingbits client update logs."
    },
    "diagnostics_wingbits_readsb_logs": {
        "ar": "إنشاء رابط لسجلات Wingbits و readsb.",
        "en": "Generate link for Wingbits & readsb logs."
    },
    "diagnostics_all_logs": {
        "ar": "إنشاء رابط لجميع السجلات الحديثة.",
        "en": "Generate link for all recent logs."
    },
    "diagnostics_os_release": {
        "ar": "عرض تفاصيل نظام التشغيل.",
        "en": "View OS release details."
    },
    "diagnostics_lsusb": {
        "ar": "عرض الأجهزة المتصلة عبر USB.",
        "en": "View USB devices."
    },
    "diagnostics_throttled": {
        "ar": "فحص انخفاض الجهد الكهربائي.",
        "en": "Check for voltage throttling."
    },
    "diagnostics_wingbits_status_verbose": {
        "ar": "عرض حالة Wingbits التفصيلية.",
        "en": "View detailed Wingbits status."
    },
    "diagnostics_geosigner_info": {
        "ar": "عرض معلومات GeoSigner.",
        "en": "View GeoSigner information."
    }
}

def lang_desc(key, lang='en'):
    return DESCRIPTIONS.get(key, {}).get(lang, '')

def run_shell(cmd):
    try:
        # Use a longer timeout for potentially long-running commands
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, encoding='utf-8', timeout=120)
        return output.strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing command:\n{e.output.strip()}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 2 minutes."


# Function to run shell commands asynchronously and suppress output
def run_shell_async(cmd, log_file_path_ignored): # log_file_path_ignored is no longer used
    global UPDATE_PROCESS
    # Always redirect output to DEVNULL as per user's request to disable all logs
    stdout_target = subprocess.DEVNULL
    stderr_target = subprocess.DEVNULL
    
    try:
        process = subprocess.Popen(cmd, shell=True, stdout=stdout_target, stderr=stderr_target, text=True)
        UPDATE_PROCESS = process
        process.wait()
    finally:
        UPDATE_PROCESS = None

# Function to load authentication credentials
def load_auth_credentials():
    if os.path.exists(AUTH_FILE_PATH):
        with open(AUTH_FILE_PATH, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return None
    return None

# Function to save authentication credentials
def save_auth_credentials(username, password_hash):
    data = {"username": username, "password_hash": password_hash}
    with open(AUTH_FILE_PATH, 'w') as f:
        json.dump(data, f)
    # Set restrictive permissions (read/write for owner only)
    os.chmod(AUTH_FILE_PATH, 0o600) 

# Decorator to protect API endpoints
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        global CURRENT_SESSION_TOKEN
        auth_token = request.headers.get('X-Auth-Token')
        if not auth_token or auth_token != CURRENT_SESSION_TOKEN:
            return jsonify({'ok': False, 'msg': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ====== API Endpoints by Service/Function ======

# ---------- Authentication Endpoints ----------
@app.route('/api/login', methods=['POST'])
def login():
    global CURRENT_SESSION_TOKEN
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    credentials = load_auth_credentials()
    if not credentials:
        # If auth file doesn't exist, this is likely the first run
        # or an issue. For security, we don't auto-create here.
        return jsonify({'ok': False, 'msg': 'Authentication file not found. Please run the installer script to set up credentials.'}), 500

    if username == credentials.get('username') and check_password_hash(credentials.get('password_hash'), password):
        CURRENT_SESSION_TOKEN = str(uuid.uuid4()) # Generate a new session token
        return jsonify({'ok': True, 'msg': 'Login successful', 'token': CURRENT_SESSION_TOKEN})
    else:
        return jsonify({'ok': False, 'msg': 'Invalid username or password'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    global CURRENT_SESSION_TOKEN
    CURRENT_SESSION_TOKEN = None # Invalidate the current session token
    return jsonify({'ok': True, 'msg': 'Logged out successfully'})

@app.route('/api/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({'ok': False, 'msg': 'Old and new passwords are required'}), 400
    
    if len(new_password) < 6: # Basic password strength check
        return jsonify({'ok': False, 'msg': 'New password must be at least 6 characters long'}), 400

    credentials = load_auth_credentials()
    if not credentials:
        return jsonify({'ok': False, 'msg': 'Authentication file not found or corrupted.'}), 500

    if not check_password_hash(credentials.get('password_hash'), old_password):
        return jsonify({'ok': False, 'msg': 'Incorrect old password'}), 401

    new_password_hash = generate_password_hash(new_password)
    save_auth_credentials(credentials.get('username'), new_password_hash)
    
    # Invalidate current session token after password change for security
    global CURRENT_SESSION_TOKEN
    CURRENT_SESSION_TOKEN = None

    return jsonify({'ok': True, 'msg': 'Password changed successfully. Please log in again.'})


# ---------- Live Stats / Dashboard ----------
@app.route('/api/stats/live', methods=['GET'])
@login_required
def live_stats():
    stats_path = '/run/readsb/stats.json'
    if not os.path.exists(stats_path):
        stats_path = '/var/run/readsb/stats.json'

    now = time.time() # Get current time for network stats calculation

    # Interface detection
    def get_main_iface_bytes():
        max_bytes = 0
        main_iface = None
        rx_bytes = tx_bytes = 0
        try:
            with open('/proc/net/dev') as f:
                lines = f.readlines()[2:]
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) < 17: continue
                    iface = parts[0].strip(':')
                    if iface == "lo": continue
                    _rx = int(parts[1])
                    _tx = int(parts[9])
                    if _rx + _tx > max_bytes:
                        max_bytes = _rx + _tx
                        rx_bytes = _rx
                        tx_bytes = _tx
                        main_iface = iface
        except FileNotFoundError:
            pass # Handle case where /proc/net/dev might not exist or be readable
        return main_iface, rx_bytes, tx_bytes

    iface, rx_bytes, tx_bytes = get_main_iface_bytes()

    # Rest of the data as usual
    stats_data = {}
    if os.path.exists(stats_path):
        with open(stats_path) as f:
            stats_data = json.load(f)
    messages_per_sec = 0
    if "last1min" in stats_data:
        msgs_1min = stats_data["last1min"].get("messages_valid", 0)
        messages_per_sec = round(msgs_1min / 60, 1)
    aircraft_with_pos = stats_data.get("aircraft_with_pos", 0)
    aircraft_without_pos = stats_data.get("aircraft_without_pos", 0)
    total_aircraft = aircraft_with_pos + aircraft_without_pos
    max_range_m = stats_data.get("last1min", {}).get("max_distance", 0)
    max_range_km = round(max_range_m / 1000, 2) if max_range_m else 0
    avg_signal = stats_data.get("last1min", {}).get("local", {}).get("signal", 0)

    # Change over last period for network usage
    global LAST_NET_STATS
    net_usage_rx_kb = net_usage_tx_kb = 0
    if LAST_NET_STATS["iface"] == iface and LAST_NET_STATS["time"] and LAST_NET_STATS["rx_bytes"] and LAST_NET_STATS["tx_bytes"]:
        delta_time = now - LAST_NET_STATS["time"]
        delta_rx = rx_bytes - LAST_NET_STATS["rx_bytes"]
        delta_tx = tx_bytes - LAST_NET_STATS["tx_bytes"]
        if delta_time > 0:
            net_usage_rx_kb = round(delta_rx / 1024, 2)
            net_usage_tx_kb = round(delta_tx / 1024, 2)
    LAST_NET_STATS = {"time": now, "iface": iface, "rx_bytes": rx_bytes, "tx_bytes": tx_bytes}

    return jsonify({
        'ok': True,
        'live': {
            'messages_per_sec': messages_per_sec,
            'aircraft_now': total_aircraft,
            'aircraft_with_pos': aircraft_with_pos,
            'aircraft_without_pos': aircraft_without_pos,
            'max_range_km': max_range_km,
            'signal_avg_db': avg_signal,
            'data_usage_rx_kb': net_usage_rx_kb,
            'data_usage_tx_kb': net_usage_tx_kb,
            'rx_total': rx_bytes,
            'tx_total': tx_bytes,
            'network_iface': iface or ""
        }
    })

# ---------- readsb Service Endpoints ----------
@app.route('/api/service/readsb/get-gain', methods=['GET'])
@login_required
def api_readsb_get_gain():
    gain = ""
    config_path = "/etc/default/readsb"
    if not os.path.exists(config_path):
        return jsonify({'ok': False, 'msg': 'readsb config not found!', 'gain': ''})
    try:
        with open(config_path, "r") as f:
            for line in f:
                if "GAIN=" in line:
                    # Example: GAIN="auto-verbose,12,-24,-6,35"
                    gain = line.split("=")[-1].strip().replace('"','').replace("'","")
                elif "--gain" in line:
                    # Example: DECODER_OPTIONS="--gain 28"
                    parts = line.replace('"','').replace("'","").split()
                    if "--gain" in parts:
                        idx = parts.index("--gain")
                        if idx+1 < len(parts):
                            gain = parts[idx+1]
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e), 'gain': ''})
    return jsonify({'ok': True, 'gain': gain or ''})

@app.route('/api/service/readsb/get-location', methods=['GET'])
@login_required
def api_readsb_get_location():
    lat, lon = None, None
    config_path = "/etc/default/readsb"
    if not os.path.exists(config_path):
        return jsonify({'ok': False, 'msg': 'readsb config not found!', 'lat': '', 'lon': ''})
    try:
        with open(config_path, "r") as f:
            lines = f.readlines()
        # Search for any line containing --lat and --lon (whether in a variable or otherwise)
        for line in lines:
            if '--lat' in line and '--lon' in line:
                # Remove quotes
                line = line.replace('"','').replace("'","")
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == '--lat' and (i+1) < len(parts):
                        lat = parts[i+1]
                    if p == '--lon' and (i+1) < len(parts):
                        lon = parts[i+1]
        # If not found, search in other formats
        if not lat or not lon:
            for line in lines:
                if line.strip().startswith("DECODER_OPTIONS="):
                    vals = line.split("=")[-1].replace('"','').replace("'","")
                    p = vals.split()
                    if '--lat' in p:
                        lat = p[p.index('--lat')+1]
                    if '--lon' in p:
                        lon = p[p.index('--lon')+1]
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e), 'lat': '', 'lon': ''})
    return jsonify({'ok': True, 'lat': lat or '', 'lon': lon or ''})

@app.route('/api/service/readsb/heatmap', methods=['POST'])
@login_required
def api_readsb_heatmap():
    data = request.get_json() or {}
    enable = data.get("enable", True)
    # Ensure the value is Boolean, not String
    if isinstance(enable, str):
        enable = (enable.lower() == "true")
    config_path = "/etc/default/readsb"
    options_to_add = "--heatmap-dir /var/globe_history --heatmap 30"

    try:
        lines = []
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                lines = f.readlines()

        found_json_options = False
        for i, line in enumerate(lines):
            if line.strip().startswith("JSON_OPTIONS="):
                found_json_options = True
                current_options = line.split('=', 1)[1].strip().strip('"').strip("'")

                if enable:
                    if options_to_add not in current_options:
                        new_options = f'"{current_options.strip()} {options_to_add}"'
                        lines[i] = f"JSON_OPTIONS={new_options}\n"
                else: # if disabling
                    if options_to_add in current_options:
                        new_options = current_options.replace(options_to_add, '').strip()
                        new_options = f'"{new_options}"' if new_options else '""'
                        lines[i] = f"JSON_OPTIONS={new_options}\n"
                break

        if not found_json_options:
            if enable:
                lines.append(f'JSON_OPTIONS="{options_to_add}"\n')

        with open(config_path, "w") as f:
            f.writelines(lines)

        if enable:
            if not os.path.exists("/var/globe_history"):
                subprocess.call(["sudo", "mkdir", "/var/globe_history"])
            subprocess.call(["sudo", "chown", "readsb", "/var/globe_history"])

        subprocess.call(["sudo", "systemctl", "restart", "readsb"])

        return jsonify({
            'ok': True,
            'result': f"Heatmap {'enabled' if enable else 'disabled'}.",
            'desc': "Experimental: Enable or disable heatmap in readsb"
        })
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)})

@app.route('/api/service/readsb/toggle-verbose', methods=['POST'])
@login_required
def api_readsb_toggle_verbose():
    lang = request.args.get('lang', 'en')
    data = request.get_json() or {}
    enable_verbose = data.get("enable", True) # Default to enable if not specified

    config_path = "/etc/default/readsb"
    verbose_option = "--verbose"

    try:
        lines = []
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                lines = f.readlines()

        found_decoder_options = False
        for i, line in enumerate(lines):
            if line.strip().startswith("DECODER_OPTIONS="):
                found_decoder_options = True
                current_options = line.split('=', 1)[1].strip().strip('"').strip("'")

                if enable_verbose:
                    if verbose_option not in current_options:
                        new_options = f'"{current_options.strip()} {verbose_option}"'.strip()
                        lines[i] = f"DECODER_OPTIONS={new_options}\n"
                else: # if disabling
                    if verbose_option in current_options:
                        new_options = current_options.replace(verbose_option, '').strip()
                        new_options = f'"{new_options}"' if new_options else '""'
                        lines[i] = f"DECODER_OPTIONS={new_options}\n"
                break

        if not found_decoder_options and enable_verbose:
            lines.append(f'DECODER_OPTIONS="{verbose_option}"\n')

        with open(config_path, "w") as f:
            f.writelines(lines)

        subprocess.call(["sudo", "systemctl", "restart", "readsb"])

        return jsonify({
            'ok': True,
            'result': f"readsb verbose mode {'enabled' if enable_verbose else 'disabled'}.",
            'desc': lang_desc("readsb_toggle_verbose", lang)
        })
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)})


@app.route('/api/service/readsb/status', methods=['GET'])
@login_required
def api_readsb_status():
    lang = request.args.get('lang', 'en')
    return jsonify({
        'result': run_shell("systemctl status readsb"),
        'desc': lang_desc("readsb_status", lang)
    })

@app.route('/api/service/readsb/restart', methods=['POST'])
@login_required
def api_readsb_restart():
    lang = request.args.get('lang', 'en')
    result = run_shell("sudo systemctl restart readsb")
    return jsonify({'result': result, 'desc': lang_desc("readsb_restart", lang)})

@app.route('/api/service/readsb/logs', methods=['GET'])
@login_required
def api_readsb_logs():
    lang = request.args.get('lang', 'en')
    return jsonify({
        'result': run_shell("journalctl -n 50 -u readsb --no-pager"),
        'desc': lang_desc("readsb_logs", lang)
    })

@app.route('/api/service/readsb/set-gain', methods=['POST'])
@login_required
def api_readsb_set_gain():
    lang = request.args.get('lang', 'en')
    data = request.json
    gain = str(data.get("gain", ""))
    result = run_shell(f"sudo readsb-gain {gain}")
    return jsonify({
        'result': result,
        'desc': lang_desc("readsb_set_gain", lang)
    })

# ---------- Wingbits Service Endpoints ----------
# Removed api_get_station_id and api_set_station_id endpoints as per user request.

@app.route('/api/service/wingbits/status', methods=['GET'])
@login_required
def api_wingbits_status():
    lang = request.args.get('lang', 'en')
    return jsonify({
        'result': run_shell("systemctl status wingbits"),
        'desc': lang_desc("wingbits_status", lang)
    })

@app.route('/api/service/wingbits/last-install-log', methods=['GET'])
@login_required
def api_wingbits_last_install_log():
    # Since install logs are now removed by install.sh, this will always return 'No install logs found.'
    return jsonify({
        'result': 'No install logs found as logging is disabled.',
        'desc': 'last Wingbits install log'
    })

@app.route('/api/service/wingbits/debug', methods=['GET'])
@login_required
def api_wingbits_debug():
    lang = request.args.get('lang', 'en')
    # Execute the debug script directly, as done in wb-config
    result = run_shell("curl -sL \"https://gitlab.com/wingbits/config/-/raw/master/debug.sh\" | sudo bash 2>&1")

    # Filter ANSI color codes
    result = re.sub(r'\x1B\[[0-9;]*[mGKF]', '', result)
    # Filter tput messages if they appear
    result = re.sub(r'tput: unknown terminal "[^"]+"\n?', '', result)
    result = re.sub(r'\r', '', result)

    return jsonify({
        'result': result,
        'desc': lang_desc("wingbits_debug", lang)
    })

@app.route('/api/service/wingbits/restart', methods=['POST'])
@login_required
def api_wingbits_restart():
    lang = request.args.get('lang', 'en')
    result = run_shell("sudo systemctl restart wingbits")
    return jsonify({'result': result, 'desc': lang_desc("wingbits_restart", lang)})

@app.route('/api/service/wingbits/logs', methods=['GET'])
@login_required
def api_wingbits_logs():
    lang = request.args.get('lang', 'en')
    return jsonify({
        'result': run_shell("journalctl -n 2000 -u wingbits --no-pager"),
        'desc': lang_desc("wingbits_logs", lang)
    })

@app.route('/api/service/wingbits/update-client', methods=['POST'])
@login_required
def api_wingbits_update_client():
    lang = request.args.get('lang', 'en')
    global UPDATE_PROCESS

    if UPDATE_PROCESS is not None and UPDATE_PROCESS.poll() is None:
        # An update is already in progress
        return jsonify({
            'ok': False,
            'msg': lang_desc("update_in_progress", lang),
            'result': 'Update already running.'
        })

    # No need to clear previous log file as logging is disabled
    # if not DISABLE_UPDATE_LOG and os.path.exists(UPDATE_LOG_FILE):
    #     os.remove(UPDATE_LOG_FILE)

    # Start the update in a new thread, output will be suppressed by run_shell_async
    threading.Thread(target=run_shell_async, args=(
        "curl -sL https://gitlab.com/wingbits/config/-/raw/master/install-client.sh | sudo bash",
        None # log_file_path is ignored now
    )).start()

    return jsonify({
        'ok': True,
        'msg': lang_desc("update_started", lang),
        'result': 'Wingbits client update started in the background. Logging is disabled for updates.'
    })

@app.route('/api/service/wingbits/update-logs', methods=['GET'])
@login_required
def api_wingbits_update_logs():
    lang = request.args.get('lang', 'en')
    # Since logging is disabled, we always return this message.
    log_content = "Client update logging is disabled in configuration. No logs are saved."
    
    status = "disabled" # Status reflects logging is disabled
    if UPDATE_PROCESS is not None and UPDATE_PROCESS.poll() is None:
        status = "running" # Still running even if logs are disabled
    elif UPDATE_PROCESS is None:
        status = "finished" # Or "not_started" if no process was ever active

    return jsonify({
        'ok': True,
        'status': status,
        'logs': log_content,
        'desc': lang_desc("wingbits_update_logs", lang)
    })


@app.route('/api/service/wingbits/geosigner-info', methods=['GET'])
@login_required
def api_wingbits_geosigner_info():
    lang = request.args.get('lang', 'en')
    result = run_shell("sudo wingbits geosigner info")
    return jsonify({
        'result': result,
        'desc': lang_desc("wingbits_geosigner_info", lang)
    })

@app.route('/api/service/wingbits/version', methods=['GET'])
@login_required
def api_wingbits_version():
    lang = request.args.get('lang', 'en')
    result = run_shell("wingbits -v")
    return jsonify({
        'result': result,
        'desc': lang_desc("wingbits_version", lang)
    })

# ---------- tar1090 Service Endpoints ----------
@app.route('/api/service/tar1090/restart', methods=['POST'])
@login_required
def api_tar1090_restart():
    lang = request.args.get('lang', 'en')
    result = run_shell("sudo systemctl restart tar1090")
    return jsonify({'result': result, 'desc': lang_desc("tar1090_restart", lang)})

@app.route('/api/service/tar1090/route-info', methods=['POST'])
@login_required
def api_tar1090_route_info():
    lang = request.args.get('lang', 'en')
    data = request.get_json() or {}
    enable = data.get("enable", True)
    if isinstance(enable, str):
        enable = (enable.lower() == "true")
    config_path = "/usr/local/share/tar1090/html/config.js"
    if not os.path.exists(config_path):
        result = "config.js not found!"
    else:
        with open(config_path, "r") as f:
            js = f.read()
        import re
        # Modifies the line if it's in the format : or = with any spaces
        if re.search(r"useRouteAPI\s*[:=]\s*(true|false)", js):
            js = re.sub(r"useRouteAPI\s*[:=]\s*(true|false)",
                        f"useRouteAPI = {'true' if enable else 'false'}", js)
        else:
            # If the line does not exist, add it to the end of the file
            if not js.endswith('\n'):
                js += '\n'
            js += f"useRouteAPI = {'true' if enable else 'false'};\n"
        with open(config_path, "w") as f:
            f.write(js)
        result = f"Route info {'enabled' if enable else 'disabled'}."
    return jsonify({
        'result': result,
        'desc': lang_desc("tar1090_route_info", lang)
    })

# ---------- graphs1090 Service Endpoints ----------
@app.route('/api/service/graphs1090/restart', methods=['POST'])
@login_required
def api_graphs1090_restart():
    lang = request.args.get('lang', 'en')
    return jsonify({
        'result': run_shell("sudo systemctl restart graphs1090"),
        'desc': lang_desc("graphs1090_restart", lang)
    })

@app.route('/api/service/graphs1090/colorscheme', methods=['POST'])
@login_required
def api_graphs1090_colorscheme():
    data = request.get_json()
    color = data.get('color', '')
    if color not in ['dark', 'default']:
        return jsonify({'ok': False, 'msg': 'Invalid color'})
    config_path = "/etc/default/graphs1090"
    try:
        # Read all old lines
        lines = []
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                lines = f.readlines()
        found = False
        # Modify the colorscheme line if it exists
        for i in range(len(lines)):
            if lines[i].strip().startswith("colorscheme="):
                lines[i] = f"colorscheme={color}\n"
                found = True
        # If not found, add the line
        if not found:
            lines.append(f"colorscheme={color}\n")
        # Rewrite the file
        with open(config_path, "w") as f:
            f.writelines(lines)
        # Restart the service
        import subprocess
        subprocess.call(["sudo", "systemctl", "restart", "graphs1090"])
        return jsonify({'ok': True, 'result': f"graphs1090 {color} mode enabled. Reload your graphs1090 page"})
    except Exception as e:
        return jsonify({'ok': False, 'msg': str(e)})

# ---------- System Information & Control Endpoints ----------
@app.route('/api/system/info', methods=['GET'])
@login_required
def system_info():
    try:
        # System specifications
        cpu_name = None
        if os.path.exists("/proc/cpuinfo"):
            cpu_name_output = os.popen('cat /proc/cpuinfo | grep "model name" | head -1').read()
            if cpu_name_output:
                cpu_name = cpu_name_output.split(":")[-1].strip()
        if not cpu_name:
            cpu_name = platform.processor()

        info = {
            "hostname": platform.node(),
            "os": platform.platform(),
            "cpu": cpu_name,
            "arch": platform.machine(),
            "cores": psutil.cpu_count(logical=True),
            "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else [0, 0, 0],
            "ram_total_mb": round(psutil.virtual_memory().total/1024/1024,1),
            "ram_free_mb": round(psutil.virtual_memory().available/1024/1024,1),
            "disk_total_gb": round(psutil.disk_usage('/').total/1024/1024/1024,2),
            "disk_free_gb": round(psutil.disk_usage('/').free/1024/1024/1024,2),
            "uptime_hr": round((psutil.boot_time() and ((time.time()-psutil.boot_time())/3600)) or 0,1)
        }

        # CPU temperature (for Raspberry Pi or supported devices)
        temp = None
        try:
            if os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
                with open('/sys/class/thermal/thermal_zone0/temp') as f:
                    temp = round(int(f.read()) / 1000, 1)
            else:
                temp_out = os.popen("sensors | grep 'CPU' | grep '°C'").read()
                if temp_out:
                    temp = temp_out
        except:
            temp = None
        info["cpu_temp"] = temp

        # SDR dongle status
        sdr_status = "not_connected"
        try:
            sdr_keywords = ["RTL", "2832", "2838", "SDR", "R820T", "HackRF", "Airspy", "LimeSDR", "SDRplay", "Realtek", "Radabox", "DVB"]
            lsusb_output = run_shell("lsusb").lower()
            if any(keyword.lower() in lsusb_output for keyword in sdr_keywords):
                sdr_status = "connected"
        except Exception as e:
            sdr_status = "not_connected"

        # Add sdr_status to info dictionary
        info["sdr_status"] = sdr_status
        
        return jsonify({"ok": True, "info": info})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route('/api/netstatus')
@login_required
def api_netstatus():
    import requests
    # Check internet connection
    try:
        r = requests.get("https://1.1.1.1", timeout=3)
        online = (r.status_code == 200 or r.status_code == 301 or r.status_code == 302)
    except requests.exceptions.RequestException:
        online = False

    # Check Wingbits server
    try:
        r2 = requests.get("https://api.wingbits.com/ping", timeout=5)
        server_ok = (r2.status_code == 200)
    except requests.exceptions.RequestException:
        server_ok = False

    # Get last sync time from local file (example, not mandatory)
    last_sync = None # No longer fetching from a file, can be set to None or a default

    return jsonify({"ok": True, "net": {
        "online": online,
        "server_ok": server_ok,
        "last_sync": last_sync or ""
    }})

@app.route('/api/alerts', methods=['GET'])
@login_required
def api_alerts():
    import subprocess, os, re
    alerts = []

    # 1. Check systemctl service status
    services = [("wingbits", "Wingbits"), ("readsb", "readsb"), ("tar1090", "tar1090")]
    for svc, label in services:
        try:
            out = subprocess.check_output(['systemctl', 'is-active', svc], stderr=subprocess.STDOUT).decode().strip()
            if out != "active":
                alerts.append(f"{label} service is NOT running!")
        except Exception as e:
            alerts.append(f"{label} service status unknown: {e}")

    # 2. Check for missing SDR (example)
    try:
        sdr = subprocess.check_output("lsusb | grep -i RTL2832", shell=True).decode().strip()
        if not sdr:
            alerts.append("SDR dongle is NOT detected! (RTL2832)")
    except Exception as e:
            alerts.append("SDR check failed: " + str(e))

    # 3. Check disk space
    try:
        st = os.statvfs("/")
        percent = 100 - (st.f_bavail / st.f_blocks * 100)
        if percent > 95:
            alerts.append(f"Disk is almost full: {percent:.1f}% used")
    except:
        pass

    # 4. Tail log files (wingbits, readsb, tar1090)
    # These are external log files, not directly controlled by the panel's logging preferences
    # We will still check them for alerts, but the panel won't generate them.
    logfiles = [
        ("/var/log/wingbits.log", "wingbits"),
        ("/var/log/readsb.log", "readsb"),
        ("/var/log/tar1090.log", "tar1090"),
    ]
    keywords = re.compile(r"(ERROR|FATAL|FAIL|WARNING|WARN)", re.IGNORECASE)
    for logfile, label in logfiles:
        if os.path.exists(logfile):
            try:
                lines = subprocess.check_output(["tail", "-n", "200", logfile]).decode(errors="ignore").splitlines()
                for line in lines:
                    if keywords.search(line):
                        # Don't duplicate alerts if the text is the same
                        if not any(line in a for a in alerts):
                            alerts.append(f"[{label}] {line.strip()[:400]}")
            except:
                pass

    return {"ok": True, "alerts": alerts}

@app.route('/api/status/check')
@login_required
def api_status_check():
    import subprocess, os
    def svc_status(name):
        try:
            out = subprocess.check_output(['systemctl', 'is-active', name], stderr=subprocess.STDOUT).decode().strip()
            return out == "active"
        except:
            return False

    import socket
    try:
        # Check internet
        online = False
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=2)
            online = True
        except:
            online = False

        # Get wingbits status output
        try:
            wb_status = subprocess.check_output(['sudo', 'wingbits', 'status'], stderr=subprocess.STDOUT).decode().strip()
        except Exception as e:
            wb_status = "Error: " + str(e)

        return jsonify({
            "ok": True,
            "status": {
                "internet": online,
                "wingbits": svc_status("wingbits"),
                "readsb": svc_status("readsb"),
                "tar1090": svc_status("tar1090"),
                "wb_details": wb_status  # Full wingbits status output
            }
        })
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route('/api/update/reinstall', methods=['POST'])
@login_required
def api_update_reinstall():
    import subprocess
    import json
    req = request.get_json(force=True)
    comps = req.get("components", [])

    steps = []
    try:
        if "deps" in comps:
            steps.append(("deps", subprocess.getoutput('sudo apt update && sudo apt install --reinstall -y python3 python3-pip rtl-sdr')))
        if "wingbits" in comps:
            steps.append(("wingbits", subprocess.getoutput('sudo systemctl stop wingbits ; wget -O /usr/local/bin/wingbits https://dl.wingbits.com/latest/wingbits-linux-arm64 ; chmod +x /usr/local/bin/wingbits ; sudo systemctl restart wingbits')))
        if "readsb" in comps:
            steps.append(("readsb", subprocess.getoutput('sudo systemctl stop readsb ; cd /tmp && wget https://github.com/wiedehopf/adsb-scripts/releases/latest/download/readsb.tar.xz ; tar -xJf readsb.tar.xz -C /usr/local/bin ; sudo systemctl restart readsb')))
        if "tar1090" in comps:
            steps.append(("tar1090", subprocess.getoutput('cd /usr/local/share/tar1090/html && sudo git pull')))
        if "panel" in comps:
            steps.append(("panel", subprocess.getoutput('cd /opt/wingbits-station-web && sudo git pull ; sudo systemctl restart wingbits-web-panel')))
        detail = "\n".join([f"[{name}]\n{out}" for name, out in steps])
        return jsonify({"ok": True, "msg": "All selected components updated!", "detail": detail})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route("/api/feeder/versions")
@login_required
def feeder_versions():
    import os, datetime
    try:
        wingbits_ver = os.popen("wingbits --version 2>/dev/null").read().strip() or None
        readsb_ver = os.popen("readsb --version 2>/dev/null").read().strip() or None
        tar1090_ver = os.popen("tar1090 --version 2>/dev/null").read().strip() or None
        panel_ver = "1.0.0"
        return jsonify({
            "ok": True,
            "versions": {
                "wingbits": wingbits_ver,
                "readsb": readsb_ver,
                "tar1090": tar1090_ver,
                "panel": panel_ver
            },
            "checked_at": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route('/api/service/urls', methods=['GET'])
@login_required
def api_get_urls():
    import socket
    # Get the device's primary IP
    def get_ip_address():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Try connecting to a public IP to get the actual outbound IP
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    ip_addr = get_ip_address()
    global WEB_PANEL_RUN_PORT # Access the global variable for the running port
    urls = [
        {"title": "Live map (tar1090)", "url": f"http://{ip_addr}/tar1090"},
        {"title": "Statistics (graphs1090)", "url": f"http://{ip_addr}/graphs1090"},
        {"title": "Advanced Web Panel", "url": f"http://{ip_addr}:{WEB_PANEL_RUN_PORT}"}, # Use dynamic port here
        {"title": "Wingbits Dashboard", "url": "https://dash.wingbits.com/"},
    ]
    return jsonify({"ok": True, "urls": urls})

# ---------- System Reboot/Shutdown Endpoints ----------
@app.route('/api/system/reboot', methods=['POST'])
@login_required
def api_reboot():
    lang = request.args.get('lang', 'en')
    run_shell("sudo reboot")
    return jsonify({'result': "Device is rebooting...", 'desc': lang_desc("pi_restart", lang)})

@app.route('/api/system/shutdown', methods=['POST'])
@login_required
def api_shutdown():
    lang = request.args.get('lang', 'en')
    run_shell("sudo shutdown -h now")
    return jsonify({'result': "Device is shutting down...", 'desc': lang_desc("pi_shutdown", lang)})

# ---------- Diagnostics Endpoints ----------
@app.route('/api/diagnostics/generate-log-link', methods=['POST'])
@login_required
def api_diagnostics_generate_log_link():
    lang = request.args.get('lang', 'en')
    data = request.get_json()
    log_type = data.get('type')

    if log_type == 'wingbits_readsb':
        cmd = "sudo journalctl -u wingbits -u readsb -n100000 --no-pager | curl -sS -H \"User-Agent: yes-please/2000\" -F 'file=@-' -F expires=336 https://0x0.st"
        desc = lang_desc("diagnostics_wingbits_readsb_logs", lang)
    elif log_type == 'all':
        cmd = "sudo journalctl -n100000 --no-pager | curl -sS -H \"User-Agent: yes-please/2000\" -F 'file=@-' -F expires=336 https://0x0.st"
        desc = lang_desc("diagnostics_all_logs", lang)
    else:
        return jsonify({'ok': False, 'msg': 'Invalid log type'})

    result = run_shell(cmd)
    return jsonify({'ok': True, 'result': result, 'desc': desc})

@app.route('/api/diagnostics/run-command', methods=['POST'])
@login_required
def api_diagnostics_run_command():
    lang = request.args.get('lang', 'en')
    data = request.get_json()
    command_key = data.get('command')

    commands = {
        'os_release': ("cat /etc/os-release", "diagnostics_os_release"),
        'lsusb': ("lsusb", "diagnostics_lsusb"),
        'throttled': ("vcgencmd get_throttled", "diagnostics_throttled"),
        'wingbits_status_verbose': ("sudo wingbits status --verbose", "diagnostics_wingbits_status_verbose"),
        'geosigner_info': ("sudo wingbits geosigner info", "diagnostics_geosigner_info")
    }

    if command_key in commands:
        cmd, desc_key = commands[command_key]
        # Special handling for vcgencmd as it might not be installed
        if command_key == 'throttled' and 'command not found' in run_shell("command -v vcgencmd"):
             result = "vcgencmd is not available on this system. This command is typically for Raspberry Pi devices."
        else:
             result = run_shell(cmd)
        
        desc = lang_desc(desc_key, lang)
        return jsonify({'ok': True, 'result': result, 'desc': desc})
    else:
        return jsonify({'ok': False, 'msg': 'Invalid command'})


# ---------- Miscellaneous System Info/Checks (For debug if needed) ----------
@app.route('/api/system/is-pi', methods=['GET'])
@login_required
def api_is_pi():
    lang = request.args.get('lang', 'en')
    cpuinfo = run_shell("cat /proc/cpuinfo")
    is_pi = 'Raspberry Pi' in cpuinfo or 'BCM' in cpuinfo
    return jsonify({
        'result': is_pi,
        'desc': lang_desc("is_pi", lang) if "is_pi" in DESCRIPTIONS else "Check if device is Raspberry Pi"
    })

@app.route('/api/system/is-runnable', methods=['GET'])
@login_required
def api_is_runnable():
    lang = request.args.get('lang', 'en')
    etc_issue = run_shell("cat /etc/issue")
    is_debian = 'Debian' in etc_issue or 'Ubuntu' in etc_issue or 'Raspbian' in etc_issue
    return jsonify({
        'result': is_debian,
        'desc': lang_desc("is_runnable", lang) if "is_runnable" in DESCRIPTIONS else "Check if OS is Debian-based"
    })

@app.route('/api/system/nc-installed', methods=['GET'])
@login_required
def api_nc_installed():
    lang = request.args.get('lang', 'en')
    res = run_shell("which nc")
    return jsonify({
        'result': bool(res),
        'desc': lang_desc("nc_installed", lang) if "nc_installed" in DESCRIPTIONS else "Check if netcat is installed"
    })

@app.route('/api/system/curl-installed', methods=['GET'])
@login_required
def api_curl_installed():
    lang = request.args.get('lang', 'en')
    res = run_shell("which curl")
    return jsonify({
        'result': bool(res),
        'desc': lang_desc("curl_installed", lang) if "curl_installed" in DESCRIPTIONS else "Check if curl is installed"
    })

def get_ip_address():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip

@app.route('/api/debug/info', methods=['GET'])
@login_required
def api_debug_info():
    try:
        # Execute the debug script directly, as done in wb-config
        result = run_shell("curl -sL \"https://gitlab.com/wingbits/config/-/raw/master/debug.sh\" | sudo bash 2>&1")

        # Filter ANSI color codes
        result = re.sub(r'\x1B\[[0-9;]*[mGKF]', '', result)
        # Filter tput messages if they appear
        result = re.sub(r'tput: unknown terminal "[^"]+"\n?', '', result)
        result = re.sub(r'\r', '', result)

        # Return the raw debug output as the 'result'
        return jsonify({"ok": True, "result": result})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})


# ----------- Frontend files -----------
# This route should not be protected as it serves the login page
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    root = '/opt/wingbits-station-web/frontend'
    if path != "" and os.path.exists(os.path.join(root, path)):
        return send_from_directory(root, path)
    else:
        return send_from_directory(root, "index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=WEB_PANEL_RUN_PORT) # Use the dynamic port
EOF

echo "Backend Flask app written."
echo ""
