#!/bin/bash

# ==========================================
# Wingbits Station Web Config - Installer
# ==========================================

set -e

REPO_URL="https://github.com/Alfahad73/Wingbits-WebUI.git"
INSTALL_DIR="/opt/wingbits-station-web"
SERVICE_PATH="/etc/systemd/system/wingbits-web-panel.service"
AUTH_FILE="$INSTALL_DIR/conf/auth.json"
BACKEND_DIR="$INSTALL_DIR/backend"
CONFIG_FILE="$INSTALL_DIR/conf/config.json" # ملف الإعدادات الجديد
# LOGROTATE_CONFIG_FILE="/etc/logrotate.d/wingbits-web-panel" # ملف إعدادات logrotate الجديد - تم تعطيله

# --- Check for root privileges ---
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Please run as root (e.g. sudo bash $0)"
    exit 1
fi

# Define a unique temporary directory for cloning the repository
TEMP_CLONE_DIR="/tmp/wingbits_webui_temp_$(date +%s%N)"

# --- Handle existing installation at the final destination ---
# Check if the final INSTALL_DIR exists or if the service file exists
if [ -d "$INSTALL_DIR" ] || [ -f "$SERVICE_PATH" ]; then
    force_reinstall="" # Initialize variable to control forced reinstallation

    # If REINSTALL_FLAG is set to 1 (e.g., via `REINSTALL_FLAG=1 curl ... | sudo bash`),
    # proceed with removal without asking for confirmation.
    if [ "$REINSTALL_FLAG" = "1" ]; then
        echo "✅ Wingbits Web Panel appears to be already installed. Forcing reinstallation."
        force_reinstall="y"
    else
        echo "✅ Wingbits Web Panel appears to be already installed."
        echo "💡 If you're experiencing issues or forgot your password, you may reinstall."
        
        # Add more specific information about why it's detected as installed
        if [ -d "$INSTALL_DIR" ]; then
            echo "   - Installation directory ($INSTALL_DIR) already exists."
        fi
        if [ -f "$SERVICE_PATH" ]; then
            echo "   - Systemd service file ($SERVICE_PATH) already exists."
        fi
        echo ""
        while true; do
            read -p "❓ Are you sure you want to delete and reinstall it? [y/N]: " answer </dev/tty
            case "$answer" in
                [Yy]* )
                    force_reinstall="y"
                    break # Exit the while loop to proceed with removal
                    ;;
                [Nn]* | "" )
                    echo "❌ Installation aborted by user."
                    rm -rf "$TEMP_CLONE_DIR" # Clean up the temporary cloned directory
                    exit 0;;
                * )
                    echo "Please answer yes (y) or no (n).";;
            esac
        done
    fi

    # If reinstallation is confirmed (either by user or REINSTALL_FLAG), remove the old installation.
    if [ "$force_reinstall" = "y" ]; then
        echo "🗑️  Removing previous installation..."
        # Stop the service gracefully before removing files
        systemctl stop wingbits-web-panel.service &>/dev/null || true
        systemctl disable wingbits-web-panel.service &>/dev/null || true
        rm -f "$SERVICE_PATH" &>/dev/null || true # Remove the old systemd service file
        rm -rf "$INSTALL_DIR" &>/dev/null || true # Remove the old installation directory
        # rm -f "$LOGROTATE_CONFIG_FILE" &>/dev/null || true # Remove old logrotate config - تم تعطيله
        systemctl daemon-reexec &>/dev/null || true # Reload systemd manager configuration
        systemctl daemon-reload &>/dev/null || true # Reload systemd unit files
        echo "✅ Previous installation removed."
    fi
fi

# --- Clone the repository to the temporary location ---
echo "📦 Cloning Wingbits-WebUI project to temporary directory $TEMP_CLONE_DIR ..."
git clone "$REPO_URL" "$TEMP_CLONE_DIR" || { echo "❌ Failed to clone repository. Aborting."; exit 1; }

# --- Move cloned project from temporary directory to final installation directory ---
echo "🚚 Moving project files from $TEMP_CLONE_DIR to $INSTALL_DIR ..."
# Ensure the parent directory for INSTALL_DIR exists
mkdir -p "$(dirname "$INSTALL_DIR")"

# Move the entire temporary directory to the final installation path.
# If INSTALL_DIR didn't exist (fresh install or just removed), mv will create it.
mv "$TEMP_CLONE_DIR" "$INSTALL_DIR" || { echo "❌ Failed to move project files from $TEMP_CLONE_DIR to $INSTALL_DIR. Aborting."; exit 1; }

# Set SCRIPT_DIR to the final installation directory.
# All subsequent script operations will now correctly reference files from this path.
SCRIPT_DIR="$INSTALL_DIR"
echo "✅ Project files moved to $INSTALL_DIR."

echo ""
echo "======================================"
echo "      Wingbits Station Web Config"
echo "      Web Control Panel Installation Script"
echo ""
echo "This script will install all requirements, create the necessary files,"
echo "setup the web backend/frontend, and start the service automatically."
echo ""

# --- Check Wingbits client ---
# Verifies if the Wingbits client is installed on the system.
if ! command -v wingbits &> /dev/null; then
    echo "------------------------------------------------------------"
    echo "❌ Wingbits client is not installed."
    echo "➡️  Please install the Wingbits client from your 'My Stations' dashboard:"
    echo "    https://wingbits.com/dashboard/stations"
    echo "------------------------------------------------------------"
    exit 1
fi
echo "✅ Wingbits client is installed."

# --- Check wb-config ---
# Verifies if the wb-config utility is installed.
if ! command -v wb-config &> /dev/null; then
    echo "------------------------------------------------------------"
    echo "❌ wb-config is not installed."
    echo "➡️  Install it using:"
    echo "    curl -sL https://gitlab.com/wingbits/config/-/raw/master/wb-config/install.sh | sudo bash"
    echo "--------------------------------------------------------------------------------"
    exit 1
fi
echo "✅ wb-config is installed."

# --- Set scripts executable ---
# Ensures all helper scripts in the same directory are executable.
echo "🔧 Setting execute permissions for sub-scripts..."
# SCRIPT_DIR is already set to $INSTALL_DIR at this point
chmod +x "$SCRIPT_DIR"/*.sh
echo "✅ Permissions set."

# --- Run setup scripts ---
# Executes the various setup stages for the web panel.
echo "🚀 Starting installation..."
"$SCRIPT_DIR/dependencies.sh"
"$SCRIPT_DIR/project-setup.sh"
"$SCRIPT_DIR/backend-deps.sh"

# --- Setup credentials ---
# Prompts the user to set up admin credentials for the web panel.
echo ""
echo "========================================"
echo "    Setup Web Panel Admin Credentials"
echo "========================================"

if [ -f "$AUTH_FILE" ]; then
    echo "🔐 Authentication file already exists. Skipping credential setup."
    echo "🔄 Use 'Change Password' in the web panel if needed."
else
    while true; do
        read -p "👤 Enter desired username: " USERNAME </dev/tty
        read -s -p "🔑 Enter desired password (min 6 characters): " PASSWORD </dev/tty
        echo
        read -s -p "🔁 Confirm password: " CONFIRM_PASSWORD </dev/tty
        echo

        if [ -z "$USERNAME" ]; then
            echo "⚠️  Username cannot be empty."
        elif [ "$PASSWORD" != "$CONFIRM_PASSWORD" ]; then
            echo "⚠️  Passwords do not match."
        elif [ ${#PASSWORD} -lt 6 ]; then
            echo "⚠️  Password must be at least 6 characters."
        else
            mkdir -p "$(dirname "$AUTH_FILE")"
            # Activate the Python virtual environment for password hashing.
            source "$BACKEND_DIR/venv/bin/activate"

            # Use a here-document to execute Python code for password hashing.
            python3 - <<END
import json, os
from werkzeug.security import generate_password_hash

data = {
    "username": "$USERNAME",
    "password_hash": generate_password_hash("$PASSWORD")
}
with open("$AUTH_FILE", 'w') as f:
    json.dump(data, f)
os.chmod("$AUTH_FILE", 0o600)
print("✅ Credentials saved.")
END
            # Deactivate the virtual environment.
            deactivate
            break
        fi
    done
fi

# --- Ask for desired port ---
echo ""
echo "========================================"
echo "    Setup Web Panel Port"
echo "========================================"
echo "Please enter the port number you want the web panel to run on."
echo "The default port is 5000."
echo ""

DEFAULT_PORT=5000
read -p "Enter desired port (e.g., 80, 8080, 5000) [${DEFAULT_PORT}]: " USER_PORT </dev/tty
USER_PORT=${USER_PORT:-$DEFAULT_PORT} # Use default if empty

# Validate port is a number
if ! [[ "$USER_PORT" =~ ^[0-9]+$ ]]; then
    echo "Invalid port number. Using default port ${DEFAULT_PORT}."
    USER_PORT=$DEFAULT_PORT
fi

# Save the port and log preference to a config file
mkdir -p "$(dirname "$CONFIG_FILE")"
cat > "$CONFIG_FILE" <<EOF
{
    "port": $USER_PORT,
    "disable_update_log": true
}
EOF
chmod 600 "$CONFIG_FILE" # Set restrictive permissions
echo "Web panel will run on port ${USER_PORT}."
echo "Configuration saved to $CONFIG_FILE."
echo ""

# --- Remove /var/log/wingbits directory and any logrotate config for it ---
echo "🗑️ Removing /var/log/wingbits directory and logrotate config to disable all panel-related logs..."
rm -rf /var/log/wingbits # Remove the directory and its contents
# rm -f "$LOGROTATE_CONFIG_FILE" # Remove logrotate config if it exists - تم تعطيله
echo "✅ Panel-related logs disabled."
echo ""


# Write backend application (app.py) and frontend (index.html)
"$SCRIPT_DIR/backend-app.sh"
"$SCRIPT_DIR/frontend-html.sh"

# --- Final steps ---
# Sets up the systemd service and displays the final message.
"$SCRIPT_DIR/systemd-service.sh"
"$SCRIPT_DIR/final-message.sh"

exit 0
