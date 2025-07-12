#!/bin/bash

# Set up project directory structure and Python venv

set -e

echo "Setting up project folders..."

INSTALL_DIR="/opt/wingbits-station-web"
BACKEND_DIR="$INSTALL_DIR/backend"
FRONTEND_DIR="$INSTALL_DIR/frontend"
CONF_DIR="$INSTALL_DIR/conf"
STATIC_DIR="$FRONTEND_DIR/static"
TEMPLATES_DIR="$FRONTEND_DIR/templates"

mkdir -p "$BACKEND_DIR" "$FRONTEND_DIR" "$CONF_DIR" "$STATIC_DIR" "$TEMPLATES_DIR"

# Initialize Python virtual environment for the backend
python3 -m venv "$BACKEND_DIR/venv"

# Set permissions for the main directory
# Get the user who executed sudo
if [ -n "$SUDO_USER" ]; then
    chown -R $SUDO_USER:$SUDO_USER "$INSTALL_DIR"
else
    # Fallback if SUDO_USER is not set (e.g., direct root login)
    echo "Warning: SUDO_USER not set. Setting ownership to current user. Consider running with 'sudo'."
    chown -R $(whoami):$(whoami) "$INSTALL_DIR"
fi


echo "Project folder structure created."
echo ""