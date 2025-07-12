#!/bin/bash

# Install Python libraries for backend in venv

set -e

echo "Installing Python backend requirements..."

INSTALL_DIR="/opt/wingbits-station-web"
BACKEND_DIR="$INSTALL_DIR/backend"

source "$BACKEND_DIR/venv/bin/activate"
pip install --upgrade pip
pip install flask flask_cors psutil requests

deactivate

echo "Backend Python packages installed!"
echo ""