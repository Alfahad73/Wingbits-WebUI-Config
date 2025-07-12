#!/bin/bash

# Set up systemd service for Wingbits web panel

set -e

echo "Setting up systemd service to run the control panel..."

INSTALL_DIR="/opt/wingbits-station-web"
BACKEND_DIR="$INSTALL_DIR/backend"
CONFIG_FILE="$INSTALL_DIR/conf/config.json" # Path to the config file

# Read the port from the config file
WEB_PANEL_PORT="5000" # Default fallback
if [ -f "$CONFIG_FILE" ]; then
    # Use python to parse JSON and extract the port
    PARSED_PORT=$(python3 -c "import json; f=open('$CONFIG_FILE'); data=json.load(f); f.close(); print(data.get('port', 5000))")
    if [[ "$PARSED_PORT" =~ ^[0-9]+$ ]]; then
        WEB_PANEL_PORT="$PARSED_PORT"
    fi
fi

cat > /etc/systemd/system/wingbits-web-panel.service <<EOF
[Unit]
Description=Wingbits Station Web Config Panel
After=network.target

[Service]
User=root
WorkingDirectory=$BACKEND_DIR
ExecStart=$BACKEND_DIR/venv/bin/python3 $BACKEND_DIR/app.py > /dev/null 2>&1
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wingbits-web-panel.service
systemctl restart wingbits-web-panel.service

echo ""
echo "The control panel is now running as a persistent service!"
echo ""
