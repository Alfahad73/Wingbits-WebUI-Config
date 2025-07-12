#!/bin/bash

# Install essential dependencies (system packages)

set -e

echo "Installing essential system packages..."
apt-get update
apt-get install -y python3 python3-pip python3-venv curl netcat-traditional

# Optional: Install Nginx if you plan to use it for reverse proxy in the future
# apt-get install -y nginx

echo "All base packages installed!"
echo ""