#!/bin/bash
# ============================================
# One-Click Deploy Script for DRL DDoS Detection
# Works on: Ubuntu 20.04+, AWS EC2 Ubuntu
# Usage: sudo bash deploy.sh
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_NAME="drl-detection"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo -e "${BLUE}"
echo "========================================="
echo "  DRL DDoS Detection - Auto Deploy"
echo "========================================="
echo -e "${NC}"

# --- Step 1: System Dependencies ---
echo -e "${YELLOW}[1/7] Installing system dependencies...${NC}"
apt-get update -qq
apt-get install -y -qq \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libpcap-dev \
    iptables \
    net-tools \
    curl \
    wget \
    git \
    > /dev/null 2>&1
echo -e "${GREEN}✓ System packages installed${NC}"

# --- Step 2: Auto-detect Network Interface ---
echo -e "${YELLOW}[2/7] Detecting network interface...${NC}"
# Prefer interfaces that are UP and have traffic (RX packets > 0)
INTERFACE=$(ip -o link show up 2>/dev/null | awk -F': ' '$2 !~ /lo|docker|veth|br-/ {print $2}' | sed 's/@.*//' | while read iface; do
    rx=$(ip -s link show "$iface" 2>/dev/null | awk '/RX:/{getline; print $2}')
    echo "$rx $iface"
done | sort -rn | head -1 | awk '{print $2}')

if [ -z "$INTERFACE" ]; then
    # Fallback: any non-loopback interface
    INTERFACE=$(ip -o link show | awk -F': ' '$2 !~ /lo|docker|veth|br-/ {print $2}' | head -1 | sed 's/@.*//')
fi

if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"
    echo -e "${YELLOW}! Could not auto-detect, defaulting to eth0${NC}"
else
    echo -e "${GREEN}✓ Detected interface: ${INTERFACE}${NC}"
fi

# --- Step 3: Setup Python Environment ---
echo -e "${YELLOW}[3/7] Setting up Python environment...${NC}"
cd "$APP_DIR"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# --- Step 4: Configure .env ---
echo -e "${YELLOW}[4/7] Configuring application...${NC}"
if [ ! -f ".env" ]; then
    cp .env.example .env
fi

# Auto-update interface in .env
sed -i "s/CAPTURE_INTERFACE=.*/CAPTURE_INTERFACE=${INTERFACE}/" .env
# Set production defaults
sed -i "s/FLASK_DEBUG=.*/FLASK_DEBUG=false/" .env
sed -i "s/FLASK_HOST=.*/FLASK_HOST=0.0.0.0/" .env
echo -e "${GREEN}✓ Configured for ${INTERFACE} (production mode)${NC}"

# --- Step 5: Create Directories ---
echo -e "${YELLOW}[5/7] Creating directories...${NC}"
mkdir -p capapp/capture_output/{in_progress,error}
mkdir -p capapp/features_output
mkdir -p capapp/logs
mkdir -p data/predictions
mkdir -p detection_module/trained_models
echo -e "${GREEN}✓ Directories ready${NC}"

# --- Step 6: Setup Systemd Service ---
echo -e "${YELLOW}[6/7] Installing systemd service...${NC}"

PYTHON_BIN="$(pwd)/.venv/bin/python3"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=DRL DDoS Detection Application
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
ExecStart=${PYTHON_BIN} ${APP_DIR}/app.py
Restart=always
RestartSec=5
StandardOutput=append:${APP_DIR}/flask.log
StandardError=append:${APP_DIR}/flask.log
Environment=PATH=${APP_DIR}/.venv/bin

# Security
NoNewPrivileges=false
ProtectSystem=false

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" 2>/dev/null || true
echo -e "${GREEN}✓ Service installed (disabled - start manually)${NC}"

# --- Step 7: Set Permissions ---
echo -e "${YELLOW}[7/7] Setting up packet capture permissions...${NC}"
setcap cap_net_raw,cap_net_admin+eip "$PYTHON_BIN" 2>/dev/null || true
echo -e "${GREEN}✓ Capabilities set${NC}"

# --- Done ---
echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}  ✓ Deployment Complete!${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo -e "${YELLOW}Commands:${NC}"
echo -e "  Start:    ${GREEN}sudo systemctl start ${SERVICE_NAME}${NC}"
echo -e "  Stop:     ${GREEN}sudo systemctl stop ${SERVICE_NAME}${NC}"
echo -e "  Status:   ${GREEN}sudo systemctl status ${SERVICE_NAME}${NC}"
echo -e "  Logs:     ${GREEN}sudo journalctl -u ${SERVICE_NAME} -f${NC}"
echo ""
echo -e "${YELLOW}Dashboard:${NC}"
echo -e "  Local:    ${GREEN}http://localhost:5000${NC}"
echo -e "  Network:  ${GREEN}http://$(hostname -I | awk '{print $1}'):5000${NC}"
echo ""
echo -e "${YELLOW}AWS EC2? Open port 5000 in Security Group${NC}"
echo ""
