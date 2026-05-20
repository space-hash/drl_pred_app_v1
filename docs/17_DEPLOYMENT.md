# Deployment Guide — Setup & Production Deployment

**Files:**
- `setup.sh` (71 lines) — Automated setup script
- `deploy.sh` (174 lines) — One-click production deploy
- `docker-compose.yml` (26 lines) — Docker deployment
- `DEPLOY.md` (89 lines) — Quick deploy guide
- `DEPLOYMENT.md` (117 lines) — Detailed deployment guide

## Overview

The system supports three deployment methods: automated setup script, one-click production deploy, and Docker Compose.

---

## Method 1: Automated Setup (`setup.sh`)

```bash
./setup.sh
```

### What It Does

```
setup.sh
│
├── 1. Create Python virtual environment
│   └── python3 -m venv .venv
│
├── 2. Install Python dependencies
│   └── .venv/bin/pip install -r requirements.txt
│
├── 3. Create .env file from template
│   └── cp .env.example .env (if .env doesn't exist)
│
├── 4. Create required directories
│   ├── capapp/capture_output/
│   ├── capapp/capture_output/in_progress/
│   ├── capapp/capture_output/error/
│   ├── capapp/features_output/
│   ├── capapp/logs/
│   ├── data/predictions/
│   └── detection_module/trained_models/
│
├── 5. Set network capabilities for packet capture
│   └── sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
│
└── 6. Print next steps
    └── source .venv/bin/activate && python app.py
```

---

## Method 2: Production Deploy (`deploy.sh`)

```bash
sudo ./deploy.sh
```

### What It Does

```
deploy.sh
│
├── 1. Install system packages
│   └── apt-get install: python3, python3-venv, python3-pip,
│       tcpdump, iptables, ip6tables, psutil deps
│
├── 2. Auto-detect network interface
│   ├── Check common interfaces: eth0, enp0s3, ens33
│   └── Fall back to: first non-lo interface from `ip link`
│
├── 3. Set up Python environment
│   ├── Create venv
│   └── Install requirements
│
├── 4. Configure .env
│   ├── Set CAPTURE_INTERFACE to detected interface
│   └── Set MITIGATION_ENABLED=true
│
├── 5. Create directories
│   └── Same as setup.sh
│
├── 6. Install systemd service
│   └── Create /etc/systemd/system/drl-ddos.service
│       ├── [Unit]
│       │   Description=DRL DDoS Detection System
│       │   After=network.target
│       │
│       ├── [Service]
│       │   Type=simple
│       │   User=root
│       │   WorkingDirectory=/opt/drl_pred_app
│       │   ExecStart=/opt/drl_pred_app/.venv/bin/python app.py
│       │   Restart=on-failure
│       │   RestartSec=5
│       │
│       └── [Install]
│           WantedBy=multi-user.target
│
├── 7. Set capabilities
│   └── setcap cap_net_raw,cap_net_admin+eip python3
│
├── 8. Initialize iptables firewall chain
│   ├── iptables -N DDOS_BLOCK
│   ├── iptables -I INPUT -j DDOS_BLOCK
│   ├── ip6tables -N DDOS_BLOCK
│   └── ip6tables -I INPUT -j DDOS_BLOCK
│
└── 9. Enable and start service
    ├── systemctl daemon-reload
    ├── systemctl enable drl-ddos
    └── systemctl start drl-ddos
```

### Service Management

```bash
# Start
sudo systemctl start drl-ddos

# Stop
sudo systemctl stop drl-ddos

# Restart
sudo systemctl restart drl-ddos

# Check status
sudo systemctl status drl-ddos

# View logs
sudo journalctl -u drl-ddos -f
```

---

## Method 3: Docker Compose

```bash
docker-compose up -d
```

### docker-compose.yml

```yaml
version: '3.8'
services:
  drl-ddos:
    build: .
    network_mode: host          # Required for packet capture
    cap_add:
      - NET_ADMIN               # Required for iptables
      - NET_RAW                 # Required for raw sockets
    volumes:
      - .:/app                  # Mount project directory
      - /var/log/drl-ddos:/app/capapp/logs  # Persistent logs
    environment:
      - FLASK_HOST=0.0.0.0
      - FLASK_PORT=5000
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/api/status"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Docker Requirements

| Requirement | Why |
|------------|-----|
| `network_mode: host` | Packet capture needs direct NIC access |
| `NET_ADMIN` capability | iptables rule management |
| `NET_RAW` capability | Raw socket creation for sniffing |
| Volume mount for logs | Persistent log storage across restarts |

---

## AWS EC2 Deployment

### Instance Requirements

| Spec | Minimum | Recommended |
|------|---------|-------------|
| vCPU | 2 | 4+ |
| RAM | 4 GB | 8 GB+ |
| Storage | 20 GB | 50 GB+ |
| Network | Standard | Enhanced networking |

### Security Group Rules

| Type | Protocol | Port | Source |
|------|----------|------|--------|
| SSH | TCP | 22 | Your IP |
| HTTP | TCP | 5000 | Your IP / 0.0.0.0/0 |

### Deployment Steps

```bash
# 1. Connect to EC2
ssh -i key.pem ubuntu@<ec2-ip>

# 2. Clone repository
git clone <repo-url>
cd drl_pred_app_v1

# 3. Run production deploy
sudo ./deploy.sh

# 4. Access dashboard
#    http://<ec2-ip>:5000
```

---

## Testing Without Root

For development/testing without root privileges:

```bash
# Use loopback interface for testing
CAPTURE_INTERFACE=lo python app.py

# Or use a pcap replay tool
sudo tcpreplay -i lo test_traffic.pcap
```

Note: The privilege check (`check_privileges()`) will fail without `cap_net_raw`, but the Flask dashboard will still load. Only the pipeline start will be blocked.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No suitable network interface" | Check `CAPTURE_INTERFACE` in `.env` |
| "Permission denied" on start | Run `sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)` |
| iptables chain already exists | Normal — the code handles this gracefully |
| Model not found | Ensure `.pt` file exists at `MODEL_PATH` |
| CUDA out of memory | Set `FORCE_CPU=true` in `.env` |
| Port 5000 already in use | Change `FLASK_PORT` in `.env` |
| eBPF not available | Set `EBPF_ENABLED=false` (requires BCC library) |
