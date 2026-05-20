# Quick Deploy Guide

## Method 1: One-Click Script (Recommended)

```bash
# Clone or copy project to target machine
cd drl_pred_app_v1

# Run deploy script (auto-installs everything)
sudo bash deploy.sh

# Start the service
sudo systemctl start drl-detection

# View logs
sudo journalctl -u drl-detection -f
```

**Access:** `http://<your-ip>:5000`

---

## Method 2: Docker (Cleanest)

```bash
# Build and run
sudo docker compose up -d

# View logs
sudo docker compose logs -f
```

**Access:** `http://<your-ip>:5000`

---

## Method 3: Manual Setup

```bash
# Install dependencies
sudo apt update && sudo apt install -y python3-venv libpcap-dev iptables

# Setup app
bash setup.sh

# Run
sudo .venv/bin/python3 app.py
```

---

## AWS EC2 Specific

1. Launch Ubuntu 22.04+ instance
2. Security Group: Open port **5000** (TCP)
3. SSH in and run:

```bash
git clone <your-repo>
cd drl_pred_app_v1
sudo bash deploy.sh
sudo systemctl start drl-detection
```

4. Access: `http://<ec2-public-ip>:5000`

---

## Service Commands

| Action | Command |
|--------|---------|
| Start | `sudo systemctl start drl-detection` |
| Stop | `sudo systemctl stop drl-detection` |
| Restart | `sudo systemctl restart drl-detection` |
| Status | `sudo systemctl status drl-detection` |
| Logs | `sudo journalctl -u drl-detection -f` |
| Auto-start on boot | `sudo systemctl enable drl-detection` |

---

## Configuration

Edit `.env` file:
- `CAPTURE_INTERFACE` - Network interface (auto-detected)
- `FLASK_PORT` - Dashboard port (default: 5000)
- `MITIGATION_RATE_LIMIT_PPM` - Rate limit threshold

After editing: `sudo systemctl restart drl-detection`
