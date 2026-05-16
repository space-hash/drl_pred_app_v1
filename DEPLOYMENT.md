# DRL DDoS Detection - Deployment Guide

## Prerequisites
- Python 3.14+
- Linux system with network interface access
- sudo password: `1234567890`

## Quick Start

### 1. Install Dependencies
```bash
cd /home/clg/rajesh/drl_pred_app_v1
python3 -m pip install -r requirements.txt --break-system-packages
```

### 2. Configure Environment
The `.env` file is pre-configured with your network interface:
```ini
CAPTURE_INTERFACE=wlp0s20f3
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false
ROTATE_INTERVAL_SECONDS=10
DISPATCHER_POLL_INTERVAL_SECONDS=5
MODEL_PATH=./detection_module/trained_models/final_drl1.pt
```

**Note:** `ROTATE_INTERVAL_SECONDS=10` provides near-real-time detection (~15s latency) while avoiding race conditions and pipeline backlogs.

### 3. Run with Packet Capture Privileges
```bash
# Install pip for root (one-time setup)
echo "1234567890" | sudo -S apt-get install -y python3-pip

# Install Python packages for root
echo "1234567890" | sudo -S pip3 install flask torch numpy pandas scapy requests scikit-learn python-dotenv matplotlib seaborn joblib --break-system-packages

# Start the app with sudo (enables live packet capture)
echo "1234567890" | sudo -S python3 app.py &>/tmp/flask_sudo.log &
```

### 4. Access the Dashboard
- **Web UI**: http://127.0.0.1:5000
- **API Status**: http://127.0.0.1:5000/api/status

## Testing Without Root

### Run App (No Live Capture)
```bash
python3 app.py
```

### Generate Sample Data
```bash
python3 generate_sample_data.py --output capapp/features_output --n 5 --flash-crowd-ratio 0.2
```

### Train New Model
```bash
python3 train.py --data capapp/features_output/sample_data.csv --epochs 100
```

### Evaluate Model
```bash
python3 evaluate_model.py --model detection_module/trained_models/final_drl1.pt --data capapp/features_output/sample_data.csv
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard UI |
| GET | `/api/status` | System status |
| GET | `/api/detections` | Recent detections |
| GET | `/api/stats` | Detection statistics |
| GET | `/api/model_status` | Model update status |
| POST | `/api/data` | Submit prediction results |
| POST | `/raw_data` | Submit raw feature data |
| POST | `/api/update_model` | Trigger model update |

## Troubleshooting

### "Missing packet capture privileges"
Run with sudo or set capabilities:
```bash
echo "1234567890" | sudo -S python3 app.py
```

### "Model not loaded"
Ensure model file exists at path specified in `.env`:
```bash
ls -la detection_module/trained_models/final_drl1.pt
```

### Port 5000 already in use
```bash
pkill -f "python3 app.py"
python3 app.py
```

## Project Structure
```
drl_pred_app_v1/
├── app.py                    # Flask web application
├── .env                      # Environment configuration
├── requirements.txt          # Python dependencies
├── capapp/                   # Packet capture module
├── core/                     # Pipeline controller
├── detection_module/         # DRL model & prediction
├── data/                     # Output predictions
├── train.py                  # Train new models
├── evaluate_model.py         # Evaluate model accuracy
├── model_manager.py          # Model version management
├── compare_models.py         # Compare model performance
├── generate_sample_data.py   # Generate test data
└── add_model_metadata.py     # Add model metadata
```
