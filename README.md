# DRL App Detect

A Flask-based real-time DDoS detection dashboard backed by a packet-capture pipeline, CIC-style feature extraction, and a deep reinforcement learning model.

## About The Project

This project captures live network traffic, rotates it into `.pcap` files, extracts per-flow network features, and runs those features through a trained DRL model to classify traffic as normal or DDoS. A Flask web UI is included to start and stop the pipeline, inspect system status, and review recent detections.

### Main workflow

1. `capapp/capture/packet_capture.py` captures packets from a network interface and writes rotating `.pcap` files.
2. `capapp/processing/dispatcher.py` picks up those capture files and sends them to the feature extractor.
3. `capapp/processing/feature_extractor/cic_extractor.py` converts traffic flows into feature CSV files under `capapp/features_output/`.
4. `detection_module/predict_pipeline.py` watches for new feature CSV files, preprocesses them, loads the DRL model, and writes prediction CSVs to `data/predictions/`.
5. `app.py` serves the dashboard and exposes API endpoints for status, detections, and model updates.

## Project Structure

```text
.
├── app.py                         # Flask dashboard entry point
├── .env.example                   # Environment variable template
├── core/controller.py            # Starts/stops capture + prediction services
├── capapp/                       # Packet capture and feature extraction pipeline
│   ├── capture/
│   ├── config/
│   ├── orchestration/
│   ├── processing/
│   │   └── feature_extractor/
│   ├── storage/
│   └── utils/
├── detection_module/             # DRL model inference and model updater
│   ├── detection.py
│   ├── model_update.py
│   ├── predict_pipeline.py
│   └── trained_models/
├── data/predictions/             # Generated prediction CSV output
├── templates/                    # Flask HTML templates
├── train.py                      # Model training script
├── evaluate_model.py             # Model evaluation & validation
├── compare_models.py             # Model comparison utility
├── model_manager.py              # Model lifecycle management
├── generate_sample_data.py       # Synthetic data generator
├── add_model_metadata.py         # Add metadata to existing models
├── MODEL.md                      # Detailed model documentation
├── setup.sh                      # Automated setup script
└── requirements.txt
```

## Requirements

- Python 3.10+ recommended
- Linux environment for raw packet capture
- Root privileges or Linux capabilities for packet sniffing
- Access to the network interface you want to capture from

Python dependencies are listed in [requirements.txt](requirements.txt).

## Setup

### Quick Setup (Recommended)

```bash
chmod +x setup.sh
./setup.sh
```

### Manual Setup

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd drl_pred_app_v1
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Create your local environment file

```bash
cp .env.example .env
```

Edit `.env` for your machine before running the app.

### 5. Configure packet capture permissions

The app uses raw sockets and Scapy. On Linux, either run the app with `sudo` or grant your Python interpreter the required capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")"
```

If you use a virtual environment, apply `setcap` to that environment's Python binary.

## Configuration

The application loads environment variables from `.env` automatically through [capapp/config/settings.py](capapp/config/settings.py).

### Important `.env` values

```bash
CAPTURE_INTERFACE=eth0
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=true
FLASK_APP_URL=http://127.0.0.1:5000

MODEL_PATH=./detection_module/trained_models/final_drl1.pt
PROCESSED_FEATURES_DIR=./capapp/features_output
PREDICTION_OUTPUT_DIR=./data/predictions

MODEL_API_URL=http://your-model-server/api/pipeline/model/download
MODEL_UPDATE_INTERVAL_HOURS=2
FORCE_CPU=true
```

If the configured interface is unavailable, the code attempts to auto-select the first non-loopback interface.

### Configuration files

- Use [.env.example](.env.example) as the template.
- Keep your real `.env` local only. It is ignored by Git.
- Centralized config now lives in [capapp/config/settings.py](capapp/config/settings.py).

## How To Run

### Run the Flask dashboard

```bash
python3 app.py
```

The dashboard starts using the `FLASK_HOST` and `FLASK_PORT` values from `.env`.

### Start the detection pipeline

Open the dashboard in a browser and click **Start Pipeline**, or call the route directly:

```bash
curl -X POST http://127.0.0.1:5000/start
```

### Stop the detection pipeline

```bash
curl -X POST http://127.0.0.1:5000/stop
```

## API Endpoints

- `GET /` - Dashboard UI
- `POST /start` - Start detection pipeline
- `POST /stop` - Stop detection pipeline
- `GET /api/status` - Current pipeline status
- `GET /api/detections` - Recent detections (with pagination)
- `GET /api/detections/<detection_id>` - Details for one detection
- `GET /api/stats` - Detection counters and throughput
- `GET /api/model_status` - Current model update status
- `POST /api/update_model` - Trigger a model download/update
- `POST /api/data` - Receive prediction results (internal)
- `POST /raw_data` - Receive raw feature data (internal)

## Model Management

See [MODEL.md](MODEL.md) for detailed model documentation.

### Generate Sample Data

```bash
# Generate train/test split with Flash Crowd data (reduces false positives)
python generate_sample_data.py --output data/ --split train test --n 10000 --flash-crowd-ratio 0.2

# Generate without Flash Crowd (legacy behavior)
python generate_sample_data.py --output data/ --split train test --n 10000
```

### Train a New Model

```bash
# With synthetic data (testing)
python train.py --auto-generate --n-samples 10000 --epochs 100 --output detection_module/trained_models/my_model.pt

# With real CICFlowMeter CSV
python train.py --data data/train.csv --epochs 500 --output detection_module/trained_models/my_model.pt

# List all models
python train.py --list-models
```

### Evaluate a Model

```bash
# With synthetic data + full report
python evaluate_model.py --model detection_module/trained_models/final_drl1.pt --auto-generate --report

# With real data + benchmark
python evaluate_model.py --model detection_module/trained_models/final_drl1.pt --data data/test.csv --benchmark --report

# Save results to JSON
python evaluate_model.py --model detection_module/trained_models/final_drl1.pt --auto-generate --output results/eval.json
```

### Compare Models

```bash
python compare_models.py detection_module/trained_models/*.pt --auto-generate --benchmark
```

### Manage Models

```bash
python model_manager.py list detection_module/trained_models/ -v
python model_manager.py validate detection_module/trained_models/final_drl1.pt
python model_manager.py info detection_module/trained_models/final_drl1.pt
python model_manager.py cleanup detection_module/trained_models/ --keep 3 --dry-run
```

## Generated Runtime Directories

These directories are expected to change while the system runs and are now ignored by Git:

- `capapp/capture_output/`
- `capapp/features_output/`
- `capapp/logs/`
- `data/predictions/`

## Notes And Caveats

- This project is designed for Linux-style packet capture and may not work on Windows without major changes.
- The model updater depends on a reachable remote API endpoint.
- The repository contains both inference code and packet-processing code in one app, so deployment should be treated as a development setup unless you harden configuration and networking.
- `.env` is loaded only if `python-dotenv` is installed, which is now included in [requirements.txt](requirements.txt).

## Troubleshooting

### "Insufficient privileges"

Run with `sudo` or grant the Python binary `cap_net_raw` and `cap_net_admin`.

### No packets are being captured

- Confirm the selected interface exists.
- Check that traffic is actually flowing through that interface.
- Verify the process has permission to sniff packets.

### Model update fails

- Confirm the machine can reach the `MODEL_API_URL` configured in `.env`.
- Verify the downloaded model matches the expected format used by `EnhancedPPOAgent.load_model(...)`.

### Model fails to load

```bash
python model_manager.py validate detection_module/trained_models/final_drl1.pt
```

## Development Cleanup

Generated captures, feature CSVs, prediction CSVs, logs, and temporary model backup files should not be committed. This repository now ignores those artifacts so Git stays focused on source code and required model assets.
