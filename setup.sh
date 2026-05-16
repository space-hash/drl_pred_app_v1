#!/bin/bash
# DRL DDoS Detection Application - Setup Script
# Run this script to set up the project on a fresh machine

set -e

echo "========================================="
echo "  DRL DDoS Detection Setup"
echo "========================================="

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $PYTHON_VERSION"

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "WARNING: This project is designed for Linux. Packet capture may not work on other OS."
fi

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create .env if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "Please edit .env to configure your settings."
fi

# Create required directories
echo "Creating required directories..."
mkdir -p capapp/capture_output/in_progress
mkdir -p capapp/capture_output/error
mkdir -p capapp/features_output
mkdir -p capapp/logs
mkdir -p data/predictions
mkdir -p detection_module/trained_models

# Set network capabilities for packet capture
echo ""
echo "Setting up packet capture permissions..."
echo "You may be prompted for your password."
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(which python3)")" 2>/dev/null || {
    echo "WARNING: Could not set capabilities. You will need to run with sudo."
    echo "Run: sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))"
}

echo ""
echo "========================================="
echo "  Setup Complete!"
echo "========================================="
echo ""
echo "To run the application:"
echo "  1. Activate virtual environment: source .venv/bin/activate"
echo "  2. Edit .env to configure your settings (especially CAPTURE_INTERFACE)"
echo "  3. Run: python3 app.py"
echo ""
echo "Or with sudo for packet capture:"
echo "  sudo .venv/bin/python3 app.py"
echo ""
