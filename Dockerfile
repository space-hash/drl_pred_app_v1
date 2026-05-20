# ============================================
# Docker deployment for DRL DDoS Detection
# Build: docker build -t drl-ddos .
# Run:   sudo docker run --cap-add=NET_ADMIN --cap-add=NET_RAW --network=host drl-ddos
# ============================================

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3.10 \
    python3.10-venv \
    python3-pip \
    libpcap-dev \
    iptables \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (cache layer)
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create directories
RUN mkdir -p capapp/capture_output/{in_progress,error} \
    capapp/features_output \
    capapp/logs \
    data/predictions \
    detection_module/trained_models

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/status || exit 1

# Run application
CMD ["python3", "app.py"]
