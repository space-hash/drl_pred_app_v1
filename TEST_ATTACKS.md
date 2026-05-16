# DDoS Attack Test Commands

## Quick Test (Built-in, no install needed)

### Flood Ping (generates ~1000+ packets/sec)
```bash
# Open a NEW terminal and run:
ping -f -c 1000 127.0.0.1
```
This sends packets as fast as possible. Should trigger rate-based auto-block within seconds.

---

## hping3 (recommended, more realistic)

### Install
```bash
sudo apt install hping3 -y
```

### SYN Flood (most common DDoS type)
```bash
# Sends 1000 SYN packets to localhost port 80
sudo hping3 -S -p 80 --flood -c 1000 127.0.0.1
```

### UDP Flood
```bash
# Sends 1000 UDP packets to localhost port 53
sudo hping3 --udp -p 53 --flood -c 1000 127.0.0.1
```

### Random IP Spoofing (harder to detect)
```bash
# Sends packets with random source IPs
sudo hping3 -S -p 80 --rand-source --flood -c 2000 127.0.0.1
```

---

## Python Scapy (already installed)

### Save as `test_attack.py` and run:
```bash
python3 test_attack.py
```

```python
#!/usr/bin/env python3
"""Generate test DDoS-like traffic to trigger detection."""
from scapy.all import IP, TCP, UDP, send, RandIP
import time

TARGET = "127.0.0.1"
PORT = 80
COUNT = 500

print(f"Sending {COUNT} packets to {TARGET}:{PORT}...")

# SYN flood
for i in range(COUNT):
    pkt = IP(src=RandIP(), dst=TARGET) / TCP(dport=PORT, flags="S")
    send(pkt, verbose=False)
    if i % 100 == 0:
        print(f"  Sent {i}/{COUNT} packets...")

print("Done. Check dashboard for detections.")
```

---

## Apache Bench (HTTP flood)

### Install
```bash
sudo apt install apache2-utils -y
```

### Run (requires a web server on port 80)
```bash
# Sends 1000 requests with 100 concurrent connections
ab -n 1000 -c 100 http://127.0.0.1/
```

---

## How to Verify It's Working

1. **Start the pipeline** → Click "Start Detection" on dashboard
2. **Run an attack command** from another terminal
3. **Check dashboard** within 30-60 seconds:
   - **Recent Detections** table should show new entries
   - **DDoS Detections** counter should increase
   - If rate-based auto-block is ON → attacker IP appears in **Blocked IPs** list
4. **Stop the attack** with `Ctrl+C`

## Expected Results

| Attack Type | What to Expect |
|-------------|----------------|
| `ping -f` | Many ICMP flows, may show as Normal (depends on model) |
| `hping3 -S` | Many TCP SYN flows, likely detected as DDoS |
| `hping3 --udp` | Many UDP flows, likely detected as DDoS |
| Scapy script | Random IPs, high packet rate → rate-block triggered |
| `ab` | Many HTTP requests, detected as DDoS if volume is high |
