#!/bin/bash
# Quick test script for all endpoints
set -e

BASE="http://127.0.0.1:5005"

echo "=== ENDPOINT TEST ==="
echo ""

# Kill any existing
pkill -f "python3 app.py" 2>/dev/null || true
sleep 2

# Start app
rm -f capapp/logs/pipeline_20260517.log
.venv/bin/python3 app.py > /tmp/app_quick.log 2>&1 &
sleep 5

# Test each
echo "1. Status:" && curl -sf $BASE/api/status > /dev/null && echo "  OK"
echo "2. System:" && curl -sf $BASE/api/system/metrics > /dev/null && echo "  OK"
echo "3. eBPF:" && curl -sf $BASE/api/ebpf/status > /dev/null && echo "  OK"
echo "4. DRL:" && curl -sf $BASE/api/drl_mitigation/status > /dev/null && echo "  OK"
echo "5. Alerts:" && curl -sf $BASE/api/alerts > /dev/null && echo "  OK"
echo "6. AlertStats:" && curl -sf $BASE/api/alerts/stats > /dev/null && echo "  OK"
echo "7. TestAlert:" && curl -sf -X POST $BASE/api/alerts/test > /dev/null && echo "  OK"
echo "8. Mitigation:" && curl -sf $BASE/api/mitigation/status > /dev/null && echo "  OK"
echo "9. Detections:" && curl -sf $BASE/api/detections > /dev/null && echo "  OK"
echo "10. HTML Sections:" && curl -sf $BASE/ | grep -co 'id="ebpf"\|id="drl"\|id="alerts"\|id="systemHealth"'

echo ""
echo "=== DATA SAMPLES ==="
echo ""
echo "System Metrics:"
curl -s $BASE/api/system/metrics | python3 -c "import json,sys; d=json.load(sys.stdin); h=d['hardware']; print(f'  CPU:{h[\"cpu_percent\"]}% Mem:{h[\"memory_percent\"]}% Disk:{h[\"disk_percent\"]}%')"

echo "eBPF:"
curl -s $BASE/api/ebpf/status | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  enabled:{d[\"enabled\"]} xdp:{d.get(\"use_xdp\",False)} bcc:{d.get(\"bcc_available\",False)}')"

echo "DRL:"
curl -s $BASE/api/drl_mitigation/status | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  enabled:{d[\"enabled\"]} model:{d[\"model_loaded\"]} conf:{d[\"confidence_threshold\"]}')"

echo "Alerts:"
curl -s $BASE/api/alerts/stats | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  total:{d[\"total_alerts\"]} channels:{d[\"channels\"]}')"

echo "Mitigation:"
curl -s $BASE/api/mitigation/status | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'  blocked:{d[\"total_blocked\"]} iptables:{d[\"use_iptables\"]}')"

echo ""
echo "=== ALL TESTS PASSED ==="
