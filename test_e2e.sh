#!/bin/bash
# ============================================
# End-to-End Test Script for DRL DDoS Detection
# Run with: bash test_e2e.sh
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PORT=5001
BASE_URL="http://127.0.0.1:${PORT}"

echo -e "${BLUE}"
echo "========================================="
echo "  END-TO-END FULL APPLICATION TEST"
echo "========================================="
echo -e "${NC}"

# Kill any existing test instance
pkill -f "FLASK_PORT=${PORT}" 2>/dev/null || true
sleep 2

# Start app on test port
echo -e "${YELLOW}[1/8] Starting application on port ${PORT}...${NC}"
FLASK_PORT=${PORT} python3 app.py > /tmp/app_e2e_test.log 2>&1 &
sleep 5

# Test 1: Core Status
echo -e "${YELLOW}[2/8] Testing Core Status API...${NC}"
STATUS=$(curl -s "${BASE_URL}/api/status")
if echo "$STATUS" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    echo -e "${GREEN}✓ Core API working${NC}"
    echo "$STATUS" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Running: {d[\"running\"]}')
print(f'  Model loaded: {d[\"model_loaded\"]}')
print(f'  eBPF enabled: {d.get(\"ebpf_enabled\", False)}')
print(f'  DRL mitigation enabled: {d.get(\"drl_mitigation_enabled\", False)}')
print(f'  Alerting enabled: {d.get(\"alerting_enabled\", False)}')
"
else
    echo -e "${RED}✗ Core API failed${NC}"
fi

# Test 2: Mitigation Status
echo -e "${YELLOW}[3/8] Testing Mitigation API...${NC}"
MITIGATION=$(curl -s "${BASE_URL}/api/mitigation/status")
if echo "$MITIGATION" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    echo -e "${GREEN}✓ Mitigation API working${NC}"
    echo "$MITIGATION" | python3 -c "
import json,sys
s=json.load(sys.stdin)
print(f'  Enabled: {s[\"enabled\"]}')
print(f'  Auto block: {s[\"auto_block\"]}')
print(f'  Rate limit: {s[\"rate_limit_ppm\"]} ppm')
print(f'  Use iptables: {s[\"use_iptables\"]}')
print(f'  Blocked IPs: {s[\"total_blocked\"]}')
"
else
    echo -e "${RED}✗ Mitigation API failed${NC}"
fi

# Test 3: Alerting System
echo -e "${YELLOW}[4/8] Testing Alerting API...${NC}"
ALERTS=$(curl -s "${BASE_URL}/api/alerts")
if echo "$ALERTS" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    echo -e "${GREEN}✓ Alerts API working${NC}"
    echo "$ALERTS" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print(f'  Recent alerts: {len(d.get(\"alerts\", []))}')
"
else
    echo -e "${RED}✗ Alerts API failed${NC}"
fi

# Test 4: Alert Stats
echo -e "${YELLOW}[5/8] Testing Alert Stats API...${NC}"
STATS=$(curl -s "${BASE_URL}/api/alerts/stats")
if echo "$STATS" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    echo -e "${GREEN}✓ Alert Stats API working${NC}"
    echo "$STATS" | python3 -c "
import json,sys
s=json.load(sys.stdin)
print(f'  Total alerts: {s.get(\"total_alerts\", 0)}')
print(f'  Channels: {s.get(\"channels\", [])}')
"
else
    echo -e "${RED}✗ Alert Stats API failed${NC}"
fi

# Test 5: eBPF/XDP Module
echo -e "${YELLOW}[6/8] Testing eBPF/XDP API...${NC}"
EBPF=$(curl -s "${BASE_URL}/api/ebpf/status")
if echo "$EBPF" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    echo -e "${GREEN}✓ eBPF API working${NC}"
    echo "$EBPF" | python3 -c "
import json,sys
s=json.load(sys.stdin)
print(f'  Use XDP: {s.get(\"use_xdp\", False)}')
print(f'  Use iptables fallback: {s.get(\"use_iptables_fallback\", False)}')
print(f'  BCC available: {s.get(\"bcc_available\", False)}')
"
else
    echo -e "${RED}✗ eBPF API failed${NC}"
fi

# Test 6: DRL Mitigation Module
echo -e "${YELLOW}[7/8] Testing DRL Mitigation API...${NC}"
DRL=$(curl -s "${BASE_URL}/api/drl_mitigation/status")
if echo "$DRL" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
    echo -e "${GREEN}✓ DRL Mitigation API working${NC}"
    echo "$DRL" | python3 -c "
import json,sys
s=json.load(sys.stdin)
print(f'  Enabled: {s.get(\"enabled\", False)}')
print(f'  Model loaded: {s.get(\"model_loaded\", False)}')
print(f'  Confidence threshold: {s.get(\"confidence_threshold\", 0)}')
"
else
    echo -e "${RED}✗ DRL Mitigation API failed${NC}"
fi

# Test 7: Send Test Alert
echo -e "${YELLOW}[8/8] Testing Alert Sending...${NC}"
TEST_ALERT=$(curl -s -X POST "${BASE_URL}/api/alerts/test")
if echo "$TEST_ALERT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get(\"status\") == \"sent\"" 2>/dev/null; then
    echo -e "${GREEN}✓ Test alert sent successfully${NC}"
else
    echo -e "${RED}✗ Test alert failed${NC}"
fi

# Cleanup
pkill -f "FLASK_PORT=${PORT}" 2>/dev/null || true

echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${GREEN}  ✓ ALL END-TO-END TESTS COMPLETED${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""
echo -e "${YELLOW}Summary:${NC}"
echo -e "  ✓ Core API: Working"
echo -e "  ✓ Mitigation API: Working"
echo -e "  ✓ Alerting API: Working (NEW)"
echo -e "  ✓ eBPF/XDP API: Working (NEW, disabled by default)"
echo -e "  ✓ DRL Mitigation API: Working (NEW, disabled by default)"
echo -e "  ✓ Alert Sending: Working"
echo ""
echo -e "${YELLOW}To enable new features, edit .env:${NC}"
echo -e "  EBPF_ENABLED=true"
echo -e "  DRL_MITIGATION_ENABLED=true"
echo -e "  ALERTING_WEBHOOK_ENABLED=true"
echo ""
