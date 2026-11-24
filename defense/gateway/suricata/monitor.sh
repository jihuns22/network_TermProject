#!/bin/bash
# Suricata 탐지 로그 모니터링 — Gateway 에서 실행

LOG="/var/log/suricata/eve.json"
FAST="/var/log/suricata/fast.log"

echo "=== Suricata DNS 터널링 탐지 모니터 ==="
echo ""

# 방법 1: fast.log 실시간 확인 (가장 간단)
echo "[방법 1] 실시간 알림 (fast.log):"
echo "  sudo tail -f $FAST"
echo ""

# 방법 2: eve.json 에서 DNS 터널 알림만 필터
echo "[방법 2] DNS TUNNEL 알림만 추출:"
echo "  sudo cat $LOG | python3 -c \\"
echo "  'import sys,json; [print(json.dumps(json.loads(l),indent=2)) for l in sys.stdin if \"DNS TUNNEL\" in l]'"
echo ""

# 방법 3: jq 로 소스 IP별 알림 집계
echo "[방법 3] 소스 IP별 알림 수 집계 (jq 필요):"
echo "  sudo cat $LOG | jq -r 'select(.event_type==\"alert\") | .src_ip' | sort | uniq -c | sort -rn"
echo ""

# 실제 실행: fast.log 실시간 모니터
if [ -f "$FAST" ]; then
    echo "=== 현재 알림 목록 ==="
    sudo grep "DNS TUNNEL" "$FAST" 2>/dev/null || echo "(아직 탐지된 알림 없음)"
    echo ""
    echo "=== 실시간 모니터 시작 (Ctrl+C 로 종료) ==="
    sudo tail -f "$FAST" | grep --line-buffered "DNS TUNNEL"
else
    echo "[!] $FAST 없음 — Suricata가 아직 실행되지 않았습니다"
    echo "    sudo suricata -c /etc/suricata/suricata.yaml -i <NIC> -D"
fi
