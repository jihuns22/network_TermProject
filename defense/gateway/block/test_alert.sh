#!/bin/bash
# 차단 서버 동작 테스트. CustomerDB(192.168.100.30) 또는 Gateway 자신에서 실행.
# 사용법: ./test_alert.sh [공격자IP] [게이트웨이주소]
ATTACKER=${1:-192.168.100.20}
GW=${2:-192.168.100.53}
KEY=${HT_SHARED_KEY:-}

curl -s -X POST "http://$GW:9999/alert" \
  -H "Content-Type: application/json" \
  -H "X-Honeytoken-Key: $KEY" \
  -d "{
    \"attacker_ip\": \"$ATTACKER\",
    \"honeytoken\": {\"table\": \"customers\", \"id\": 1, \"name\": \"Kim Honey\", \"api_key\": \"sk_live_HONEY0001\"},
    \"query\": \"SELECT * FROM customers ORDER BY id\",
    \"db_user\": \"app\",
    \"detected_at\": \"$(date '+%Y-%m-%d %H:%M:%S')\"
  }"
echo
