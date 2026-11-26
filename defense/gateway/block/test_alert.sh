#!/bin/bash
# 차단 서버 동작 테스트. CustomerDB(192.168.100.30) 또는 Gateway 자신에서 실행.
# 팀원 DB 의 forward.py 가 보내는 알림과 같은 형식으로 보낸다.
# 사용법: ./test_alert.sh [공격자IP] [게이트웨이주소] [포트]
ATTACKER=${1:-192.168.100.20}
GW=${2:-192.168.100.53}
PORT=${3:-8080}
KEY=${HT_SHARED_KEY:-}
N=${EVENT_NO:-$(date +%s)}

KEY_HEADER=()
[ -n "$KEY" ] && KEY_HEADER=(-H "X-Honeytoken-Key: $KEY")

curl -s --noproxy '*' -X POST "http://$GW:$PORT/alerts" \
  -H "Content-Type: application/json" "${KEY_HEADER[@]}" \
  --data-binary "{\"event\":\"HONEYTOKEN_READ\",\"event_id\":\"honeygen_5-$N\",\"time\":\"$(date '+%Y-%m-%d %H:%M:%S%z')\",\"db\":\"honeygen_5\",\"login\":\"business_reader\",\"client_ip\":\"$ATTACKER\",\"cno\":\"ASN-658\"}" \
  -w '\nHTTP %{http_code}\n'
