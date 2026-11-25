#!/bin/bash
# 시연 끝난 뒤 차단 규칙 전부 비우기 (Gateway 에서 sudo 로 실행)
iptables -F HONEYTOKEN_BLOCK 2>/dev/null && echo "HONEYTOKEN_BLOCK 비움" || echo "체인이 없음"
iptables -S HONEYTOKEN_BLOCK 2>/dev/null
