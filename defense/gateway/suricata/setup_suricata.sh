#!/bin/bash
# Gateway (192.168.100.53) 에서 실행
# Suricata IDS DNS 터널링 탐지 설정

set -e

# ── 1. Suricata 설치 ───────────────────────────────────────────
sudo apt-get update
sudo apt-get install -y suricata

# ── 2. 규칙 파일 복사 ──────────────────────────────────────────
sudo cp dns-tunnel.rules /etc/suricata/rules/dns-tunnel.rules

# ── 3. suricata.yaml 에 규칙 등록 ─────────────────────────────
# 기존 rule-files 섹션에 dns-tunnel.rules 추가
sudo grep -q "dns-tunnel.rules" /etc/suricata/suricata.yaml || \
    sudo sed -i '/rule-files:/a\  - dns-tunnel.rules' /etc/suricata/suricata.yaml

# ── 4. 인터페이스 이름 확인 (내부망 NIC) ──────────────────────
echo "[*] 현재 NIC 목록:"
ip a | grep -E "^[0-9]+:" | awk '{print $2}'
echo ""
echo "[!] suricata.yaml 의 af-packet interface 를 내부망 NIC 이름으로 수정하세요"
echo "    sudo nano /etc/suricata/suricata.yaml"

# ── 5. 설정 검증 ───────────────────────────────────────────────
sudo suricata -T -c /etc/suricata/suricata.yaml
echo "[+] 설정 검증 완료"

# ── 6. Suricata 실행 ───────────────────────────────────────────
# NIC 이름을 확인 후 아래 명령 실행 (ens33 → 실제 NIC 이름으로 교체)
# sudo suricata -c /etc/suricata/suricata.yaml -i ens33 -D
echo ""
echo "[*] 실행 명령 (NIC 이름 확인 후):"
echo "    sudo suricata -c /etc/suricata/suricata.yaml -i <NIC이름> -D"
