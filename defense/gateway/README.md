# Gateway — Suricata IDS 설정

**실행 환경:** Gateway (192.168.100.53, Ubuntu 16.04, Suricata 3.0)

## 파일

| 파일 | 설명 |
|---|---|
| `suricata/dns-tunnel.rules` | DNS 터널링 탐지 규칙 |
| `suricata/suricata-debian.yaml` | Suricata 최소 설정 |
| `suricata/monitor.sh` | 탐지 로그 모니터링 스크립트 |
| `suricata/setup_suricata.sh` | 설치 스크립트 |

## 설치 및 실행

**규칙 파일 적용:**
```bash
sudo tee /etc/suricata/rules/dns-tunnel.rules < suricata/dns-tunnel.rules
sudo tee /etc/suricata/suricata-debian.yaml < suricata/suricata-debian.yaml
```

**설정 검증:**
```bash
sudo suricata -T -c /etc/suricata/suricata-debian.yaml
```

**실행:**
```bash
sudo suricata -c /etc/suricata/suricata-debian.yaml -i ens33 -D
```

**탐지 로그 모니터링:**
```bash
sudo tail -f /var/log/suricata/fast.log
```

## 탐지 규칙

| SID | 규칙 | 설명 |
|---|---|---|
| 9001 | long hex label | 50자 이상 hex 서브도메인 |
| 9002 | START signal | 세션 시작 패킷 |
| 9003 | END signal | 세션 종료 패킷 |
| 9004 | high query rate | 10초에 15회 이상 쿼리 |

## 주의

- NIC 이름이 `ens33`이 아닌 경우 `suricata-debian.yaml`의 `interface:` 수정
- Suricata 3.0은 `alert dns` 키워드 미지원 → `alert udp` 사용
