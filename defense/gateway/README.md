# Gateway — 차단 서버 + Suricata IDS

**실행 환경:** Gateway (192.168.100.53, Ubuntu 16.04, Suricata 3.0)

## 허니토큰 알림 수신 + 자동 차단 (`block/`)

CustomerDB(팀원 `forward.py`)가 보내는 허니토큰 조회 알림을 `POST :8080/alerts` 로 받아
알림의 `client_ip` 를 iptables 전용 체인 `HONEYTOKEN_BLOCK`(INPUT + FORWARD 연결)에 DROP 으로 넣습니다.
알림 형식은 팀원 DB 에 맞췄습니다(`client_ip`, `cno`, 키 헤더 없음). 팀원의 `gateway.py` 대신 이 서버를 띄웁니다.
설치·설계는 [block/README.md](block/README.md), 실험 절차는 [block/EXPERIMENT.md](block/EXPERIMENT.md).

## Suricata IDS (`suricata/`, 유지 여부 미정)

> 2026-11-25 탐지 방식이 허니토큰 알림으로 바뀌어, IDS를 보조로 남길지 뺄지는 팀원과 논의 중입니다.

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
