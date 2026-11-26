# 네트워크 보안 실습 — DNS 터널링 공격/방어

경기대학교 네트워크보안 텀프로젝트. Win10 공격자가 고객 DB 를 읽어 DNS 터널링으로 Kali 에 빼돌리고,
DB 속 허니토큰(미끼 고객)이 조회되는 순간 Gateway 가 공격자 IP 를 차단해 유출을 끊습니다.
진행 현황과 팀 결정 변경사항은 [PROGRESS.md](PROGRESS.md) 참고.

## 환경

| VM | IP | 역할 | 주요 포트 |
|---|---|---|---|
| Win10 | 192.168.100.20 | 공격자 (DB 조회 + DNS 유출) | |
| Gateway | 192.168.100.53 | DNS 포워더(dnsmasq) + 허니토큰 차단 서버 (+ IDS, 유지 여부 미정) | 53/udp, 8080/tcp(알림 수신) |
| Kali | 192.168.200.10 | C2 수신 서버 | 53/udp |
| CustomerDB | 192.168.100.30 | 고객 DB(PostgreSQL 9.5, 허니토큰 포함) — 팀원 담당 | 5433/tcp |

## 지금까지 구현한 것

| 구성 | 폴더 / 위치 | 상태 |
|---|---|---|
| DNS 터널링 유출 (PowerShell, hex 인코딩) | [`attack/win10/`](attack/README.md) | 완료, 동작 확인 |
| C2 수신·파일 복원 (Python) | [`attack/kali/`](attack/README.md) | 완료, 동작 확인 |
| 허니토큰 고객 DB + 조회 알림 | 팀원 담당 · 요약 [`defense/customerdb/`](defense/customerdb/README.md) | 완료 (팀원) |
| 허니토큰 알림 수신 + iptables 자동 차단 | [`defense/gateway/block/`](defense/gateway/block/README.md) | 완료, 팀원 알림 형식에 맞춤. Gateway VM 실연동은 [EXPERIMENT.md](defense/gateway/block/EXPERIMENT.md) 8단계 |
| Suricata IDS 규칙 (SID 9001~9004) | [`defense/gateway/suricata/`](defense/gateway/README.md) | 동작 확인, 유지 여부 미정 |

## 구조

```
attack/
  win10/   → DNS 터널링 유출 스크립트 (PowerShell)
  kali/    → DNS 터널 수신 서버 (Python)

defense/
  gateway/block/    → 허니토큰 알림 수신 + iptables 자동 차단 서버 (block_server.py)
  gateway/suricata/ → Suricata IDS 탐지 규칙 및 설정 (유지 여부 미정)
  customerdb/       → 팀원 허니토큰 DB 요약과 연동 정보
```

## 흐름

```
① Win10 ──psql:5433──▶ CustomerDB   SELECT * FROM read_customers(...)
                                     (어떤 열로 정렬해도 첫 행이 미끼 고객)
② CustomerDB: 함수가 미끼 행을 낼 때 DB 로그에 HNY01 기록
   forward.py ──curl POST :8080/alerts {client_ip, cno, ...}──▶ Gateway
③ Gateway block_server.py: 출처 확인 → iptables HONEYTOKEN_BLOCK 에 client_ip DROP
                                       (INPUT + FORWARD)
④ Win10 ──DNS(hex)──▶ Gateway dnsmasq ──▶ Kali   ← ③ 이후 DROP, 유출 중단
```

DB 조회 자체(Win10 → DB, 같은 망)는 Gateway 를 거치지 않아 막을 수 없습니다.
이 구조는 **읽은 직후 DNS 로 빼내는 것**을 막습니다.

## 빠른 시연 순서

1. Kali: `sudo python3 attack/kali/kali_dns_server.py`
2. Gateway: `sudo python3 defense/gateway/block/block_server.py` (기본 :8080, 팀원 `gateway.py` 는 띄우지 않음)
3. CustomerDB: 팀원 README 대로 `server.py`, `forward.py` 실행
4. Win10: 유출 스크립트로 유출이 되는 것 확인 → psql 로 `read_customers()` 조회
5. Gateway 화면 `[BLOCKED] 192.168.100.20` → Win10 유출 재시도 시 DNS 타임아웃
6. 리셋: `sudo defense/gateway/block/reset_block.sh`

자세한 단계와 기대 결과는 [EXPERIMENT.md](defense/gateway/block/EXPERIMENT.md).
