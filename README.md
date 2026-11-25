# 네트워크 보안 실습 — DNS 터널링 공격/방어

진행 현황과 팀 결정 변경사항은 [PROGRESS.md](PROGRESS.md) 참고.

## 환경

| VM | IP | 역할 |
|---|---|---|
| Win10 | 192.168.100.20 | 공격자 (유출) |
| Gateway | 192.168.100.53 | DNS 포워더 + 차단 서버 (+ IDS, 유지 여부 미정) |
| Kali | 192.168.200.10 | C2 수신 서버 |
| CustomerDB | 192.168.100.30 | 타겟 DB (허니토큰 포함) |

## 구조

```
attack/
  win10/   → DNS 터널링 유출 스크립트 (PowerShell)
  kali/    → DNS 터널 수신 서버 (Python)

defense/
  gateway/suricata/ → Suricata IDS 탐지 규칙 및 설정 (유지 여부 미정)
  gateway/block/    → 허니토큰 알림 수신 + iptables 자동 차단 서버
  customerdb/       → PostgreSQL 허니토큰 (팀원 담당)
```

## 흐름

```
Win10 → DNS 쿼리(hex 인코딩) → Gateway(dnsmasq) → Kali(복원)
  │
  └→ CustomerDB 조회 (실사용 DB 속 허니토큰)
         ↓ 허니토큰 조회 감지 → curl (공격자 IP + 허니토큰 데이터)
     Gateway 차단 서버 → iptables DROP (INPUT + FORWARD)
         ↓
     DNS 터널링 유출 중단
```
