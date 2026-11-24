# 네트워크 보안 실습 — DNS 터널링 공격/방어

## 환경

| VM | IP | 역할 |
|---|---|---|
| Win10 | 192.168.100.20 | 공격자 (유출) |
| Gateway | 192.168.100.53 | DNS 포워더 + IDS |
| Kali | 192.168.200.10 | C2 수신 서버 |
| CustomerDB | 192.168.100.30 | 타겟 DB |

## 구조

```
attack/
  win10/   → DNS 터널링 유출 스크립트 (PowerShell)
  kali/    → DNS 터널 수신 서버 (Python)

defense/
  gateway/ → Suricata IDS 탐지 규칙 및 설정
  customerdb/ → PostgreSQL Honeytoken (추후)
```

## 흐름

```
Win10 → DNS 쿼리(hex 인코딩) → Gateway(dnsmasq) → Kali(복원)
                                      ↓
                                Suricata 탐지
```
