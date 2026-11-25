# 방어 시나리오

## 구성

| 폴더 | VM | 도구 | 담당 |
|---|---|---|---|
| gateway/block/ | Gateway (192.168.100.53) | Python 차단 서버 + iptables | 우리 |
| gateway/suricata/ | Gateway (192.168.100.53) | Suricata IDS (유지 여부 미정) | 우리 |
| customerdb/ | CustomerDB (192.168.100.30) | PostgreSQL 허니토큰 | 팀원 |

## 탐지·차단 방식 (2026-11-25 변경)

허니토큰이 조회되는 순간 DB에서 알림을 보내고(공격자 IP + 허니토큰 데이터),
Gateway가 이를 `curl`로 받아 공격자 IP를 차단합니다. 자세한 내용은 [PROGRESS.md](../PROGRESS.md).
