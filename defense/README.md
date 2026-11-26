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

## 연동 요약 (2026-11-26 팀원 DB 형식에 맞춤)

| 항목 | 값 |
|---|---|
| 알림 보내는 쪽 | CustomerDB `forward.py` (192.168.100.30) |
| 받는 쪽 | Gateway `block_server.py` → `POST http://192.168.100.53:8080/alerts` |
| 차단할 IP | 알림의 `client_ip` (DB 를 조회한 PC) |
| 허니토큰 데이터 | `cno`(미끼 고객번호), `db`, `event_id`, `login`, `time` |
| 인증 | 출처 IP(192.168.100.30) 검사. 공유 키는 기본 끔 |
| 응답 | 출처가 정상이면 항상 200 (forward.py 무한 재시도 방지) |
