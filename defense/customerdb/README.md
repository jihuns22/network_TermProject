# CustomerDB — PostgreSQL 허니토큰

**실행 환경:** CustomerDB (192.168.100.30)  
**담당:** 팀원

## 설계 (2026-11-25 팀 결정)

- 별도 가짜 DB가 아니라 **실사용 DB 레코드 사이에 허니토큰을 약 5%, 1% 비율로 섞음**
- **어떤 기준으로 정렬해도 첫 번째에 오는 허니토큰**을 둬 조회 즉시 감지
- 허니토큰이 조회되면 알림 발생 → `curl`로 Gateway(192.168.100.53:8080/alerts)에 **공격자 IP(client_ip) + 허니토큰(cno)** 전달
- 탈취된 허니토큰(예: API 키)으로 공격자를 추적하는 부분은 발표 때 구두 설명

## 팀원 DB 구성 요약

- PostgreSQL 9.5, 192.168.100.30:5433. 조회 계정 `business_reader` 는 테이블을 직접 못 읽고 `read_customers(정렬열, 내림차순, 행수, 건너뛸수)` 함수로만 조회
- 고객 100명 + `HONEY_PERCENT`(예: 5 → 미끼 5명, DB 이름 `honeygen_5`). 어느 행이 미끼인지는 관리자 전용 `honey.tokens` 에만 있음
- 미끼 2개는 cno·email·이름 어느 열로 정렬해도 맨 앞/맨 뒤에 옴
- 함수가 미끼 행을 낼 때마다 DB 로그(audit.csv)에 `HNY01` 로 JSON 기록 → `forward.py` 가 읽어서 curl 로 Gateway 에 POST (2xx 받을 때까지 3초마다 재시도)

## Gateway와 맞춘 것 (2026-11-26)

Gateway 차단 서버를 팀원 알림 형식에 맞췄습니다. 팀원 쪽은 수정할 필요 없고, 팀원 `gateway.py` 대신 우리 `block_server.py` 를 띄웁니다.
자세한 형식은 [`../gateway/block/README.md`](../gateway/block/README.md)의 "알림 형식" 참고.

> 참고: PostgreSQL에는 SELECT 트리거가 없어서 예전 초안의 `AFTER SELECT` 트리거는 동작하지 않습니다.
