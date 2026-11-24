# CustomerDB — PostgreSQL Honeytoken

**실행 환경:** CustomerDB (192.168.100.30)

## 계획 (추후 구현)

- PostgreSQL에 가짜 토큰 테이블 생성
- SELECT 접근 시 trigger 발동 → 로그 기록
- 로그 감시 스크립트 → iptables 자동 차단
