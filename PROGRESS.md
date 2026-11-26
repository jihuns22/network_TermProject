# 네트워크 보안 텀 프로젝트 — 진행 현황

> 최종 수정: 2026-11-25 (팀 회의 결과 설계 변경 반영)  
> 담당: Jihun Son  
> 레포: https://github.com/jihuns22/network_TermProject

---

## 과제 개요

**DNS 터널링 공격 시나리오를 직접 구현하고, 이를 탐지·차단하는 방어 시스템을 구축하는 실습 과제**

### 네트워크 환경

| VM | IP | 역할 |
|---|---|---|
| Win10 | 192.168.100.20 | 공격자 (파일 유출) |
| Gateway | 192.168.100.53 | DNS 포워더 + 차단 서버 (+ IDS, 유지 여부 미정) |
| Kali | 192.168.200.10 | C2 수신 서버 |
| CustomerDB | 192.168.100.30 | 타겟 DB (PostgreSQL, 허니토큰 포함) |

---

## 🔁 2026-11-25 팀 결정 변경사항

### 1. 탐지 방식 변경 — 허니토큰 조회 알림

- **기존:** Suricata IDS가 DNS 패킷을 분석해 탐지
- **변경:** 허니토큰이 **조회되는 순간** DB 쪽에서 알림을 발생시키고,
  그 정보(**공격자 IP + 조회된 허니토큰 데이터**)를 `curl`로 Gateway에 전달 → Gateway가 공격자 IP 차단
- **IDS(Suricata) 유지 여부: 미정.** 보조 탐지로 남길지 뺄지는 팀원과 논의 후 결정

### 2. 별도 가짜 DB → 실사용 DB에 허니토큰 혼합

- 기존 방식(가짜 DB를 따로 만듦)은 "공격이 올 것을 미리 안다"는 전제라 실제 시나리오와 괴리가 큼
- 변경: **실사용 DB 레코드 사이에 허니토큰을 약 5%, 1% 비율로 섞어 넣음**
- 빠른 감지를 위해 **어떤 기준으로 정렬해도 첫 번째에 오는 허니토큰**을 둠
  (공격자가 `ORDER BY`를 무엇으로 하든 첫 행에서 바로 알림 발생)

### 3. 공격자 추적은 구두 설명

- 데이터 탈취 후(예: 허니토큰의 API 키) 해당 API 키를 감시 대상으로 지정
- 공격자가 그 키를 사용하면 사용 위치를 특정
- **구현하지 않고 발표 때 구두로 설명**

### 역할 분담

| 부분 | 담당 |
|---|---|
| 허니토큰 포함 DB + 조회 감지 + 알림 전송(curl) | 팀원 (제작 중) |
| Gateway 알림 수신 + iptables 자동 차단 | 우리 (`defense/gateway/block/`) |

---

## ✅ 완료된 작업

### 1. 공격 시나리오 — DNS 터널링 (완료)

```
Win10 → DNS 쿼리(hex 인코딩) → Gateway(dnsmasq) → Kali(복원)
```

- **Win10** (`attack/win10/win10_exfil.ps1`): 파일을 hex 인코딩 후 50자씩 쪼개어 `{seq}{hex}.tunnel.lab.test` DNS 쿼리로 전송
- **Kali** (`attack/kali/kali_dns_server.py`): UDP:53 수신, DNS 쿼리 파싱, hex → 원본 파일 복원 (`/tmp/exfil/`에 저장)
- **Gateway**: dnsmasq가 `.tunnel.lab.test` 쿼리를 Kali(192.168.200.10)로 포워딩

**실제 동작 확인 완료** — Win10에서 스크립트 실행 시 Kali에서 파일 수신 성공

### 2. Suricata IDS 규칙 (완료, 유지 여부 미정)

파일: `defense/gateway/suricata/`

| SID | 규칙 | 설명 |
|---|---|---|
| 9001 | long hex label | 긴 hex 패턴이 포함된 쿼리 |
| 9002 | START signal | 세션 시작 패킷 (`start` + `tunnel`) |
| 9003 | END signal | 세션 종료 패킷 (`end` + `tunnel`) |
| 9004 | high query rate | 10초에 15회 이상 쿼리 |

> Suricata 3.0은 `alert dns` 미지원 → `alert udp any any -> any 53` 사용.
> DNS 와이어 포맷은 도트 대신 길이 프리픽스 → `content:"tunnel"` 로 매칭.

**동작 확인 완료** — 4개 규칙 로드 성공, `fast.log` 탐지 로그 확인

### 3. Gateway 차단 서버 (작성 완료, 팀원 DB 알림 형식에 맞춤)

파일: `defense/gateway/block/` — 자세한 내용은 [README](defense/gateway/block/README.md), 실험 절차는 [EXPERIMENT.md](defense/gateway/block/EXPERIMENT.md)

```
CustomerDB (허니토큰 조회 감지)
    ↓ curl POST http://192.168.100.53:8080/alerts  {client_ip, cno, db, login, time, event_id}
Gateway block_server.py (:8080)
    ↓ 검증 → iptables 전용 체인 HONEYTOKEN_BLOCK 에 DROP 추가
Win10 → Gateway:53 DNS 쿼리 차단 → 유출 중단
```

- **INPUT과 FORWARD 둘 다 차단하는 이유:** Win10의 DNS 터널링 쿼리는 Gateway의 dnsmasq(:53)로
  **직접** 들어오므로 `INPUT` 체인을 탐. 예전 초안처럼 `FORWARD`만 막으면 터널링이 계속됨.
  Gateway를 거쳐 나가는 다른 트래픽까지 막기 위해 `FORWARD`도 함께 막음.
  전용 체인 `HONEYTOKEN_BLOCK`을 만들어 두 체인 맨 앞에 연결하므로, 리셋할 때 이 체인만 비우면 됨
- 출처 제한(CustomerDB·Gateway만 알림 가능), 화이트리스트(Gateway·DB IP는 차단 안 함), IPv4 형식 검증, 중복 차단 방지
- 예전 초안 형식 `POST /block?ip=...` 도 호환
- Ubuntu 16.04 기본 Python 3.5 호환, 외부 패키지 없음
- 일반 Linux + 실제 iptables 에서 동작 확인. Gateway VM에서는 아직 실행 전

> **알림 형식은 팀원 DB([customer-db-lab/ubuntu-db](https://github.com/quswodn1211/customer-db-lab/tree/main/ubuntu-db))의 `forward.py` 에 맞춤 (2026-11-26).**
> 차단 IP 는 `client_ip`, 허니토큰은 `cno`. 팀원 forward.py 가 키 헤더를 안 보내므로 공유 키는 기본 끔(출처 IP 검사만).
> forward.py 가 2xx 를 받을 때까지 재시도하므로 화이트리스트 등 차단 안 하는 경우도 200 으로 응답.
> 예전 형식(`/alert` + `attacker_ip`, `/block?ip=`)도 계속 받음.

---

## 📋 남은 작업

| 항목 | 상태 | 비고 |
|---|---|---|
| 허니토큰 포함 DB + 조회 감지 + curl 알림 | 완료 (팀원) | customer-db-lab/ubuntu-db |
| 알림 형식 맞추기 | 완료 | Gateway 쪽을 팀원 형식(8080 /alerts, client_ip, cno)에 맞춤 |
| Gateway에 차단 서버 설치·실험 | 미완료 | `EXPERIMENT.md` 순서대로 (8단계가 팀원 DB 실연동) |
| IDS(Suricata) 유지 여부 결정 | 미정 | 팀원과 논의 중 |
| 최종 통합 테스트 | 미완료 | 허니토큰 조회 → 알림 → 차단 → 유출 중단 |
| 공격자 추적 설명 준비 | 미완료 | 발표 구두 설명 (API 키 감시) |

---

## 핵심 기술 메모

- **DNS 터널링**: 도메인 서브라벨에 hex 인코딩 데이터를 숨겨 DNS 쿼리로 파일 전송
- **허니토큰**: 실사용 DB에 섞인 가짜 레코드. 조회 자체가 공격 신호 → 공격자 IP 차단
- **PostgreSQL에는 SELECT 트리거가 없음**: 예전 초안의 `AFTER SELECT` 트리거는 동작하지 않음.
  뷰/함수 래핑, 로그 감시 등으로 조회를 감지해야 함 (팀원 담당 부분 참고용)
- **Win10 → DB 직접 접속은 Gateway가 못 막음**: 같은 망(192.168.100.x)이라 Gateway를 거치지 않음.
  차단 효과는 "외부(Kali)로 빼내는 DNS 경로를 끊는 것"
- **엔트로피 분석**: DNS 서브도메인의 무작위성(hex/base64 ≈ 3.7 bits/char)으로 터널링 탐지 가능 (고급 방어)
