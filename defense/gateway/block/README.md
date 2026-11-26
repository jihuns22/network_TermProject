# Gateway 허니토큰 알림 수신 + 자동 차단

## 1. 전체 흐름

```
Win10 공격자 (192.168.100.20)
   │  ① psql 로 SELECT * FROM read_customers(...)   (어떻게 정렬해도 첫 행이 허니토큰)
   ▼
CustomerDB (192.168.100.30:5433)   ← 팀원 담당
   │  ② read_customers() 함수가 미끼 행을 낼 때 DB 로그(audit.csv)에 HNY01 기록
   │  ③ forward.py 가 curl POST http://192.168.100.53:8080/alerts  (client_ip + cno)
   ▼
Gateway (192.168.100.53)      ← 우리 담당 (이 폴더)
   │  ④ 출처/키/IP 검증 → 화이트리스트 확인 → 중복 확인
   │  ⑤ iptables -I HONEYTOKEN_BLOCK -s <공격자IP> -j DROP
   │  ⑥ /var/log/honeytoken_block.log 에 알림+허니토큰 데이터 기록
   ▼
Win10 → Gateway:53 DNS 쿼리가 DROP 됨 → DNS 터널링 유출 중단
```

## 2. 설계에서 중요한 점

**INPUT 체인도 막아야 함.** 예전 초안(PROGRESS.md)은 `FORWARD` 만 막았는데, Win10의 DNS 터널링 쿼리는
Gateway의 dnsmasq(:53) 로 *직접* 들어오므로 `INPUT` 체인을 탑니다. `FORWARD` 만 막으면 터널링이 계속됩니다.
그래서 전용 체인 `HONEYTOKEN_BLOCK` 을 만들고 `INPUT` 과 `FORWARD` 맨 앞에서 이 체인으로 보냅니다.
해제/리셋도 이 체인만 비우면 되어 기존 방화벽 규칙을 건드리지 않습니다.

**Win10 → DB 직접 접속은 Gateway가 못 막음.** 둘 다 192.168.100.x 같은 망이라 Gateway를 거치지 않습니다.
차단 효과는 "외부(Kali)로 데이터를 빼내는 DNS 경로를 끊는 것"이고, 발표 때 이렇게 설명하면 됩니다.

**아무나 차단 요청을 보내면 안 됨.** 공격자가 `/alerts` 에 Gateway나 DB IP를 넣어 보내면 스스로 망을 끊는 꼴이 됩니다. 그래서:
- 출처 제한: CustomerDB(192.168.100.30)와 Gateway 자신만 알림 가능 (그 외 403)
- 공유 키(선택, 기본 꺼짐): `X-Honeytoken-Key` 헤더 값이 맞아야 함 (틀리면 401)
- 화이트리스트: 127.0.0.1, 192.168.100.53, 192.168.100.30 은 절대 차단 안 함
- IP 형식 검증: `ipaddress` 모듈로 IPv4만 허용 → `1.2.3.4; rm -rf /` 같은 값은 거부 (iptables 는 셸 없이 인자 리스트로 실행)

**중복 차단 방지.** 허니토큰이 여러 행 조회되면 알림이 여러 번 옵니다. `iptables -C` 로 이미 있는지 확인해 규칙이 한 번만 들어갑니다.

**Python 3.5 호환.** Gateway가 Ubuntu 16.04라 기본 python3 가 3.5입니다. f-string 등 3.6+ 문법 없이 작성했고, 외부 패키지도 쓰지 않습니다.

## 3. 알림 형식 (팀원 DB에 맞춤)

팀원 DB 의
`forward.py` 가 보내는 형식을 그대로 받습니다. 팀원 쪽 코드나 `.env` 는 바꾸지 않아도 됩니다
(`.env` 기본값 `GATEWAY_PORT=8080`, `ALERT_PATH=/alerts`).

```http
POST /alerts HTTP/1.1
Host: 192.168.100.53:8080
Content-Type: application/json

{"event":"HONEYTOKEN_READ","event_id":"honeygen_5-3","time":"2026-11-26 09:30:00.123+09",
 "db":"honeygen_5","login":"business_reader","client_ip":"192.168.100.20","cno":"ASN-658"}
```

| 팀원 필드 | 뜻 | 우리 로그 필드 |
|---|---|---|
| `client_ip` | DB를 조회한 PC = **차단할 IP** | `attacker_ip` |
| `cno` | 조회된 미끼 고객번호 | `honeytoken.cno` |
| `db`, `event_id` | DB 이름, 알림 번호 | `honeytoken.db`, `honeytoken.event_id`, `event_id` |
| `login` | DB 계정 | `db_user` |
| `time` | DB가 미끼 행을 낸 시각 | `detected_at` |

팀원 DB 동작에서 알아둘 점:
- 미끼 **한 행당 알림 1건**입니다. 전체 조회(`SELECT count(*) FROM read_customers();`)면 미끼 수만큼 연달아 옵니다. 첫 알림에서 차단되고 나머지는 `already_blocked` 로 처리됩니다.
- `forward.py` 는 **HTTP 2xx를 받을 때까지 3초마다 재시도**하고 알림을 순서대로 하나씩 보냅니다. 그래서 출처가 정상인 알림은 차단하지 않는 경우(화이트리스트 IP 등)에도 **200** 으로 답합니다. 4xx를 주면 그 알림에서 멈춰 뒤 알림이 전부 밀립니다.
- 공유 키 헤더는 보내지 않습니다. 그래서 기본은 키 검사 없이 **출발지 IP(192.168.100.30) 검사**로만 거릅니다. 키까지 쓰려면 팀원 `forward.py` 의 curl 인자에 `'-H', 'X-Honeytoken-Key: labkey'` 를 추가하고 우리 서버를 `--key labkey` 로 띄웁니다.
- 허니토큰 데이터는 `cno` 만 옵니다. email·이름도 받으려면 팀원 `schema.sql` 의 `json_build_object` 에 `'email', r.email, 'full_name', r.full_name` 을 추가해야 합니다(우리 서버는 수정 없이 로그에 남김).
- 팀원의 `gateway.py`(수집 전용, 같은 8080 사용)는 **띄우지 않습니다.** 우리 서버가 그 역할 + 차단을 합니다.

예전 제안 형식(`POST /alert`, `attacker_ip`/`honeytoken`)과 초안 형식(`POST /block?ip=...`)도 계속 받습니다.

응답:

| 상황 | 코드 | 본문 예 |
|---|---|---|
| 새로 차단 | 200 | `{"ok":true,"ip":"192.168.100.20","blocked":true,"new":true}` |
| 이미 차단됨 | 200 | `{"ok":true,...,"new":false}` |
| 화이트리스트/잘못된 IP | 200 | `{"ok":false,"blocked":false,"error":"..."}` (재시도 막기 위해 200) |
| 잘못된 JSON | 400 | |
| 키 틀림 / 허용 안 된 출처 | 401 / 403 | |

그 밖의 엔드포인트: `GET /health`, `GET /blocked`(차단 목록), `POST /unblock?ip=...`(Gateway 자신에서만, 시연 리셋용).

## 4. Gateway 에 설치·실행

```bash
# 파일 복사 (Gateway 에서)
sudo mkdir -p /opt/honeytoken
sudo cp block_server.py /opt/honeytoken/
chmod +x test_alert.sh reset_block.sh

# (1) 먼저 실제 차단 없이 연습
sudo python3 /opt/honeytoken/block_server.py --dry-run --log /tmp/ht.log

# (2) 실제 실행 (root 필요). 기본 포트 8080. 공유 키는 팀원 curl 에도 넣었을 때만 --key
sudo python3 /opt/honeytoken/block_server.py

# (3) 상시 실행하려면 systemd 등록
sudo cp honeytoken-block.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeytoken-block
sudo journalctl -u honeytoken-block -f
```

Gateway 에 다른 방화벽(ufw 등)이 8080 을 막고 있다면 DB 에서만 열어 주세요:
`sudo iptables -I INPUT -p tcp -s 192.168.100.30 --dport 8080 -j ACCEPT`

## 5. 테스트 순서

```bash
# Gateway 또는 CustomerDB 에서
./test_alert.sh 192.168.100.20 192.168.100.53     # 팀원 DB와 같은 형식으로 보냄

# Gateway 에서 결과 확인
sudo iptables -S HONEYTOKEN_BLOCK     # -A HONEYTOKEN_BLOCK -s 192.168.100.20/32 -j DROP
curl -s localhost:8080/blocked
tail -f /var/log/honeytoken_block.log
```

통합 시연:
1. Win10에서 `win10_exfil.ps1` 실행 → Kali에 파일이 들어오는 것 확인
2. Win10에서 DB 조회 → 팀원 forward.py 가 알림 전송
   `psql -h 192.168.100.30 -p 5433 -U business_reader -d honeygen_5` 후 `SELECT * FROM read_customers('email', false, 1, 0);`
3. Gateway 화면에 `[BLOCKED] 192.168.100.20` 출력
4. Win10에서 다시 유출 시도 → `nslookup test.tunnel.lab.test 192.168.100.53` 이 타임아웃, Kali에 아무것도 안 들어옴
5. 시연 리셋: `sudo ./reset_block.sh`

## 6. 동작 확인한 것

Linux(Python 3, root)에서 실제 iptables 로 확인했습니다: 체인 생성과 INPUT/FORWARD 연결, DROP 규칙 추가,
중복 알림 시 규칙 1개만 유지, 재시작 시 기존 차단 목록 복원, 해제, 화이트리스트 IP·잘못된 IP·잘못된 키·잘못된 JSON 거부.
Ubuntu 16.04 Gateway 에서 직접 돌려본 것은 아니고, Python 3.5 문법 검사만 통과했습니다.
