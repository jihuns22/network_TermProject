# Gateway 허니토큰 알림 수신 + 자동 차단

## 1. 전체 흐름

```
Win10 공격자 (192.168.100.20)
   │  ① SELECT * FROM customers ...   (실사용 DB 조회, 첫 행에 허니토큰)
   ▼
CustomerDB (192.168.100.30)   ← 팀원 담당
   │  ② 허니토큰이 조회된 것을 감지
   │  ③ curl POST http://192.168.100.53:9999/alert  (공격자 IP + 허니토큰 데이터)
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

**아무나 차단 요청을 보내면 안 됨.** 공격자가 `/alert` 에 Gateway나 DB IP를 넣어 보내면 스스로 망을 끊는 꼴이 됩니다. 그래서:
- 출처 제한: CustomerDB(192.168.100.30)와 Gateway 자신만 알림 가능 (그 외 403)
- 공유 키(선택): `X-Honeytoken-Key` 헤더 값이 맞아야 함 (틀리면 401)
- 화이트리스트: 127.0.0.1, 192.168.100.53, 192.168.100.30 은 절대 차단 안 함
- IP 형식 검증: `ipaddress` 모듈로 IPv4만 허용 → `1.2.3.4; rm -rf /` 같은 값은 거부 (iptables 는 셸 없이 인자 리스트로 실행)

**중복 차단 방지.** 허니토큰이 여러 행 조회되면 알림이 여러 번 옵니다. `iptables -C` 로 이미 있는지 확인해 규칙이 한 번만 들어갑니다.

**Python 3.5 호환.** Gateway가 Ubuntu 16.04라 기본 python3 가 3.5입니다. f-string 등 3.6+ 문법 없이 작성했고, 외부 패키지도 쓰지 않습니다.

## 3. 알림 형식 (⚠ 제안안 — 팀원과 맞춰야 함)

아래 형식은 제가 제안한 것이고, 팀원 코드가 아직 없어 확정된 것이 아닙니다. 필수 필드는 `attacker_ip` 하나뿐이고 나머지는 로그용이라 없어도 동작합니다.

```http
POST /alert HTTP/1.1
Host: 192.168.100.53:9999
Content-Type: application/json
X-Honeytoken-Key: <공유키, 안 쓰면 생략>

{
  "attacker_ip": "192.168.100.20",
  "honeytoken": {"table": "customers", "id": 1, "name": "Kim Honey", "api_key": "sk_live_HONEY0001"},
  "query": "SELECT * FROM customers ORDER BY id",
  "db_user": "app",
  "detected_at": "2026-11-25 15:10:00"
}
```

팀원 쪽 curl 예시 (PostgreSQL 에서는 `inet_client_addr()` 가 접속한 클라이언트 IP):

```bash
curl -s -X POST http://192.168.100.53:9999/alert \
  -H "Content-Type: application/json" \
  -H "X-Honeytoken-Key: labkey" \
  -d '{"attacker_ip":"192.168.100.20","honeytoken":{"id":1,"api_key":"sk_live_HONEY0001"}}'
```

예전 초안 방식(`POST /block?ip=192.168.100.20`, 본문 없음)도 그대로 받아줍니다.

응답:

| 상황 | 코드 | 본문 예 |
|---|---|---|
| 새로 차단 | 200 | `{"ok":true,"ip":"192.168.100.20","blocked":true,"new":true}` |
| 이미 차단됨 | 200 | `{"ok":true,...,"new":false}` |
| 화이트리스트/잘못된 IP | 400 | `{"ok":false,"error":"..."}` |
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

# (2) 실제 실행 (root 필요). 공유 키 쓰려면 --key
sudo python3 /opt/honeytoken/block_server.py --key labkey

# (3) 상시 실행하려면 systemd 등록
sudo cp honeytoken-block.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeytoken-block
sudo journalctl -u honeytoken-block -f
```

Gateway 에 다른 방화벽(ufw 등)이 9999 를 막고 있다면 DB 에서만 열어 주세요:
`sudo iptables -I INPUT -p tcp -s 192.168.100.30 --dport 9999 -j ACCEPT`

## 5. 테스트 순서

```bash
# Gateway 또는 CustomerDB 에서
HT_SHARED_KEY=labkey ./test_alert.sh 192.168.100.20 192.168.100.53

# Gateway 에서 결과 확인
sudo iptables -S HONEYTOKEN_BLOCK     # -A HONEYTOKEN_BLOCK -s 192.168.100.20/32 -j DROP
curl -s localhost:9999/blocked
tail -f /var/log/honeytoken_block.log
```

통합 시연:
1. Win10에서 `win10_exfil.ps1` 실행 → Kali에 파일이 들어오는 것 확인
2. Win10에서 DB 조회 (허니토큰 포함) → 팀원 코드가 알림 전송
3. Gateway 화면에 `[BLOCKED] 192.168.100.20` 출력
4. Win10에서 다시 유출 시도 → `nslookup test.tunnel.lab.test 192.168.100.53` 이 타임아웃, Kali에 아무것도 안 들어옴
5. 시연 리셋: `sudo ./reset_block.sh`

## 6. 동작 확인한 것

Linux(Python 3, root)에서 실제 iptables 로 확인했습니다: 체인 생성과 INPUT/FORWARD 연결, DROP 규칙 추가,
중복 알림 시 규칙 1개만 유지, 재시작 시 기존 차단 목록 복원, 해제, 화이트리스트 IP·잘못된 IP·잘못된 키·잘못된 JSON 거부.
Ubuntu 16.04 Gateway 에서 직접 돌려본 것은 아니고, Python 3.5 문법 검사만 통과했습니다.
