# 허니토큰 차단 실험 절차 (팀원 DB 없이)

팀원의 허니토큰 DB가 없어도, **curl로 알림을 흉내 내서** 차단이 되는지 확인할 수 있습니다.
각 단계 앞의 `[VM]` 이 명령을 실행할 곳입니다.

| VM | IP |
|---|---|
| Win10 (공격자) | 192.168.100.20 |
| Gateway | 192.168.100.53 |
| Kali (C2) | 192.168.200.10 |
| CustomerDB | 192.168.100.30 |

> 실험 중 Win10 이 막혀도 Gateway 콘솔에서는 언제든 풀 수 있습니다 (7단계). Gateway 는 화이트리스트라 스스로를 막지 않습니다.

---

## 0단계. 실험 전 상태 확인 (DNS 터널링이 지금 되는지)

**[Kali]** C2 수신 서버 실행
```bash
sudo python3 kali_dns_server.py
```

**[Win10]** PowerShell 에서
```powershell
nslookup test.tunnel.lab.test 192.168.100.53
.\win10_exfil.ps1        # 평소 쓰던 방식대로
```

**기대 결과:** Kali 의 `/tmp/exfil/` 에 파일이 생김. (지금은 아무것도 막지 않은 상태)

---

## 1단계. Gateway 에 파일 올리기

**[Gateway]** 아래 중 편한 방법으로 `block_server.py`, `test_alert.sh`, `reset_block.sh` 를 옮깁니다.
- 레포에 올렸다면: `git pull`
- VM 공유 폴더 / USB
- 다른 VM에서 scp: `scp block_server.py test_alert.sh reset_block.sh user@192.168.100.53:~/`

```bash
sudo mkdir -p /opt/honeytoken
sudo cp block_server.py /opt/honeytoken/
chmod +x test_alert.sh reset_block.sh
python3 --version          # 3.5.x 면 정상 (Ubuntu 16.04 기본)
which curl || sudo apt-get install -y curl
```

---

## 2단계. 연습 모드(dry-run)로 띄워 보기

실제로는 아무것도 막지 않고, 어떤 iptables 명령을 실행할지만 출력합니다.

**[Gateway] 터미널 1**
```bash
sudo python3 /opt/honeytoken/block_server.py --dry-run --log /tmp/ht.log
```
**기대 결과:**
```
[DRY-RUN] 체인 HONEYTOKEN_BLOCK 준비 (INPUT, FORWARD 에 연결)
[...] 허니토큰 차단 서버 시작 0.0.0.0:9999 (dry_run=True, ...)
```

**[Gateway] 터미널 2**
```bash
curl -s localhost:9999/health
./test_alert.sh 192.168.100.20 127.0.0.1
```
**기대 결과:** 응답 `{"ok": true, "ip": "192.168.100.20", "blocked": true, "new": true}`,
터미널 1 에 `[DRY-RUN] iptables -I HONEYTOKEN_BLOCK 1 -s 192.168.100.20 -j DROP` 과 `[BLOCKED] 192.168.100.20` 출력.

확인 후 터미널 1 에서 `Ctrl+C` 로 종료.

---

## 3단계. 실제 모드로 띄우기

**[Gateway] 터미널 1**
```bash
sudo python3 /opt/honeytoken/block_server.py --key labkey
```
**[Gateway] 터미널 2**
```bash
sudo iptables -S | grep HONEYTOKEN
```
**기대 결과:**
```
-N HONEYTOKEN_BLOCK
-A INPUT -j HONEYTOKEN_BLOCK
-A FORWARD -j HONEYTOKEN_BLOCK
```
(아직 DROP 규칙은 없음)

> Gateway 에 ufw 가 켜져 있으면 9999 를 DB 에서만 열어 주세요:
> `sudo iptables -I INPUT -p tcp -s 192.168.100.30 --dport 9999 -j ACCEPT`

---

## 4단계. 가짜 알림이 거부되는지 (보안 확인, 선택)

**[Win10]** 공격자가 직접 알림을 보내 Gateway/DB 를 막으려는 상황
```powershell
curl.exe -s -X POST http://192.168.100.53:9999/alert -H "Content-Type: application/json" -d "{\"attacker_ip\":\"192.168.100.30\"}"
```
**기대 결과:** `{"ok": false, "error": "sender not allowed"}` (403). 차단 규칙은 생기지 않음.

**[Gateway]** 키 없이 보내면
```bash
./test_alert.sh 192.168.100.20 127.0.0.1
```
**기대 결과:** `{"ok": false, "error": "bad key"}` (401). 3단계에서 `--key labkey` 로 띄웠기 때문.

---

## 5단계. 허니토큰 알림 흉내 → 차단

팀원 DB 가 보낼 알림을 대신 보냅니다. 실제 상황과 같게 하려면 **CustomerDB** 에서 보내세요 (curl 필요).

**[CustomerDB]** (또는 DB 가 없으면 Gateway 에서 `127.0.0.1` 로)
```bash
# test_alert.sh 를 복사해 두었다면
HT_SHARED_KEY=labkey ./test_alert.sh 192.168.100.20 192.168.100.53

# 스크립트 없이 한 줄로
curl -s -X POST http://192.168.100.53:9999/alert \
  -H "Content-Type: application/json" -H "X-Honeytoken-Key: labkey" \
  -d '{"attacker_ip":"192.168.100.20","honeytoken":{"id":1,"api_key":"sk_live_HONEY0001"}}'
```
**기대 결과:** `{"ok": true, "ip": "192.168.100.20", "blocked": true, "new": true}`
Gateway 터미널 1 에 `[BLOCKED] 192.168.100.20  (허니토큰: {...})`

**[Gateway]**
```bash
sudo iptables -S HONEYTOKEN_BLOCK
curl -s localhost:9999/blocked
sudo tail -n 5 /var/log/honeytoken_block.log
```
**기대 결과:** `-A HONEYTOKEN_BLOCK -s 192.168.100.20/32 -j DROP` 한 줄, 로그에 허니토큰 데이터 기록.

같은 명령을 한 번 더 보내 보세요 → `"new": false`, 규칙은 여전히 한 줄 (중복 방지).

---

## 6단계. DNS 터널링이 실제로 끊기는지

**[Win10]**
```powershell
nslookup test.tunnel.lab.test 192.168.100.53
.\win10_exfil.ps1
```
**기대 결과:**
- `nslookup` 이 `DNS request timed out` / `시간 초과`
- 유출 스크립트가 진행되지 않거나 오류
- **[Kali]** `/tmp/exfil/` 에 새 파일이 생기지 않음, 수신 서버 화면에 쿼리가 안 찍힘

**[Gateway]** 실제로 패킷이 떨어지는지 숫자로 확인 (발표 캡처용으로 좋음)
```bash
sudo iptables -L HONEYTOKEN_BLOCK -v -n
```
**기대 결과:** `192.168.100.20` 줄의 `pkts` 숫자가 Win10 이 시도할 때마다 늘어남.

> 0단계에서는 됐는데 6단계에서 안 되면 성공입니다.
> 6단계에서도 터널링이 된다면 Win10 의 DNS 가 Gateway 가 아닌 다른 서버를 쓰는지 확인하세요 (`ipconfig /all`).

---

## 7단계. 차단 해제 / 원상복구

**[Gateway]** 하나만 풀기 (서버가 켜져 있을 때)
```bash
curl -s -X POST 'localhost:9999/unblock?ip=192.168.100.20'
```

**[Gateway]** 전부 풀기 (서버가 꺼져 있어도 됨)
```bash
sudo ./reset_block.sh
# 또는
sudo iptables -F HONEYTOKEN_BLOCK
```

**[Gateway]** 실험 흔적까지 완전히 지우기
```bash
# 서버를 Ctrl+C 로 끈 뒤
sudo iptables -D INPUT -j HONEYTOKEN_BLOCK
sudo iptables -D FORWARD -j HONEYTOKEN_BLOCK
sudo iptables -F HONEYTOKEN_BLOCK
sudo iptables -X HONEYTOKEN_BLOCK
```

**확인:** **[Win10]** `nslookup test.tunnel.lab.test 192.168.100.53` 이 다시 응답하면 복구 완료.

> 주의: 서버를 꺼도 이미 들어간 차단 규칙은 남아 있습니다. 반대로 Gateway 를 재부팅하면 iptables 규칙이 사라집니다
> (서버를 다시 켜면 체인은 다시 만들어지지만, 차단된 IP 는 비어 있음).

---

## 문제가 생기면

| 증상 | 확인할 것 |
|---|---|
| `root 권한이 필요합니다` | `sudo` 로 실행 |
| `Address already in use` | 이미 서버가 떠 있음: `sudo ss -lntp \| grep 9999` |
| DB 에서 curl 이 멈춤 | Gateway 방화벽이 9999 를 막는지, 3단계 ACCEPT 규칙 |
| `sender not allowed` (DB에서 보냈는데) | DB 의 실제 IP 가 192.168.100.30 인지 (`ip addr`) |
| `SyntaxError` | `python3 --version` 이 3.5 미만인지 |
