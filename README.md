# 네트워크 보안 실습 — DNS 터널링 공격/방어

경기대학교 네트워크보안 텀프로젝트. Win10 공격자가 고객 DB 를 읽어 DNS 터널링으로 Kali 에 빼돌리고,
DB 속 허니토큰(미끼 고객)이 조회되는 순간 Gateway 가 공격자 IP 를 차단해 유출을 끊습니다.
진행 현황과 팀 결정 변경사항은 [PROGRESS.md](PROGRESS.md) 참고.

## 환경

| VM | IP | 역할 | 주요 포트 |
|---|---|---|---|
| Win10 | 192.168.100.20 | 공격자 (DB 조회 + DNS 유출) | |
| Gateway | 192.168.100.53 | DNS 포워더(dnsmasq) + 허니토큰 차단 서버 (+ IDS, 유지 여부 미정) | 53/udp, 8080/tcp(알림 수신) |
| Kali | 192.168.200.10 | C2 수신 서버 | 53/udp |
| CustomerDB | 192.168.100.30 | 고객 DB(PostgreSQL 9.5, 허니토큰 포함) — 팀원 담당 | 5433/tcp |

## VM별 설치할 것

실습망은 VMware 내부 네트워크라 인터넷이 안 됩니다. 설치할 때만 아래 "임시 인터넷 연결"로 잠깐 붙였다가 끊습니다.

| VM | OS | 설치할 것 | 용도 |
|---|---|---|---|
| Win10 | Windows 10 | PostgreSQL Windows 설치 프로그램 중 **Command Line Tools**(`psql.exe`)만 | DB 조회(허니토큰 조회) |
| | | (기본 내장) PowerShell 5, `Resolve-DnsName`, `nslookup`, `curl.exe` | DNS 터널링 유출, 테스트 |
| Gateway | Ubuntu 16.04 | `git`, `curl`, `dnsmasq` | 레포 받기, 알림 테스트, DNS 포워딩 |
| | | (기본 내장) `python3`(3.5), `iptables` | 차단 서버 `block_server.py`, 차단 |
| | | (선택) `suricata` | IDS 보조 탐지 (유지 여부 미정) |
| Kali | Kali Linux | (기본 내장) `python3`, `git` | C2 수신 서버 `kali_dns_server.py` |

우리 Python 코드(`block_server.py`, `kali_dns_server.py`)는 표준 라이브러리만 써서 `pip` 설치가 필요 없습니다.
Gateway(Ubuntu 16.04) 는 처음 받았을 때 `git`, `curl` 이 없었습니다. 인터넷 연결은 아래 "임시 인터넷 연결" 을 먼저 하세요.

### Win10 (192.168.100.20)

PostgreSQL 클라이언트는 [PostgreSQL Windows 다운로드](https://www.postgresql.org/download/windows/) 의 64비트 설치 프로그램에서
구성 요소를 **Command Line Tools** 만 선택해 설치합니다 (서버는 필요 없음).

```powershell
# 설치 확인 (PowerShell). 버전 폴더(19)는 설치한 버전에 맞게 바꾸세요
$psql = 'C:\Program Files\PostgreSQL\19\bin\psql.exe'
& $psql --version

# 기본 내장 도구 확인
$PSVersionTable.PSVersion                  # 5.x
Get-Command Resolve-DnsName, nslookup, curl.exe

# 실습망 연결 확인
Test-NetConnection 192.168.100.30 -Port 5433   # DB
nslookup test.tunnel.lab.test 192.168.100.53   # Gateway DNS
```

### Gateway (192.168.100.53, Ubuntu 16.04)

```bash
# 설치
sudo apt-get update
sudo apt-get install -y git curl dnsmasq
sudo apt-get install -y suricata        # IDS 를 쓸 때만 (선택)

# 확인
git --version
curl --version | head -1
dnsmasq --version | head -1
python3 --version                       # 3.5.x (기본 내장)
sudo iptables -L -n | head -3           # 기본 내장
suricata -V                             # 설치한 경우만
```

### Kali (192.168.200.10)

설치할 것은 없습니다. 기본 내장 도구만 확인합니다.

```bash
python3 --version
git --version
# 없으면: sudo apt-get update && sudo apt-get install -y python3 git
```

### 임시 인터넷 연결 (설치할 때만)

1. VMware 에서 해당 VM 에 **네트워크 어댑터를 하나 추가하고 NAT 로 연결**합니다 (VM 설정 → Add → Network Adapter → NAT).
2. 새 NIC 에서 주소를 받습니다.
   ```bash
   ip -4 addr                      # 새로 생긴 NIC 이름 확인 (예: ens38)
   sudo dhclient ens38
   ```
3. DNS 를 8.8.8.8 로 바꿉니다. 내부망 DNS(Gateway)로는 외부 이름을 못 찾기 때문입니다.
   ```bash
   sudo cp /etc/resolv.conf /etc/resolv.conf.bak
   echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf
   ping -c 2 archive.ubuntu.com    # 응답 오면 연결 성공
   ```
4. 위 설치 명령을 실행합니다.
5. 끝나면 원래대로 돌립니다. **NAT 어댑터를 빼지 않으면 실험 결과가 달라질 수 있습니다** (트래픽이 NAT 쪽으로 나갈 수 있음).
   ```bash
   sudo dhclient -r ens38
   sudo cp /etc/resolv.conf.bak /etc/resolv.conf
   ```
   그다음 VMware 에서 NAT 어댑터를 제거(또는 연결 해제)합니다.

> Gateway 는 dnsmasq 가 `/etc/resolv.conf` 를 상위 DNS 로 읽을 수 있으니, 되돌린 뒤 `sudo systemctl restart dnsmasq` 로 다시 띄우세요.

### 레포 받기

```bash
git clone https://github.com/jihuns22/network_TermProject.git
```
Win10 은 git 이 없어도 됩니다. GitHub 에서 ZIP 으로 받거나 필요한 파일만 복사하세요.

## 지금까지 구현한 것

| 구성 | 폴더 / 위치 | 상태 |
|---|---|---|
| DNS 터널링 유출 (PowerShell, hex 인코딩) | [`attack/win10/`](attack/README.md) | 완료, 동작 확인 |
| C2 수신·파일 복원 (Python) | [`attack/kali/`](attack/README.md) | 완료, 동작 확인 |
| 허니토큰 고객 DB + 조회 알림 | 팀원 담당 · 요약 [`defense/customerdb/`](defense/customerdb/README.md) | 완료 (팀원) |
| 허니토큰 알림 수신 + iptables 자동 차단 | [`defense/gateway/block/`](defense/gateway/block/README.md) | 완료, 팀원 알림 형식에 맞춤. Gateway VM 실연동은 [EXPERIMENT.md](defense/gateway/block/EXPERIMENT.md) 8단계 |
| Suricata IDS 규칙 (SID 9001~9004) | [`defense/gateway/suricata/`](defense/gateway/README.md) | 동작 확인, 유지 여부 미정 |

## 구조

```
attack/
  win10/   → DNS 터널링 유출 스크립트 (PowerShell)
  kali/    → DNS 터널 수신 서버 (Python)

defense/
  gateway/block/    → 허니토큰 알림 수신 + iptables 자동 차단 서버 (block_server.py)
  gateway/suricata/ → Suricata IDS 탐지 규칙 및 설정 (유지 여부 미정)
  customerdb/       → 팀원 허니토큰 DB 요약과 연동 정보
```

## 흐름

```
① Win10 ──psql:5433──▶ CustomerDB   SELECT * FROM read_customers(...)
                                     (어떤 열로 정렬해도 첫 행이 미끼 고객)
② CustomerDB: 함수가 미끼 행을 낼 때 DB 로그에 HNY01 기록
   forward.py ──curl POST :8080/alerts {client_ip, cno, ...}──▶ Gateway
③ Gateway block_server.py: 출처 확인 → iptables HONEYTOKEN_BLOCK 에 client_ip DROP
                                       (INPUT + FORWARD)
④ Win10 ──DNS(hex)──▶ Gateway dnsmasq ──▶ Kali   ← ③ 이후 DROP, 유출 중단
```

DB 조회 자체(Win10 → DB, 같은 망)는 Gateway 를 거치지 않아 막을 수 없습니다.
이 구조는 **읽은 직후 DNS 로 빼내는 것**을 막습니다.

## 빠른 시연 순서

1. Kali: `sudo python3 attack/kali/kali_dns_server.py`
2. Gateway: `sudo python3 defense/gateway/block/block_server.py` (기본 :8080, 팀원 `gateway.py` 는 띄우지 않음)
3. CustomerDB: 팀원 README 대로 `server.py`, `forward.py` 실행
4. Win10: 유출 스크립트로 유출이 되는 것 확인 → psql 로 `read_customers()` 조회
5. Gateway 화면 `[BLOCKED] 192.168.100.20` → Win10 유출 재시도 시 DNS 타임아웃
6. 리셋: `sudo defense/gateway/block/reset_block.sh`

자세한 단계와 기대 결과는 [EXPERIMENT.md](defense/gateway/block/EXPERIMENT.md).
