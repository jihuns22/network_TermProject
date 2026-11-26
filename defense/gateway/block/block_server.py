#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
허니토큰 알림 수신 + 자동 차단 서버 (Gateway 192.168.100.53 용)

CustomerDB 쪽 허니토큰 감지 코드(팀원 customer-db-lab 의 forward.py)가 curl 로 알림을 보내면
  1) 보낸 쪽이 CustomerDB 인지, (설정했다면) 공유 키가 맞는지 확인하고
  2) 알림 안의 공격자 IP(client_ip)를 검증한 뒤 (화이트리스트 제외)
  3) iptables 전용 체인 HONEYTOKEN_BLOCK 에 DROP 규칙을 넣고
  4) 알림 내용(허니토큰 데이터 포함)을 JSON 로그로 남긴다.

Gateway 가 Ubuntu 16.04 (Python 3.5) 이므로 f-string 등 3.6+ 문법은 쓰지 않았다.

팀원 DB 가 보내는 알림 (허니토큰 행 1개당 1건, 공유 키 헤더 없음)
  POST http://192.168.100.53:8080/alerts
  {"event":"HONEYTOKEN_READ","event_id":"honeygen_5-3","time":"...","db":"honeygen_5",
   "login":"business_reader","client_ip":"192.168.100.20","cno":"ASN-658"}

팀원 forward.py 는 HTTP 2xx 를 받을 때까지 3초마다 같은 알림을 다시 보내고, 알림을 순서대로
하나씩 처리한다. 그래서 출처·형식이 정상인 알림은 차단을 하지 않는 경우(화이트리스트, 이미 차단됨)에도
200 으로 답해야 뒤 알림이 밀리지 않는다.

엔드포인트
  POST /alerts           팀원 DB 알림 (기본)
  POST /alert            같은 처리 (예전 제안 형식 attacker_ip/honeytoken 도 받음)
  POST /block?ip=x.x.x.x  예전 초안 호환용 (IP 만 전달)
  GET  /blocked          현재 차단 목록
  POST /unblock?ip=...   차단 해제 (Gateway 자신에서만 허용, 시연 리셋용)
  GET  /health           동작 확인
"""

import argparse
import ipaddress
import json
import os
import socketserver
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# ----------------------------------------------------------------------
# 설정 (환경변수 또는 명령행 인자로 바꿀 수 있음)
# ----------------------------------------------------------------------
LISTEN_HOST = os.environ.get("HT_LISTEN_HOST", "0.0.0.0")
# 팀원 DB .env 의 기본값 GATEWAY_PORT=8080, ALERT_PATH=/alerts 에 맞춤
LISTEN_PORT = int(os.environ.get("HT_LISTEN_PORT", "8080"))

# 알림을 보낼 수 있는 출처 (CustomerDB). 쉼표로 여러 개 가능.
ALLOWED_SENDERS = os.environ.get("HT_ALLOWED_SENDERS", "192.168.100.30,192.168.100.53,127.0.0.1")

# 공유 키. 비워두면 검사하지 않음 (기본). 팀원 forward.py 는 키 헤더를 보내지 않으므로
# 키를 쓰려면 팀원 curl 에 -H "X-Honeytoken-Key: <키>" 를 추가해야 함.
SHARED_KEY = os.environ.get("HT_SHARED_KEY", "")

# 절대 차단하면 안 되는 IP (Gateway 자신, DB, 루프백)
WHITELIST = os.environ.get("HT_WHITELIST", "127.0.0.1,192.168.100.53,192.168.100.30")

LOG_FILE = os.environ.get("HT_LOG_FILE", "/var/log/honeytoken_block.log")
CHAIN = "HONEYTOKEN_BLOCK"
MAX_BODY = 64 * 1024

DRY_RUN = False          # --dry-run 이면 iptables 를 실제로 실행하지 않음
_lock = threading.Lock()
_blocked = {}            # ip -> 최초 차단 정보


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def split_csv(s):
    return [x.strip() for x in s.split(",") if x.strip()]


def log_event(event):
    """JSON 한 줄씩 로그 파일에 쓰고 화면에도 출력."""
    event.setdefault("time", now_str())
    line = json.dumps(event, ensure_ascii=False)
    print(line)
    sys.stdout.flush()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception as e:  # 로그 실패가 차단을 막으면 안 됨
        print("[WARN] 로그 파일 기록 실패: %s" % e)


# ----------------------------------------------------------------------
# iptables
# ----------------------------------------------------------------------
def run_ipt(args):
    cmd = ["iptables"] + args
    if DRY_RUN:
        print("[DRY-RUN] " + " ".join(cmd))
        return 0
    return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_chain():
    """전용 체인을 만들고 INPUT/FORWARD 맨 앞에서 그 체인으로 점프시킨다.

    INPUT  : Win10 -> Gateway(dnsmasq :53) DNS 터널링 쿼리를 막음 (핵심)
    FORWARD: Gateway 를 거쳐 다른 망(Kali 등)으로 가는 트래픽을 막음
    """
    if DRY_RUN:
        print("[DRY-RUN] 체인 %s 준비 (INPUT, FORWARD 에 연결)" % CHAIN)
        return
    if run_ipt(["-N", CHAIN]) != 0:
        pass  # 이미 있음
    for parent in ("INPUT", "FORWARD"):
        if run_ipt(["-C", parent, "-j", CHAIN]) != 0:
            run_ipt(["-I", parent, "1", "-j", CHAIN])


def load_existing():
    """재시작해도 이미 차단된 IP 를 목록에 반영."""
    if DRY_RUN:
        return
    try:
        out = subprocess.check_output(["iptables", "-S", CHAIN]).decode()
    except Exception:
        return
    for line in out.splitlines():
        parts = line.split()
        if "-s" in parts and "DROP" in parts:
            ip = parts[parts.index("-s") + 1].split("/")[0]
            _blocked.setdefault(ip, {"ip": ip, "blocked_at": "(재시작 전)", "reason": "existing"})


def block_ip(ip):
    """차단. 이미 차단돼 있으면 False."""
    if not DRY_RUN and run_ipt(["-C", CHAIN, "-s", ip, "-j", "DROP"]) == 0:
        return False
    if ip in _blocked:
        return False
    rc = run_ipt(["-I", CHAIN, "1", "-s", ip, "-j", "DROP"])
    if rc != 0:
        raise RuntimeError("iptables 실패 (rc=%d). root 권한으로 실행했는지 확인" % rc)
    return True


def unblock_ip(ip):
    removed = False
    while run_ipt(["-C", CHAIN, "-s", ip, "-j", "DROP"]) == 0 and not DRY_RUN:
        run_ipt(["-D", CHAIN, "-s", ip, "-j", "DROP"])
        removed = True
    if ip in _blocked:
        del _blocked[ip]
        removed = True
    return removed


# ----------------------------------------------------------------------
# 검증
# ----------------------------------------------------------------------
def validate_ip(value):
    """IPv4 주소만 허용. 문제 있으면 (None, 이유)."""
    if not value:
        return None, "attacker_ip 없음"
    try:
        ip = ipaddress.ip_address(str(value).strip().split("/")[0])
    except ValueError:
        return None, "IP 형식 아님: %r" % value
    if ip.version != 4:
        return None, "IPv4 만 지원"
    s = str(ip)
    if s in split_csv(WHITELIST) or ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return None, "화이트리스트/특수 주소라 차단 안 함: %s" % s
    return s, None


# ----------------------------------------------------------------------
# HTTP
# ----------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "HoneytokenBlock/1.0"

    def log_message(self, fmt, *args):  # 기본 접속 로그는 끔 (우리 로그만)
        pass

    def reply(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def sender(self):
        return self.client_address[0]

    def check_sender(self):
        if self.sender() not in split_csv(ALLOWED_SENDERS):
            log_event({"event": "rejected", "why": "허용되지 않은 출처", "sender": self.sender(),
                       "path": self.path})
            self.reply(403, {"ok": False, "error": "sender not allowed"})
            return False
        if SHARED_KEY and self.headers.get("X-Honeytoken-Key", "") != SHARED_KEY:
            log_event({"event": "rejected", "why": "공유 키 불일치", "sender": self.sender()})
            self.reply(401, {"ok": False, "error": "bad key"})
            return False
        return True

    def read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("본문이 너무 큼")
        raw = self.rfile.read(length).decode("utf-8", "replace")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("JSON 객체여야 함")
        return data

    # ---------------- GET ----------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            return self.reply(200, {"ok": True, "dry_run": DRY_RUN})
        if path == "/blocked":
            with _lock:
                return self.reply(200, {"ok": True, "blocked": list(_blocked.values())})
        self.reply(404, {"ok": False, "error": "not found"})

    # ---------------- POST ----------------
    def do_POST(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)

        if u.path == "/unblock":
            if self.sender() not in ("127.0.0.1", "192.168.100.53"):
                return self.reply(403, {"ok": False, "error": "localhost only"})
            ip = (qs.get("ip") or [""])[0]
            with _lock:
                removed = unblock_ip(ip)
            log_event({"event": "unblocked", "ip": ip, "removed": removed})
            return self.reply(200, {"ok": True, "ip": ip, "removed": removed})

        if u.path not in ("/alerts", "/alert", "/block"):
            return self.reply(404, {"ok": False, "error": "not found"})

        if not self.check_sender():
            return

        try:
            data = self.read_json()
        except Exception as e:
            log_event({"event": "rejected", "why": "JSON 파싱 실패: %s" % e, "sender": self.sender()})
            return self.reply(400, {"ok": False, "error": "bad json"})

        # 공격자 IP: 팀원 형식 client_ip, 예전 제안 형식 attacker_ip, 초안 /block?ip=...
        raw_ip = data.get("client_ip") or data.get("attacker_ip") or (qs.get("ip") or [""])[0]
        ip, err = validate_ip(raw_ip)

        honeytoken = data.get("honeytoken")
        if honeytoken is None and data.get("cno"):
            # 팀원 형식: 조회된 미끼 고객번호(cno)와 DB 이름, 이벤트 번호
            honeytoken = {"cno": data.get("cno"), "db": data.get("db"),
                          "event_id": data.get("event_id")}

        alert = {
            "event": "alert",
            "sender": self.sender(),
            "db_event": data.get("event"),            # HONEYTOKEN_READ
            "event_id": data.get("event_id"),
            "attacker_ip": raw_ip,
            "honeytoken": honeytoken,
            "query": data.get("query"),
            "db_user": data.get("login") or data.get("db_user"),
            "detected_at": data.get("time") or data.get("detected_at"),
        }
        log_event(alert)

        if err:
            # 출처는 정상이므로 200 으로 답한다. 4xx 를 주면 팀원 forward.py 가 같은 알림을
            # 무한 재시도하면서 뒤 알림 전체가 멈춘다.
            log_event({"event": "not_blocked", "why": err, "event_id": data.get("event_id")})
            return self.reply(200, {"ok": False, "blocked": False, "error": err})

        try:
            with _lock:
                newly = block_ip(ip)
                if newly:
                    _blocked[ip] = {
                        "ip": ip,
                        "blocked_at": now_str(),
                        "honeytoken": honeytoken,
                    }
        except RuntimeError as e:
            log_event({"event": "block_failed", "ip": ip, "why": str(e)})
            return self.reply(500, {"ok": False, "error": str(e)})

        if newly:
            log_event({"event": "blocked", "ip": ip})
            print("[BLOCKED] %s  (허니토큰: %s)" % (ip, json.dumps(honeytoken, ensure_ascii=False)))
        else:
            log_event({"event": "already_blocked", "ip": ip})
        self.reply(200, {"ok": True, "ip": ip, "blocked": True, "new": newly})


class ThreadedServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    global DRY_RUN, LISTEN_PORT, LOG_FILE, SHARED_KEY
    ap = argparse.ArgumentParser(description="허니토큰 알림 수신 + iptables 자동 차단")
    ap.add_argument("--port", type=int, default=LISTEN_PORT)
    ap.add_argument("--dry-run", action="store_true", help="iptables 실행 없이 출력만")
    ap.add_argument("--log", default=LOG_FILE)
    ap.add_argument("--key", default=SHARED_KEY, help="공유 키 (X-Honeytoken-Key 헤더)")
    a = ap.parse_args()
    DRY_RUN, LISTEN_PORT, LOG_FILE, SHARED_KEY = a.dry_run, a.port, a.log, a.key

    if not DRY_RUN and os.geteuid() != 0:
        print("root 권한이 필요합니다: sudo python3 block_server.py")
        sys.exit(1)

    setup_chain()
    load_existing()
    print("[%s] 허니토큰 차단 서버 시작 %s:%d (dry_run=%s, 허용 출처=%s, 키 검사=%s)"
          % (now_str(), LISTEN_HOST, LISTEN_PORT, DRY_RUN, ALLOWED_SENDERS, bool(SHARED_KEY)))
    ThreadedServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
