#!/usr/bin/env python3
"""workload.py — одинаковая нагрузка для всех протоколов DPI-бенчмарка.

server: python3 workload.py serve [--port 8080] [--tls cert.pem key.pem]
client: python3 workload.py run --url http://10.77.0.2:8080 --out phases.json [--short]

Фазы (метки времени пишутся в phases.json, analyze.py режет по ним pcap):
  idle  — простой (виден keepalive/heartbeat)
  web   — 25 загрузок «страниц» 8–120 КБ с паузами 0.3–1.5 с
  chat  — 30 мелких запросов по 1 КБ (мелкие пакеты, как мессенджер)
  bulk  — одна большая загрузка (по умолчанию 20 МБ)
"""
import argparse, json, os, random, socket, ssl, sys, time
import http.server, socketserver, urllib.request

BLOCK = b"\0" * 65536


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        try:
            n = int(self.path.rsplit("/", 1)[-1])
        except ValueError:
            n = 1024
        n = max(0, min(n, 1 << 31))
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        self.end_headers()
        while n > 0:
            k = min(n, len(BLOCK))
            self.wfile.write(BLOCK[:k])
            n -= k


class TS(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(a):
    s = TS(("0.0.0.0", a.port), H)
    if a.tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.tls[0], a.tls[1])
        s.socket = ctx.wrap_socket(s.socket, server_side=True)
    s.serve_forever()


def get(url, n, timeout):
    ctx = ssl._create_unverified_context()
    t = time.time()
    with urllib.request.urlopen(f"{url}/n/{n}", timeout=timeout, context=ctx) as r:
        got = 0
        while True:
            b = r.read(65536)
            if not b:
                break
            got += len(b)
    return got, time.time() - t


def run(a):
    rnd = random.Random(a.seed)
    ph, res = {}, {"ok": 0, "fail": 0, "bytes": 0}
    short = a.short
    plan = [("idle", None), ("web", (8 if short else 25, 8_000, 120_000, 0.3, 1.5)),
            ("chat", (8 if short else 30, 1024, 1024, 0.2, 0.6)), ("bulk", None)]
    if a.phases:
        plan = [p for p in plan if p[0] in a.phases.split(",")]
    for name, spec in plan:
        t0 = time.time()
        if name == "idle":
            time.sleep(a.idle)
        elif name == "bulk":
            try:
                got, dt = get(a.url, a.bulk_mb * 1_000_000, a.timeout * 6)
                res["bytes"] += got
                res["ok"] += got == a.bulk_mb * 1_000_000
                res["bulk_mbps"] = round(got * 8 / dt / 1e6, 2)
            except Exception as e:
                res["fail"] += 1
                res["bulk_err"] = str(e)[:80]
        else:
            n, lo, hi, p0, p1 = spec
            for _ in range(n):
                sz = rnd.randint(lo, hi)
                try:
                    got, _ = get(a.url, sz, a.timeout)
                    res["bytes"] += got
                    res["ok"] += 1
                except Exception:
                    res["fail"] += 1
                time.sleep(rnd.uniform(p0, p1))
        ph[name] = [t0, time.time()]
    out = {"phases": ph, "result": res}
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)
    print(json.dumps(res))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sp = p.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("serve"); s.add_argument("--port", type=int, default=8080)
    s.add_argument("--tls", nargs=2)
    r = sp.add_parser("run"); r.add_argument("--url", required=True); r.add_argument("--out")
    r.add_argument("--short", action="store_true"); r.add_argument("--idle", type=float, default=40)
    r.add_argument("--bulk-mb", type=int, default=20); r.add_argument("--timeout", type=float, default=10)
    r.add_argument("--seed", type=int, default=7); r.add_argument("--phases")
    a = p.parse_args()
    serve(a) if a.cmd == "serve" else run(a)
