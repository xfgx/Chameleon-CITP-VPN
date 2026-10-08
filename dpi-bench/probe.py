#!/usr/bin/env python3
"""probe.py — активное зондирование сервера, как это делает цензор (GFW/ТСПУ).

UDP: случайные датаграммы разной длины, повтор (replay) настоящего первого пакета
     клиента, его обрезка и порча одного бита. Фиксируем любой ответ: UDP или ICMP.
TCP: подключение (открыт ли порт), затем: тишина, 1 байт, 104 случайных байта
     (длина hello CITP), HTTP GET, TLS ClientHello, replay настоящего первого
     сообщения. Фиксируем ответные байты и через сколько секунд сервер закрыл
     соединение (одинаковый таймаут закрытия — тоже отпечаток).
"""
import argparse, json, os, socket, struct, threading, time


def first_payloads(pcap, client, proto, port, n=2):
    out = []
    with open(pcap, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return out
        le = gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        e = "<" if le else ">"
        lt = struct.unpack(e + "I", gh[20:24])[0]
        while len(out) < n:
            h = f.read(16)
            if len(h) < 16:
                break
            _, _, cl, _ = struct.unpack(e + "IIII", h)
            d = f.read(cl)
            off = 14 if lt == 1 else 0
            ip = d[off:]
            if len(ip) < 20 or ip[0] >> 4 != 4:
                continue
            ihl = (ip[0] & 15) * 4
            src = socket.inet_ntoa(ip[12:16])
            pr = ip[9]
            l4 = ip[ihl:]
            if src != client:
                continue
            if proto == "udp" and pr == 17 and struct.unpack(">H", l4[2:4])[0] == port:
                out.append(l4[8:])
            elif proto == "tcp" and pr == 6 and struct.unpack(">H", l4[2:4])[0] == port:
                pl = l4[(l4[12] >> 4) * 4:]
                if pl:
                    out.append(pl)
    return out


def icmp_listener(stop, hits, host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return
    s.settimeout(0.3)
    while not stop.is_set():
        try:
            d, a = s.recvfrom(2048)
            if a[0] == host and d[20] == 3:  # destination unreachable
                hits.append(time.time())
        except socket.timeout:
            pass


def udp_probes(a, replay):
    tests = [(f"random-{n}", os.urandom(n)) for n in (1, 16, 28, 64, 148, 512, 1200)]
    if replay:
        r = replay[0]
        tests += [("replay-first", r), ("replay-truncated", r[: max(1, len(r) // 2)]),
                  ("replay-bitflip", r[:-1] + bytes([r[-1] ^ 1]))]
    stop, icmp = threading.Event(), []
    th = threading.Thread(target=icmp_listener, args=(stop, icmp, a.host), daemon=True)
    th.start()
    res = []
    for name, data in tests:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.5)
        t0 = time.time(); n0 = len(icmp)
        s.sendto(data, (a.host, a.port))
        got = None
        try:
            d, _ = s.recvfrom(4096)
            got = len(d)
        except (socket.timeout, ConnectionRefusedError):
            pass
        time.sleep(0.2)
        res.append({"probe": name, "sent": len(data), "reply_bytes": got, "icmp": len(icmp) > n0})
        s.close()
    stop.set()
    return res


def tcp_one(a, name, data, out):
    t0 = time.time()
    r = {"probe": name, "sent": len(data) if data else 0}
    try:
        s = socket.create_connection((a.host, a.port), timeout=5)
    except Exception as e:
        r.update(connect=False, err=type(e).__name__)
        out.append(r); return
    r["connect"] = True
    s.settimeout(a.hold)
    if data:
        s.sendall(data)
    got = 0; how = "timeout"
    t1 = time.time()
    try:
        while True:
            d = s.recv(4096)
            if not d:
                how = "fin"; break
            got += len(d)
    except ConnectionResetError:
        how = "rst"
    except socket.timeout:
        how = "timeout"
    r.update(reply_bytes=got, closed_by=how, close_after_s=round(time.time() - t1, 1))
    s.close(); out.append(r)


def tcp_probes(a, replay):
    hello = bytes.fromhex("16030100c8010000c40303") + os.urandom(32) + b"\x00\x00\x02\x13\x01\x01\x00" + b"\x00" * 140
    tests = [("silence", b""), ("random-1", os.urandom(1)), ("random-104", os.urandom(104)),
             ("random-600", os.urandom(600)), ("http-get", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
             ("tls-clienthello", hello)]
    if replay:
        tests.append(("replay-first", replay[0]))
    out, th = [], []
    for name, data in tests:
        t = threading.Thread(target=tcp_one, args=(a, name, data, out)); t.start(); th.append(t)
        time.sleep(0.1)
    [t.join() for t in th]
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--proto", required=True); p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True); p.add_argument("--replay")
    p.add_argument("--client"); p.add_argument("--out", required=True)
    p.add_argument("--hold", type=float, default=70)
    a = p.parse_args()
    rp = first_payloads(a.replay, a.client, a.proto, a.port) if a.replay else []
    res = udp_probes(a, rp) if a.proto == "udp" else tcp_probes(a, rp)
    answered = [r for r in res if r.get("reply_bytes") or r.get("icmp")]
    if a.proto == "udp":
        summary = f"ответов {len(answered)}/{len(res)}" + (" (" + ", ".join(r["probe"] for r in answered) + ")" if answered else " — сервер молчит")
    else:
        closes = sorted({r.get("close_after_s") for r in res if r.get("connect")})
        how = sorted({r.get("closed_by") for r in res if r.get("connect")})
        summary = (f"порт открыт; ответных байт {sum(r.get('reply_bytes', 0) for r in res)}; закрытие: "
                   f"{'/'.join(how)} через {closes} с")
    json.dump({"proto": a.proto, "port": a.port, "replay_len": [len(x) for x in rp], "probes": res,
               "summary": summary}, open(a.out, "w"), indent=1, ensure_ascii=False)
    print(summary)


if __name__ == "__main__":
    main()
