#!/usr/bin/env python3
"""analyze.py — «детекторы ТСПУ» поверх записей lab.sh. Без зависимостей.

python3 analyze.py <results-dir>   → report.json + report.md

Каждый детектор моделирует один публично описанный приём DPI/ТСПУ:
  D1 сигнатура      — известные заголовки (WireGuard, OpenVPN, TLS, QUIC, DTLS, STUN, HTTP)
  D2 FET            — правило «полностью зашифрованного трафика» (Wu et al., USENIX Sec'23:
                      popcount/байт в 3.4..4.6 и нет печатных признаков → блок)
  D3 первые 5 пакетов — окно ТСПУ «5 пакетов» (The Insider 2026-01): повторяется ли
                      (направление, длина) первых 5 пакетов от сеанса к сеансу
  D4 пульс простоя  — периодичный keepalive в простое (CV интервалов < 0.15)
  D5 ACK-эхо        — туннельный признак: в загрузке вверх идут пакеты одной длины
                      (это внутренние TCP ACK, обёрнутые туннелем)
  D6 длины mod 16   — блочный шифр/фиксированное выравнивание
  D7 активное зондирование — сервер отвечает зонду или закрывает по фиксированному таймеру
  D8 политики        — выживает ли протокол при блокировках из отчётов NTC/Habr
"""
import collections, glob, json, math, os, socket, statistics, struct, sys

C, S = os.environ.get("DPI_C", "198.18.1.2"), os.environ.get("DPI_S", "198.18.2.1")
PORT = {"ks": ("udp", 51830), "wg": ("udp", 51820), "ovpn": ("udp", 1194),
        "citp": ("tcp", int(os.environ.get("DPI_CITP_PORT", 9443))), "citp-cbr": ("tcp", int(os.environ.get("DPI_CITP_PORT", 9443))), "tls": ("tcp", 443)}
if os.environ.get("DPI_LIVE"):  # порты live-node.sh
    PORT.update(ks=("udp", 56001), wg=("udp", 56002), ovpn=("udp", 56003), **{"citp-cbr": ("tcp", 9444)})
NAME = {"ks": "KS", "citp": "CITP", "citp-cbr": "CITP + CBR", "wg": "WireGuard",
        "ovpn": "OpenVPN (UDP)", "tls": "HTTPS (эталон)"}


def read_pcap(path):
    pk = []
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return pk
        e = "<" if gh[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = gh[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        lt = struct.unpack(e + "I", gh[20:24])[0]
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            ts, tu, cl, _ = struct.unpack(e + "IIII", h)
            d = f.read(cl)
            ip = d[14:] if lt == 1 else d
            if len(ip) < 20 or ip[0] >> 4 != 4:
                continue
            ihl = (ip[0] & 15) * 4
            tot = struct.unpack(">H", ip[2:4])[0]
            pr = ip[9]
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            l4 = ip[ihl:]
            if pr == 17 and len(l4) >= 8:
                sp, dp = struct.unpack(">HH", l4[:4])
                plen = tot - ihl - 8; pl = l4[8:]
            elif pr == 6 and len(l4) >= 20:
                sp, dp = struct.unpack(">HH", l4[:4])
                thl = (l4[12] >> 4) * 4
                plen = tot - ihl - thl; pl = l4[thl:]
            else:
                continue
            pk.append({"t": ts + tu / (1e9 if nano else 1e6), "up": src == C, "pr": "udp" if pr == 17 else "tcp",
                       "sp": sp, "dp": dp, "len": plen, "pl": pl[:max(0, plen)], "src": src, "dst": dst})
    return pk


def flow(pk, proto):
    pr, port = PORT[proto]
    return [p for p in pk if p["pr"] == pr and ((p["up"] and p["dp"] == port) or (not p["up"] and p["sp"] == port))]


# --- D1 сигнатуры --------------------------------------------------------------
def signature(pl, pr):
    if len(pl) >= 4 and pr == "udp" and pl[0] in (1, 2, 3, 4) and pl[1:4] == b"\0\0\0":
        return "WireGuard"
    if len(pl) >= 3 and pl[0] == 0x16 and pl[1] == 3:
        return "TLS"
    if pl[:4] in (b"GET ", b"POST", b"HTTP"):
        return "HTTP"
    if pr == "udp" and len(pl) >= 5 and pl[0] & 0xC0 == 0xC0 and pl[1:5] in (b"\0\0\0\1", b"\x6b\x33\x43\xcf"):
        return "QUIC"
    if pr == "udp" and len(pl) >= 3 and pl[0] in (0x16, 0x17) and pl[1] == 0xFE:
        return "DTLS"
    if pr == "udp" and len(pl) >= 8 and pl[4:8] == b"\x21\x12\xa4\x42":
        return "STUN"
    return None


def flow_signature(data):
    """Сигнатура потока по первым пакетам в обе стороны (как L7-классификатор DPI)."""
    up = next((p for p in data if p["up"]), None)
    dn = next((p for p in data if not p["up"]), None)
    if not up:
        return None
    a, pr = up["pl"], up["pr"]
    b = dn["pl"] if dn else b""
    if pr == "udp" and len(a) >= 4 and a[0] == 1 and a[1:4] == b"\0\0\0" and up["len"] == 148:
        return "WireGuard"
    if pr == "udp" and a[:1] == b"\x38" and 14 <= up["len"] <= 64 and b[:1] == b"\x40":
        return "OpenVPN"  # P_CONTROL_HARD_RESET_CLIENT_V2 → SERVER_V2
    return signature(a, pr)


# --- D2 FET (Wu et al. 2023) --------------------------------------------------
def fet(pl):
    if not pl:
        return {"rule": False, "why": "нет данных"}
    pr = [32 <= b <= 126 for b in pl]
    pop = sum(bin(b).count("1") for b in pl) / len(pl)
    run = best = 0
    for x in pr:
        run = run + 1 if x else 0; best = max(best, run)
    ex = []
    if pop <= 3.4 or pop >= 4.6: ex.append("Ex1 popcount")
    if len(pl) >= 6 and all(pr[:6]): ex.append("Ex2 печатное начало")
    if sum(pr) / len(pl) > 0.5: ex.append("Ex3 >50% печатных")
    if best > 20: ex.append("Ex4 печатная серия")
    if signature(pl, "tcp") in ("TLS", "HTTP"): ex.append("Ex5 протокол")
    return {"rule": not ex, "popcount": round(pop, 2), "exempt": ex}


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b); n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def in_phase(p, ph, name, skip=0.0):
    a = ph.get(name)
    return a and a[0] + skip <= p["t"] <= a[1]


def analyze_capture(out, proto):
    pc = f"{out}/cap/{proto}.pcap"
    if not os.path.exists(pc):
        return None
    pk = flow(read_pcap(pc), proto)
    data = [p for p in pk if p["len"] > 0]
    ph = json.load(open(f"{out}/cap/{proto}.phases.json"))["phases"] if os.path.exists(f"{out}/cap/{proto}.phases.json") else {}
    res = json.load(open(f"{out}/cap/{proto}.result.json")) if os.path.exists(f"{out}/cap/{proto}.result.json") else {}
    r = {"packets": len(pk), "data_packets": len(data), "result": res}
    first_up = next((p for p in data if p["up"]), None)
    r["signature"] = flow_signature(data)
    r["fet"] = fet(first_up["pl"]) if first_up else None
    r["first_payload_len"] = first_up["len"] if first_up else None
    r["entropy_first5"] = round(entropy(b"".join(p["pl"] for p in data[:5])), 2)
    # D4 пульс простоя
    idle = [p for p in pk if p["up"] and p["len"] > 0 and in_phase(p, ph, "idle", 3)]
    if len(idle) >= 4:
        iat = [b["t"] - a["t"] for a, b in zip(idle, idle[1:])]
        m = statistics.mean(iat); cv = statistics.pstdev(iat) / m if m else 0
        r["idle"] = {"pkts": len(idle), "period_s": round(statistics.median(iat), 2), "cv": round(cv, 3),
                     "periodic": cv < 0.15, "sizes": sorted({p["len"] for p in idle})[:6]}
    else:
        r["idle"] = {"pkts": len(idle), "periodic": False}
    # D5 ACK-эхо и размеры
    bulk_up = [p for p in data if p["up"] and in_phase(p, ph, "bulk")]
    bulk_dn = [p for p in data if not p["up"] and in_phase(p, ph, "bulk")]
    if bulk_up:
        mode, cnt = collections.Counter(p["len"] for p in bulk_up).most_common(1)[0]
        mb = sum(p["len"] for p in bulk_dn) / 1e6 or 1
        r["ack_echo"] = {"up_pkts": len(bulk_up), "up_per_MB": round(len(bulk_up) / mb), "mode_len": mode,
                         "mode_share": round(cnt / len(bulk_up), 2),
                         "flag": len(bulk_up) / mb > 50 and cnt / len(bulk_up) > 0.6}
    else:
        r["ack_echo"] = {"up_pkts": 0, "flag": False}
    if bulk_dn:
        mode, cnt = collections.Counter(p["len"] for p in bulk_dn).most_common(1)[0]
        r["bulk_down"] = {"mode_len": mode, "mode_share": round(cnt / len(bulk_dn), 2)}
    wc = [p["len"] for p in data if in_phase(p, ph, "web") or in_phase(p, ph, "chat")]
    lens = collections.Counter(wc)
    r["size_entropy_bits"] = round(entropy(wc), 2) if wc else None
    dl = sorted(set(wc))
    res16 = collections.Counter(l % 16 for l in dl)
    r["mod16_share"] = round(res16.most_common(1)[0][1] / len(dl), 2) if len(dl) >= 8 else None
    r["distinct_sizes"] = len(lens)
    app = res.get("bytes") or 0
    r["overhead_pct"] = round(100 * (sum(p["len"] for p in data) / app - 1), 1) if app else None
    r["server_endpoints"] = len({(p["dst"], p["dp"]) for p in pk if p["up"]})
    r["client_ports"] = len({p["sp"] for p in pk if p["up"]})
    return r


def analyze_sessions(out, proto):
    fps = []
    for f in sorted(glob.glob(f"{out}/sess/{proto}.*.pcap")):
        d = [p for p in flow(read_pcap(f), proto) if p["len"] > 0][:5]
        fps.append(tuple(("↑" if p["up"] else "↓") + str(p["len"]) for p in d))
    if not fps:
        return None
    top, n = collections.Counter(fps).most_common(1)[0]
    return {"sessions": len(fps), "same_first5_share": round(n / len(fps), 2), "example": " ".join(top),
            "stable": n / len(fps) >= 0.8 and len(fps) >= 3}


def load_policies(out, proto):
    pol = {}
    for f in glob.glob(f"{out}/policy/{proto}.*.json"):
        name = os.path.basename(f)[len(proto) + 1:-5]
        try:
            d = json.load(open(f))
        except Exception:
            continue
        ok = d.get("ok", 0)
        pol[name] = {"ok": ok, "fail": d.get("fail", 0), "mbps": d.get("bulk_mbps"),
                     "status": "ok" if ok >= 17 and d.get("fail", 0) == 0 else ("partial" if ok > 0 else "fail")}
    return pol


def load_probe(out, proto):
    f = f"{out}/probe/{proto}.json"
    if not os.path.exists(f):
        return None
    d = json.load(open(f))
    pr = d["probes"]
    if d["proto"] == "udp":
        ans = [x["probe"] for x in pr if x.get("reply_bytes") or x.get("icmp")]
        return {"summary": d["summary"], "answered": ans, "flag": bool(ans)}
    conn = [x for x in pr if x.get("connect")]
    rb = sum(x.get("reply_bytes", 0) for x in conn)
    closes = [x["close_after_s"] for x in conn if x.get("closed_by") in ("fin", "rst")]
    fixed = len(closes) >= 3 and max(closes) - min(closes) < 1.5 and all(x.get("closed_by") != "timeout" for x in conn)
    return {"summary": d["summary"], "reply_bytes": rb, "fixed_close": fixed,
            "close_s": sorted(set(closes)), "flag": rb > 0 or fixed}


FLAGS = [("sig", "D1 сигнатура"), ("fet", "D2 FET"), ("first5", "D3 первые 5"), ("idle", "D4 пульс"),
         ("ack", "D5 ACK-эхо"), ("mod16", "D6 mod 16"), ("probe", "D7 зонд")]


def verdict(r):
    c, s, pb = r.get("capture") or {}, r.get("sessions") or {}, r.get("probe") or {}
    f = {}
    sig = c.get("signature")
    f["sig"] = sig if sig in ("WireGuard", "OpenVPN", "QUIC", "DTLS", "STUN") else None
    f["fet"] = bool((c.get("fet") or {}).get("rule"))
    f["first5"] = bool(s.get("stable"))
    f["idle"] = bool((c.get("idle") or {}).get("periodic"))
    f["ack"] = bool((c.get("ack_echo") or {}).get("flag"))
    f["mod16"] = (c.get("mod16_share") or 0) > 0.5
    f["probe"] = bool(pb.get("flag"))
    return f


def fmt_flag(k, v, r):
    c = r.get("capture") or {}
    if k == "sig":
        return f"🔴 {v}" if v else ("🟢 TLS" if c.get("signature") == "TLS" else "🟢 нет")
    if k == "fet":
        fe = c.get("fet") or {}
        return (f"🔴 попадает (popcount {fe.get('popcount')})" if v else
                f"🟢 исключение: {', '.join(fe.get('exempt', [])[:1]) or '—'}")
    if k == "first5":
        s = r.get("sessions") or {}
        if not s:
            return "—"
        return (f"🔴 {int(100*s.get('same_first5_share',0))}% сеансов: {s.get('example','')}" if v else
                f"🟢 {int(100*s.get('same_first5_share',0))}% совпадений")
    if k == "idle":
        i = c.get("idle") or {}
        return (f"🔴 каждые {i.get('period_s')} с (CV {i.get('cv')})" if v else
                f"🟢 {i.get('pkts',0)} пак., нерегулярно" if i.get("pkts") else "🟢 тишина")
    if k == "ack":
        a = c.get("ack_echo") or {}
        return (f"🔴 {a.get('mode_share',0)*100:.0f}% вверх = {a.get('mode_len')} Б" if v else
                f"🟢 {a.get('up_per_MB',0)} пак./МБ" if a.get("up_pkts") else "🟢 нет")
    if k == "mod16":
        return f"🔴 {c.get('mod16_share')}" if v else f"🟢 {c.get('mod16_share') if c.get('mod16_share') is not None else '—'}"
    if k == "probe":
        p = r.get("probe") or {}
        if not p:
            return "—"
        if p.get("close_s") is not None:
            return (f"🔴 закрывает ровно через {p['close_s']} с" if p.get("fixed_close") else
                    "🔴 отвечает" if p.get("reply_bytes") else "🟢 молчит")
        return f"🔴 ответ на {', '.join(p['answered'])}" if v else "🟢 молчит"
    return str(v)


POL_NAME = {"none": "без блокировок", "udp-block": "UDP в блоке", "ports-lt1000": "порты ≥1000 закрыты",
            "freeze16k": "заморозка после 16 КБ", "udp-ban": "бан IP за UDP"}


def main():
    out = sys.argv[1]
    protos = [p for p in ["ks", "citp", "citp-cbr", "wg", "ovpn", "tls"] if os.path.exists(f"{out}/cap/{p}.pcap")]
    rep = {}
    for p in protos:
        r = {"capture": analyze_capture(out, p), "sessions": analyze_sessions(out, p),
             "probe": load_probe(out, p), "policy": load_policies(out, p)}
        r["flags"] = verdict(r)
        r["score"] = sum(1 for v in r["flags"].values() if v)
        rep[p] = r
    json.dump(rep, open(f"{out}/report.json", "w"), indent=1, ensure_ascii=False, default=str)
    L = ["# DPI-бенчмарк: отчёт", "", f"Стенд: `{out}`. 🔴 = признак, за который DPI/ТСПУ может зацепиться; 🟢 = не зацепится.", ""]
    L.append("| Детектор | " + " | ".join(NAME[p] for p in protos) + " |")
    L.append("|---|" + "---|" * len(protos))
    for k, title in FLAGS:
        L.append(f"| {title} | " + " | ".join(fmt_flag(k, rep[p]["flags"][k], rep[p]) for p in protos) + " |")
    L.append("| **Итого признаков** | " + " | ".join(f"**{rep[p]['score']} из {len(FLAGS)}**" for p in protos) + " |")
    L += ["", "## Политики блокировки (D8)", "", "| Политика | " + " | ".join(NAME[p] for p in protos) + " |",
          "|---|" + "---|" * len(protos)]
    icon = {"ok": "✅", "partial": "⚠️", "fail": "❌"}
    for pol in ["none", "udp-block", "ports-lt1000", "freeze16k", "udp-ban"]:
        row = []
        for p in protos:
            x = rep[p]["policy"].get(pol)
            row.append("—" if not x else icon[x["status"]] + (f" {x['mbps']} Мбит/с" if x.get("mbps") and x["status"] != "fail" else ""))
        L.append(f"| {POL_NAME[pol]} | " + " | ".join(row) + " |")
    L += ["", "## Подробности", "", "| | " + " | ".join(NAME[p] for p in protos) + " |", "|---|" + "---|" * len(protos)]
    def g(p, *ks):
        x = rep[p]["capture"] or {}
        for k in ks:
            x = (x or {}).get(k) if isinstance(x, dict) else None
        return "—" if x is None else x
    rows = [("Первый пакет клиента, Б", ("first_payload_len",)), ("Энтропия первых 5, бит/Б", ("entropy_first5",)),
            ("Разных длин пакетов (web+chat)", ("distinct_sizes",)), ("Энтропия длин, бит", ("size_entropy_bits",)),
            ("Накладные расходы, %", ("overhead_pct",)), ("Скорость загрузки, Мбит/с", ("result", "bulk_mbps")),
            ("Пакетов в простое", ("idle", "pkts")), ("Серверных адресов:портов", ("server_endpoints",))]
    for title, ks in rows:
        L.append(f"| {title} | " + " | ".join(str(g(p, *ks)) for p in protos) + " |")
    L += ["", "Зонды:", ""] + [f"- **{NAME[p]}**: {(rep[p]['probe'] or {}).get('summary', '—')}" for p in protos]
    open(f"{out}/report.md", "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
