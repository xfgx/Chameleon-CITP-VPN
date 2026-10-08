#!/usr/bin/env python3
"""compare.py — что сделала сеть между клиентом (РФ) и сервером (зарубеж).

python3 compare.py <live-dir>   (cap/<proto>.pcap — запись клиента, server.pcap — запись сервера)

Для каждого протокола в его временном окне:
  * потери вверх/вниз (UDP — по совпадению содержимого пакетов, TCP — по байтам);
  * внедрённые пакеты: пришли получателю, но отправитель их не посылал (RST-инъекция и т.п.);
  * RST/FIN, увиденные каждой стороной;
  * самая длинная пауза входящего потока в фазе загрузки («заморозка»).
"""
import collections, hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DPI_LIVE", "1")
import analyze as A


def key(p):
    return (p["up"], p["pr"], p["len"], hashlib.sha1(p["pl"][:200]).hexdigest()[:16])


def main():
    out = sys.argv[1]
    srv_all = A.read_pcap(f"{out}/server.pcap")
    # на стороне сервера адрес клиента = DPI_C, свой адрес — частный; направление по src
    for p in srv_all:
        p["up"] = p["src"] == A.C
    rep = {}
    for proto in ["ks", "citp", "citp-cbr", "wg", "ovpn", "tls"]:
        f = f"{out}/cap/{proto}.pcap"
        if not os.path.exists(f):
            continue
        cl = A.flow(A.read_pcap(f), proto)
        if not cl:
            rep[proto] = {"note": "клиент ничего не записал"}; continue
        t0, t1 = cl[0]["t"] - 2, cl[-1]["t"] + 2
        sv = [p for p in A.flow(srv_all, proto) if t0 <= p["t"] <= t1]
        r = {"client_pkts": len(cl), "server_pkts": len(sv)}
        pr = A.PORT[proto][0]
        if pr == "udp":
            ck, sk = collections.Counter(map(key, cl)), collections.Counter(map(key, sv))
            up_sent = sum(v for k, v in ck.items() if k[0]); up_recv = sum(min(v, sk[k]) for k, v in ck.items() if k[0])
            dn_sent = sum(v for k, v in sk.items() if not k[0]); dn_recv = sum(min(v, ck[k]) for k, v in sk.items() if not k[0])
            inj_to_srv = sum(max(0, v - ck[k]) for k, v in sk.items() if k[0])
            inj_to_cl = sum(max(0, v - sk[k]) for k, v in ck.items() if not k[0])
            r.update(up_loss_pct=round(100 * (1 - up_recv / up_sent), 2) if up_sent else None,
                     down_loss_pct=round(100 * (1 - dn_recv / dn_sent), 2) if dn_sent else None,
                     injected_to_server=inj_to_srv, injected_to_client=inj_to_cl)
        else:
            ub_c = sum(p["len"] for p in cl if p["up"]); ub_s = sum(p["len"] for p in sv if p["up"])
            db_s = sum(p["len"] for p in sv if not p["up"]); db_c = sum(p["len"] for p in cl if not p["up"])
            r.update(up_bytes_client=ub_c, up_bytes_server=ub_s, down_bytes_server=db_s, down_bytes_client=db_c,
                     up_delivered_pct=round(100 * ub_s / ub_c, 1) if ub_c else None,
                     down_delivered_pct=round(100 * db_c / db_s, 1) if db_s else None)
        ph = {}
        pf = f"{out}/cap/{proto}.phases.json"
        if os.path.exists(pf):
            ph = json.load(open(pf)).get("phases", {})
        b = ph.get("bulk")
        if b:
            dn = [p["t"] for p in cl if not p["up"] and b[0] <= p["t"] <= b[1]]
            r["bulk_max_gap_s"] = round(max((y - x for x, y in zip(dn, dn[1:])), default=0), 2)
        res = f"{out}/cap/{proto}.result.json"
        if os.path.exists(res):
            try:
                r["result"] = json.load(open(res))
            except Exception:
                pass
        tl = f"{out}/cap/{proto}.tcpdump.log"
        if os.path.exists(tl):
            import re
            m = dict((b, int(a)) for a, b in re.findall(r"(\d+) packets (captured|received by filter)", open(tl).read()))
            r["client_capture_missed"] = m.get("received by filter", 0) - m.get("captured", 0)
        rep[proto] = r
    json.dump(rep, open(f"{out}/compare.json", "w"), indent=1, ensure_ascii=False)
    L = ["| Протокол | Работает | Скорость, Мбит/с | Потери ↑ / ↓ | Лишние у получателя* | Не записал tcpdump клиента | Макс. пауза загрузки, с |", "|---|---|---|---|---|---|---|"]
    for proto, r in rep.items():
        res = r.get("result") or {}
        okk = res.get("ok", 0)
        st = "✅" if okk >= 56 and not res.get("fail") else ("⚠️" if okk else "❌")
        if "up_loss_pct" in r:
            loss = f"{r['up_loss_pct']}% / {r['down_loss_pct']}%"; inj = r["injected_to_server"] + r["injected_to_client"]
        else:
            loss = f"{100 - (r.get('up_delivered_pct') or 0):.1f}% / {100 - (r.get('down_delivered_pct') or 0):.1f}% (байты)"; inj = "—"
        L.append(f"| {A.NAME[proto]} | {st} {okk}/56 | {res.get('bulk_mbps', '—')} | {loss} | {inj} | {r.get('client_capture_missed', '—')} | {r.get('bulk_max_gap_s', '—')} |")
    L += ["", "\\* пакеты, которые получатель записал, а отправитель — нет (кандидаты на инъекцию). Если их число не больше",
          "«не записал tcpdump клиента», это артефакт записи, а не вмешательство сети. Потери ↓ по той же причине завышены;",
          "для TCP «потери» по байтам включают ретрансляции."]
    open(f"{out}/compare.md", "w").write("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
