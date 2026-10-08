#!/usr/bin/env python3
"""Графики бенчмарка Chameleon KS (SVG без зависимостей).

  charts.py --series "ks-hub 2=B.jsonl" "ks-hub 3=C.jsonl" ... --svgdir docs/bench --html out.html

Вход — строки JSON от ks-stress / bench.sh (users, alive_users, ka_rtt_ms_p50/p95,
connect_ms_p95, mem_peak). Выход:
  * --svgdir: отдельные SVG для README (тёмная/светлая тема по prefers-color-scheme);
  * --html:   фрагмент для сайта (inline SVG, тема из CSS-переменных страницы).
"""
import argparse, json, math, os, html

COLORS = ["#ff7a59", "#4c8dff", "#30d158", "#bf5af2", "#ffd60a"]
W, H = 560, 300
ML, MR, MT, MB = 58, 18, 18, 42

def dl(sec):
    return f"kc-dl{int(round(sec*20))}"

def load(path):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    return sorted(rows, key=lambda r: r["users"])

def fmt_ms(v):
    if v >= 1000:
        s = f"{v/1000:.1f}".rstrip("0").rstrip(".").replace(".", ",")
        return f"{s} с"
    return f"{v:.0f} мс"

class Ax:
    def __init__(s, xs, ylo, yhi, log=False):
        s.xlo, s.xhi = min(xs), max(xs); s.ylo, s.yhi, s.log = ylo, yhi, log
    def x(s, v):
        return ML + (v - s.xlo) / (s.xhi - s.xlo or 1) * (W - ML - MR)
    def y(s, v):
        if s.log:
            v = max(v, s.ylo); f = (math.log10(v) - math.log10(s.ylo)) / (math.log10(s.yhi) - math.log10(s.ylo))
        else:
            f = (v - s.ylo) / (s.yhi - s.ylo)
        return H - MB - min(max(f, 0), 1) * (H - MT - MB)

def frame(ax, xs, yticks, ylab):
    o = []
    for t in yticks:
        y = ax.y(t)
        o.append(f'<line class="kc-gl" x1="{ML}" x2="{W-MR}" y1="{y:.1f}" y2="{y:.1f}"/>')
        o.append(f'<text x="{ML-8}" y="{y+3.5:.1f}" text-anchor="end">{ylab(t)}</text>')
    for v in xs:
        o.append(f'<text x="{ax.x(v):.1f}" y="{H-MB+18}" text-anchor="middle">{v}</text>')
    o.append(f'<text x="{(ML+W-MR)/2:.0f}" y="{H-6}" text-anchor="middle" class="kc-cap">пользователей</text>')
    o.append(f'<line class="kc-ax" x1="{ML}" x2="{W-MR}" y1="{H-MB}" y2="{H-MB}"/>')
    return o

def lines(ax, series, key, ok=lambda r: True, tip=lambda r, v: "", area=False, fails=True):
    o = []
    for i, (name, rows) in enumerate(series):
        c = COLORS[i % len(COLORS)]
        pts = [(ax.x(r["users"]), ax.y(r[key]), r) for r in rows if ok(r)]
        if not pts:
            continue
        d = "M" + " L".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts)
        if area and len(pts) > 1 and (area == "all" or i == len(series) - 1):
            o.append(f'<path d="{d} L{pts[-1][0]:.1f},{H-MB} L{pts[0][0]:.1f},{H-MB} Z" fill="url(#kcg{i})" class="kc-area"/>')
        o.append(f'<path d="{d}" stroke="{c}" class="kc-line {dl(i*0.25)}"/>')
        for x, y, r in pts:
            o.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="4" fill="{c}" class="kc-dot {dl(0.9+i*0.25)}"><title>{html.escape(name)} · {r["users"]} польз.: {tip(r, r[key])}</title></circle>')
        if fails:
            for r in rows:
                if not ok(r):
                    x, y = ax.x(r["users"]), MT + 10
                    o.append(f'<g class="kc-dot {dl(1.4)}"><path d="M{x-5:.1f},{y-5} l10,10 m0,-10 l-10,10" stroke="{c}" stroke-width="2.5" stroke-linecap="round"/>'
                             f'<text x="{x-9:.1f}" y="{y+4}" text-anchor="end" class="kc-bad kc-t{i % len(COLORS)}">отказ</text><title>{html.escape(name)} · {r["users"]}: 0 на связи</title></g>')
    return o

def grads(n):
    return "<defs>" + "".join(f'<linearGradient id="kcg{i}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="{COLORS[i%5]}" stop-opacity=".22"/><stop offset="1" stop-color="{COLORS[i%5]}" stop-opacity="0"/></linearGradient>' for i in range(n)) + "</defs>"

def ch_latency(series, xs):
    ax = Ax(xs, 100, 20000, log=True)
    o = [grads(len(series))]
    o.append(f'<rect class="kc-ok" x="{ML}" y="{ax.y(500):.1f}" width="{W-ML-MR}" height="{ax.y(100)-ax.y(500):.1f}"/>')
    o.append(f'<text x="{W-MR-6}" y="{ax.y(500)+13:.1f}" text-anchor="end" class="kc-okt">норма ≤ 500 мс</text>')
    o += frame(ax, xs, [100, 200, 500, 1000, 2000, 5000, 10000, 20000], fmt_ms)
    o += lines(ax, series, "ka_rtt_ms_p95", ok=lambda r: r["alive_users"] > 0 and r["ka_rtt_ms_p95"] > 0,
               tip=lambda r, v: f"p95 {fmt_ms(v)}, p50 {fmt_ms(r.get('ka_rtt_ms_p50', 0))}", area=True)
    return ("Задержка p95", "95% ответов быстрее этой отметки. Ниже — лучше, логарифмическая шкала.", o)

def ch_alive(series, xs):
    ax = Ax(xs, 0, 100)
    o = []
    for t in [0, 25, 50, 75, 100]:
        y = ax.y(t)
        o.append(f'<line class="kc-gl" x1="{ML}" x2="{W-MR}" y1="{y:.1f}" y2="{y:.1f}"/><text x="{ML-8}" y="{y+3.5:.1f}" text-anchor="end">{t}%</text>')
    n = len(series); band = (W - ML - MR) / len(xs); gw = band * 0.7; bw = gw / n
    for gi, u in enumerate(xs):
        cx = ML + band * (gi + 0.5)
        o.append(f'<text x="{cx:.1f}" y="{H-MB+18}" text-anchor="middle">{u}</text>')
        for i, (name, rows) in enumerate(series):
            r = next((r for r in rows if r["users"] == u), None)
            if not r: continue
            pct = r["alive_users"] * 100 / r["users"]; x = cx - gw / 2 + i * bw
            hgt = max(H - MB - ax.y(pct), 2)
            o.append(f'<rect x="{x+1.5:.1f}" y="{H-MB-hgt:.1f}" width="{bw-3:.1f}" height="{hgt:.1f}" rx="3" fill="{COLORS[i%5]}" class="kc-bar {dl(0.1*gi+0.05*i)}"><title>{html.escape(name)} · {u} польз.: {r["alive_users"]} на связи ({pct:.0f}%)</title></rect>')
            if pct < 99.5:
                o.append(f'<text x="{x+bw/2:.1f}" y="{H-MB-hgt-6:.1f}" text-anchor="middle" class="kc-val kc-t{i%5}">{pct:.0f}%</text>')
    o.append(f'<text x="{(ML+W-MR)/2:.0f}" y="{H-6}" text-anchor="middle" class="kc-cap">пользователей</text>')
    o.append(f'<line class="kc-ax" x1="{ML}" x2="{W-MR}" y1="{H-MB}" y2="{H-MB}"/>')
    return ("Пользователей на связи", "Доля клиентов, которые получали ответы во время измерения.", o)

def ch_mem(series, xs):
    mx = max((r.get("mem_peak", 0) for _, rows in series for r in rows), default=0) / 2**20
    top = max(100, math.ceil(mx / 100) * 100)
    ax = Ax(xs, 0, top)
    o = [grads(len(series))] + frame(ax, xs, [top * k / 4 for k in range(5)], lambda t: f"{t:.0f} МБ")
    o += lines(ax, [(n, [dict(r, mem=r.get("mem_peak", 0) / 2**20) for r in rows if r.get("mem_peak")]) for n, rows in series],
               "mem", tip=lambda r, v: f"{v:.0f} МБ", area="all", fails=False)
    last = [(n, rows[-1]) for n, rows in series if rows and rows[-1].get("mem_peak")]
    if len(last) >= 2:
        hi = max(last, key=lambda t: t[1]["mem_peak"]); lo = min(last, key=lambda t: t[1]["mem_peak"])
        k = hi[1]["mem_peak"] / lo[1]["mem_peak"]
        o.append(f'<text x="{ax.x(xs[-1])-10:.1f}" y="{(ax.y(hi[1]["mem_peak"]/2**20)+ax.y(lo[1]["mem_peak"]/2**20))/2:.1f}" text-anchor="end" class="kc-note">в {k:.1f}× меньше</text>'.replace(".", ",", 1) if False else
                 f'<text x="{ax.x(xs[-1])-10:.1f}" y="{(ax.y(hi[1]["mem_peak"]/2**20)+ax.y(lo[1]["mem_peak"]/2**20))/2:.1f}" text-anchor="end" class="kc-note">в {str(round(k,1)).replace(".",",")}× меньше памяти</text>')
    return ("Память хаба", "Пиковое потребление RAM (systemd MemoryPeak).", o)

def ch_connect(series, xs):
    ax = Ax(xs, 200, 20000, log=True)
    o = [grads(len(series))] + frame(ax, xs, [200, 500, 1000, 2000, 5000, 10000, 20000], fmt_ms)
    o += lines(ax, series, "connect_ms_p95", ok=lambda r: r.get("connect_ms_p95", 0) > 0,
               tip=lambda r, v: f"подключение p95 {fmt_ms(v)}", fails=False)
    return ("Время подключения p95", "От первого пакета до первого ответа хаба. Ниже — лучше.", o)

CSS_BASE = """
.kc{--kc-mu:var(--muted,#8e8e93);--kc-fg:var(--fg,#f5f5f7);font-family:var(--font,ui-sans-serif,system-ui,sans-serif)}
.kc-legend{display:flex;flex-wrap:wrap;gap:8px 18px;margin:14px 0 10px;font-size:13px;color:var(--kc-mu)}
.kc-legend i{display:inline-block;width:18px;height:4px;border-radius:2px;margin-right:7px;vertical-align:middle}
.kc-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,520px),1fr));gap:16px;margin:6px 0 18px}
.kc-card{border:1px solid rgba(127,127,127,.2);border-radius:18px;padding:16px 14px 6px;background:rgba(127,127,127,.05)}
.kc-card h4{margin:0 0 3px;font-size:15px;font-weight:600}
.kc-card p{margin:0 0 6px;font-size:12.5px;color:var(--kc-mu);line-height:1.4}
.kc svg{width:100%;height:auto;display:block;overflow:visible}
.kc svg text{fill:var(--kc-mu);font:12px var(--mono,ui-monospace,monospace)}
.kc svg text.kc-cap{font-size:10.5px;opacity:.8}
.kc svg text.kc-bad,.kc svg text.kc-val{font-weight:700}
.kc svg text.kc-note{fill:#30d158;font-weight:700;font-size:12px}
.kc svg text.kc-okt{fill:#30d158;opacity:.8}
.kc-gl{stroke:rgba(127,127,127,.15)}.kc-ax{stroke:rgba(127,127,127,.4)}
.kc-ok{fill:#30d158;opacity:.07}
.kc-line{fill:none;stroke-width:2.6;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:1400;stroke-dashoffset:1400;animation:kc-draw 1.5s cubic-bezier(.4,0,.2,1) forwards}
.kc-area{opacity:0;animation:kc-fade .8s ease 1.2s forwards}
.kc-dot{opacity:0;animation:kc-fade .4s ease 1s forwards;transition:r .15s}
circle.kc-dot:hover{r:6.5}
.kc-bar{transform-box:fill-box;transform-origin:50% 100%;transform:scaleY(0);animation:kc-grow .7s cubic-bezier(.2,.8,.2,1) forwards}
.kc-bar:hover{filter:brightness(1.25)}
.kc-wait .kc-line,.kc-wait .kc-area,.kc-wait .kc-dot,.kc-wait .kc-bar{animation-play-state:paused}
@keyframes kc-draw{to{stroke-dashoffset:0}}@keyframes kc-fade{to{opacity:1}}@keyframes kc-grow{to{transform:scaleY(1)}}
@media (prefers-reduced-motion:reduce){.kc-line,.kc-area,.kc-dot,.kc-bar{animation:none!important;opacity:1;stroke-dashoffset:0;transform:none}}
"""

CSS = CSS_BASE + "".join(f".kc-dl{k}{{animation-delay:{k/20:.2f}s!important}}" for k in range(61)) \
    + "".join(f".kc-b{i}{{background:{c}}}.kc svg text.kc-t{i},svg text.kc-t{i}{{fill:{c}}}" for i, c in enumerate(COLORS)) \
    + ".kc-raw{margin:4px 0 18px}.kc-raw summary{cursor:pointer;color:var(--muted);font-size:13.5px;margin-bottom:8px}"

JS = """(()=>{const go=()=>document.querySelectorAll('.kc').forEach(r=>{if(!('IntersectionObserver'in window))return;r.classList.add('kc-wait');
new IntersectionObserver((e,o)=>{e.forEach(x=>{if(x.isIntersecting){r.classList.remove('kc-wait');o.disconnect()}})},{threshold:.2}).observe(r)});
document.readyState==='loading'?document.addEventListener('DOMContentLoaded',go):go()})();"""

def build(series):
    xs = sorted({r["users"] for _, rows in series for r in rows})
    charts = [ch_latency(series, xs), ch_alive(series, xs), ch_mem(series, xs), ch_connect(series, xs)]
    return xs, charts

def html_fragment(series, charts, title_note=""):
    leg = "".join(f'<span><i class="kc-b{i%5}"></i>{html.escape(n)}</span>' for i, (n, _) in enumerate(series))
    cards = "".join(f'<figure class="kc-card"><h4>{t}</h4><p>{s}</p><svg viewBox="0 0 {W} {H}" role="img" aria-label="{t}">{"".join(b)}</svg></figure>' for t, s, b in charts)
    return f'<div class="kc"><div class="kc-legend">{leg}</div><div class="kc-grid">{cards}</div></div>'

def svg_standalone(series, chart):
    t, s, body = chart
    leg = "".join(f'<rect x="{18+i*170}" y="{58}" width="16" height="4" rx="2" fill="{COLORS[i%5]}"/><text x="{40+i*170}" y="{63}" class="lg">{html.escape(n)}</text>' for i, (n, _) in enumerate(series))
    style = CSS.replace(".kc ", "").replace(".kc{", ":root{") + """
:root{--muted:#8e8e93;--fg:#f5f5f7}.bg{fill:#0f0f11}
@media (prefers-color-scheme:light){:root{--muted:#6e6e73;--fg:#1d1d1f}.bg{fill:#fafafb}}
svg text{fill:var(--muted);font:11px ui-monospace,SFMono-Regular,Menlo,monospace}
.tt{fill:var(--fg)!important;font:600 16px ui-sans-serif,system-ui,sans-serif!important}
.st{font:12.5px ui-sans-serif,system-ui,sans-serif!important}.lg{font:12.5px ui-sans-serif,system-ui,sans-serif!important}
.kc-line{animation:none;stroke-dashoffset:0}.kc-area,.kc-dot{animation:none;opacity:1}.kc-bar{animation:none;transform:none}
"""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H+80}" width="{W}" height="{H+80}"><style>{style}</style>'
            f'<rect class="bg" width="{W}" height="{H+80}" rx="16"/><text x="18" y="28" class="tt">{t}</text><text x="18" y="46" class="st">{s}</text>{leg}'
            f'<g transform="translate(0,74)">{"".join(body)}</g></svg>')

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--series", nargs="+", required=True, help='"Имя=файл.jsonl"')
    ap.add_argument("--svgdir"); ap.add_argument("--html")
    ap.add_argument("--css", help="CSS для сайта (CSP: без inline)"); ap.add_argument("--js", help="JS анимации")
    a = ap.parse_args()
    series = [(s.split("=", 1)[0], load(s.split("=", 1)[1])) for s in a.series]
    xs, charts = build(series)
    if a.svgdir:
        os.makedirs(a.svgdir, exist_ok=True)
        for name, ch in zip(["latency", "online", "memory", "connect"], charts):
            open(os.path.join(a.svgdir, f"{name}.svg"), "w").write(svg_standalone(series, ch))
    if a.html:
        open(a.html, "w").write(html_fragment(series, charts))
    if a.css:
        open(a.css, "w").write(CSS)
    if a.js:
        open(a.js, "w").write(JS)
    print("ok:", len(charts), "графика,", len(series), "серии")
