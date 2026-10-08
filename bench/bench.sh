#!/usr/bin/env bash
# Chameleon KS — бенчмарк с чекпоинтами.
#   ./bench/bench.sh                 интерактивное меню
#   ./bench/bench.sh speed|capacity|scale|all|report|status|reset [RUN_ID]
# Каждый шаг пишет результат в bench/results/<RUN_ID>/ и отметку в state/.
# Повторный запуск продолжает с первого невыполненного чекпоинта.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ENVF=${BENCH_ENV:-$HERE/bench.env}
[ -f "$ENVF" ] || { echo "нет $ENVF — скопируйте bench.env.example в bench.env (или запустите chameleon-setup)"; exit 1; }
# shellcheck disable=SC1090
. "$ENVF"
: "${NODE_IP:?NODE_IP}" "${NODE_SSH:=ssh root@$NODE_IP}" "${HUB_PORT:=51899}" "${PORTBASE:=0}"
: "${STRESS_BIN:=$HERE/../bin/ks-stress}" "${HUB_BIN_REMOTE:=/opt/chameleon/bench/ks-hub}" "${REMOTE_DIR:=/opt/chameleon/bench}"
: "${KEYS:=1000}" "${HOLD:=60}" "${RAMP:=20}" "${WARM:=15}" "${ACTIVE:=0.1}" "${PPS:=20}" "${SIZE:=1000}"
: "${SLA_ALIVE_PCT:=99}" "${SLA_P95_MS:=500}" "${SLA_LOSS_PCT:=2}"
: "${PROFILES:=1:512 2:1024}" "${CAP_LEVELS:=100 200 300 500 700 1000}" "${SCALE_LEVELS:=1 10 50 100 300 500}"
: "${SCALE_PROFILE:=2:1024}" "${SPEED_PATHS:=direct ks}" "${SPEED_URL:=}" "${SPEED_REPEAT:=3}" "${PING_HOST:=1.1.1.1}"

RUN=${2:-${RUN_ID:-$(date +%Y%m%d)}}
OUT=$HERE/results/$RUN; ST=$OUT/state; mkdir -p "$ST"; ln -sfn "$RUN" "$HERE/results/latest"
LOCALKEYS=$OUT/../.keys
log(){ echo "$(date +%T) $*" | tee -a "$OUT/bench.log"; }
done_(){ [ -f "$ST/$1.done" ]; }
mark(){ echo "$2" > "$ST/$1.done"; }
remote(){ $NODE_SSH "$@"; }

# --- подготовка: ключи виртуальных пользователей (локально и на ноде) -------
prepare(){
  done_ prepare && return 0
  log "prepare: $KEYS ключей, бинарник хаба $HUB_BIN_REMOTE"
  [ -x "$STRESS_BIN" ] || { log "нет $STRESS_BIN — make bench-tools"; return 1; }
  mkdir -p "$LOCALKEYS"
  if [ "$(ls "$LOCALKEYS" | wc -l)" -lt "$KEYS" ]; then
    for i in $(seq 11 $((KEYS+10))); do f=$LOCALKEYS/$i-b$i.key; [ -f "$f" ] || { head -c32 /dev/urandom | base64 > "$f"; chmod 600 "$f"; }; done
  fi
  remote "mkdir -p $REMOTE_DIR/allkeys $REMOTE_DIR/users && test -x $HUB_BIN_REMOTE" || { log "на ноде нет $HUB_BIN_REMOTE (scp bin/ks-hub)"; return 1; }
  tar -C "$LOCALKEYS" -cf - . | remote "tar -C $REMOTE_DIR/allkeys -xf - && chmod 600 $REMOTE_DIR/allkeys/*"
  mark prepare "{\"keys\":$KEYS}"
}

# hub_start <cores> <memMB> <users>: изолированный тестовый хаб (прод не трогаем)
hub_start(){
  local c=$1 m=$2 n=$3
  remote "cd $REMOTE_DIR && systemctl stop ks-bench-hub 2>/dev/null; systemctl reset-failed ks-bench-hub 2>/dev/null; rm -f users/*;
    ls allkeys | sort -n | head -$n | while read f; do cp -p allkeys/\$f users/; done;
    pb=''; [ $PORTBASE -gt 0 ] && pb='-portbase $PORTBASE';
    systemd-run -q --unit=ks-bench-hub -p CPUQuota=$((c*100))% -p MemoryMax=${m}M -p MemorySwapMax=0 \
      $HUB_BIN_REMOTE \$pb -keydir $REMOTE_DIR/users -tun ksb0 -innerself 10.97.0.2/16 -listen $HUB_PORT -maxusers 4000 -status ''" >/dev/null
  sleep 3
}
hub_stop(){ remote "systemctl stop ks-bench-hub 2>/dev/null; systemctl show -p MemoryPeak --value ks-bench-hub 2>/dev/null" ; }

# load <users> <active> → одна строка JSON от ks-stress
load(){
  local n=$1 a=$2 pb=""
  [ "$PORTBASE" -gt 0 ] && pb="-portbase $PORTBASE"
  "$STRESS_BIN" -hub "$NODE_IP:$HUB_PORT" $pb -keys "$LOCALKEYS" -levels "$n" -ramp "$RAMP" -warm "$WARM" \
    -hold "$HOLD" -active "$a" -pps "$PPS" -size "$SIZE" 2>>"$OUT/stress.err" | tail -1
}

sla_ok(){ # JSON → 0 если укладываемся в SLA
  python3 - "$1" "$SLA_ALIVE_PCT" "$SLA_P95_MS" "$SLA_LOSS_PCT" <<'PY'
import json,sys
d=json.loads(sys.argv[1]); a,p,l=map(float,sys.argv[2:])
ok = d["alive_users"]*100.0/max(1,d["users"])>=a and 0<=d["ka_rtt_ms_p95"]<=p and d["ka_loss_pct"]<=l
sys.exit(0 if ok else 1)
PY
}

# --- 1. скорость: сравнение путей ----------------------------------------
speed(){
  [ -n "$SPEED_URL" ] || { log "speed: задайте SPEED_URL (файл 50-100 МБ)"; return 1; }
  for p in $SPEED_PATHS; do
    done_ "speed-$p" && { log "speed $p: чекпоинт есть, пропуск"; continue; }
    local ifopt="" var="SPEED_IF_${p//-/_}"; [ -n "${!var:-}" ] && ifopt="--interface ${!var}"
    [ "$p" = ks ] && [ -z "$ifopt" ] && ifopt="--interface ks0"
    local mb=() rt
    for i in $(seq "$SPEED_REPEAT"); do
      mb+=("$(curl -s $ifopt -o /dev/null -w '%{speed_download}' --max-time 60 "$SPEED_URL" | awk '{printf "%.1f",$1*8/1e6}')")
    done
    rt=$(ping -c 20 -i 0.2 -q ${ifopt:+-I ${ifopt#--interface }} "$PING_HOST" 2>/dev/null | awk -F/ '/rtt|round-trip/{print $5}')
    local js; js=$(printf '{"path":"%s","mbit":[%s],"rtt_ms":%s}' "$p" "$(IFS=,; echo "${mb[*]}")" "${rt:-null}")
    echo "$js" >> "$OUT/speed.jsonl"; mark "speed-$p" "$js"; log "speed $p: $js"
  done
}

# --- 2. максимум пользователей при разных ресурсах ------------------------
capacity(){
  prepare || return 1
  for prof in $PROFILES; do
    local c=${prof%%:*} m=${prof##*:} best=0
    done_ "cap-$prof" && { log "capacity $prof: чекпоинт есть"; continue; }
    for n in $CAP_LEVELS; do
      [ "$n" -gt "$KEYS" ] && break
      if done_ "cap-$prof-$n"; then r=$(cat "$ST/cap-$prof-$n.done"); else
        log "capacity ${c}vCPU/${m}MB: $n пользователей"; hub_start "$c" "$m" "$n"
        r=$(load "$n" "$ACTIVE"); peak=$(hub_stop | tail -1)
        r=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);d.update(cores=$c,mem_mb=$m,mem_peak=sys.argv[2]);print(json.dumps(d))" "$r" "${peak:-0}")
        echo "$r" >> "$OUT/capacity.jsonl"; mark "cap-$prof-$n" "$r"
      fi
      if sla_ok "$r"; then best=$n; else log "capacity $prof: SLA нарушен на $n"; break; fi
    done
    mark "cap-$prof" "{\"cores\":$c,\"mem_mb\":$m,\"max_users\":$best}"; log "capacity $prof: максимум $best"
  done
}

# --- 3. скорость при разном числе пользователей ---------------------------
scale(){
  prepare || return 1
  local c=${SCALE_PROFILE%%:*} m=${SCALE_PROFILE##*:}
  for n in $SCALE_LEVELS; do
    done_ "scale-$n" && { log "scale $n: чекпоинт есть"; continue; }
    log "scale: $n пользователей, все активны"; hub_start "$c" "$m" "$n"
    r=$(load "$n" 1.0); hub_stop >/dev/null
    r=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);d['per_user_mbit']=round(d['down_mbit']/max(1,d['users']),3);print(json.dumps(d))" "$r")
    echo "$r" >> "$OUT/scale.jsonl"; mark "scale-$n" "$r"; log "scale $n: $r"
  done
}

report(){
  python3 - "$OUT" <<'PY' | tee "$OUT/REPORT.md"
import json,os,sys
o=sys.argv[1]
def rows(f):
    p=os.path.join(o,f); return [json.loads(l) for l in open(p)] if os.path.exists(p) else []
print("# Отчёт бенчмарка\n")
s=rows("speed.jsonl")
if s:
    print("## 1. Скорость: сравнение путей\n\n| Путь | Мбит/с (медиана) | Все замеры | RTT, мс |\n|---|---|---|---|")
    for r in s:
        m=sorted(r["mbit"]); print(f"| {r['path']} | {m[len(m)//2]} | {', '.join(map(str,r['mbit']))} | {r['rtt_ms']} |")
c=rows("capacity.jsonl")
if c:
    print("\n## 2. Пользователи и ресурсы сервера\n\n| vCPU | RAM, МБ | Польз. | Живых | KA p50/p95, мс | Потери, % | Пик RAM |\n|---|---|---|---|---|---|---|")
    for r in c:
        print(f"| {r['cores']} | {r['mem_mb']} | {r['users']} | {r['alive_users']} | {r['ka_rtt_ms_p50']}/{r['ka_rtt_ms_p95']} | {max(0,r['ka_loss_pct'])} | {r.get('mem_peak','')} |")
s=rows("scale.jsonl")
if s:
    print("\n## 3. Скорость при разном числе пользователей\n\n| Польз. | Суммарно ↓ Мбит/с | На пользователя | RTT p50/p95, мс | Потери, % |\n|---|---|---|---|---|")
    for r in s:
        print(f"| {r['users']} | {r['down_mbit']} | {r['per_user_mbit']} | {r['data_rtt_ms_p50']}/{r['data_rtt_ms_p95']} | {max(0,r['data_loss_pct'])} |")
PY
}

charts(){
  python3 - "$OUT" "$HERE/charts.py" <<'PY2'
import json,os,subprocess,sys,collections
o,ch=sys.argv[1],sys.argv[2]; d=os.path.join(o,"charts"); os.makedirs(d,exist_ok=True)
groups=collections.OrderedDict()
for f,key in (("capacity.jsonl",lambda r:f"{r['cores']} vCPU / {r['mem_mb']} МБ"),("scale.jsonl",lambda r:"все активны")):
    p=os.path.join(o,f)
    if os.path.exists(p):
        for l in open(p):
            r=json.loads(l); groups.setdefault(f[:-6]+": "+key(r),[]).append(r)
if not groups: sys.exit("нет данных: сначала capacity или scale")
args=[]
for i,(k,rows) in enumerate(groups.items()):
    fn=os.path.join(d,f"s{i}.jsonl"); open(fn,"w").write("".join(json.dumps(r)+"\n" for r in rows)); args.append(f"{k}={fn}")
subprocess.check_call(["python3",ch,"--series",*args,"--svgdir",d,"--html",os.path.join(d,"charts.html")])
print("графики:",d)
PY2
}

status(){ echo "RUN $RUN ($OUT)"; ls "$ST" 2>/dev/null | sed 's/\.done$//' | sed 's/^/  [x] /'; }

menu(){
  while :; do
    echo; echo "Chameleon KS benchmark — прогон $RUN"
    echo " 1) Скорость: сравнение путей (direct / KS / …)"
    echo " 2) Максимум пользователей при разных ресурсах сервера"
    echo " 3) Скорость при разном числе пользователей"
    echo " 4) Всё по порядку (1→2→3)"
    echo " 5) Отчёт (results/$RUN/REPORT.md) и графики"
    echo " 6) Состояние чекпоинтов"
    echo " 7) Сбросить чекпоинты прогона"
    echo " 0) Выход"
    read -rp "> " a
    case $a in 1) speed;; 2) capacity;; 3) scale;; 4) speed; capacity; scale; report;; 5) report; charts;; 6) status;;
      7) rm -rf "$ST" && mkdir -p "$ST" && echo сброшено;; 0) exit 0;; esac
  done
}

case ${1:-menu} in
  speed) speed;; capacity) capacity;; scale) scale;; all) speed; capacity; scale; report; charts;;
  report) report;; charts) charts;; status) status;; reset) rm -rf "$ST"; echo "сброшено: $RUN";; menu) menu;;
  *) echo "usage: $0 [speed|capacity|scale|all|report|charts|status|reset] [RUN_ID]"; exit 2;;
esac
