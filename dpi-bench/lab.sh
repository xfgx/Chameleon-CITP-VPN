#!/usr/bin/env bash
# lab.sh — стенд DPI-бенчмарка: три netns (клиент | «ТСПУ» | сервер) на одной машине.
#
#   клиент dpc 198.18.1.2 ── dpm (цензор: tcpdump + nftables + netem 40 мс) ── dps 198.18.2.1 сервер
#
# Протоколы: ks citp citp-cbr wg ovpn tls (tls = обычный HTTPS без туннеля, эталон «нормального» трафика).
# Команды:
#   lab.sh up | down                    — поднять/снести стенд
#   lab.sh capture <proto>              — полный прогон нагрузки с записью pcap
#   lab.sh sessions <proto> [N]         — N коротких сеансов (стабильность первых 5 пакетов)
#   lab.sh probe <proto>                — активное зондирование сервера
#   lab.sh policy <proto> <policy>      — нагрузка под политикой цензора (см. POLICIES)
#   lab.sh all                          — всё по всем протоколам (с чекпоинтами), затем analyze.py
# Результаты: $OUT (по умолчанию dpi-bench/results/<дата>), чекпоинты — $OUT/state.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
BIN=${BIN:-$ROOT/bin}
OUT=${OUT:-$HERE/results/$(date +%Y%m%d)}
PROTOS=${PROTOS:-"ks citp citp-cbr wg ovpn tls"}
# доп. флаги (beta): KS_EXTRA="-pad 200" CITP_EXTRA="-tlsrec" CITP_PORT=853 (порт < 1000; 443 занят эталонным HTTPS)
KS_EXTRA=${KS_EXTRA:-}; CITP_EXTRA=${CITP_EXTRA:-}; CITP_PORT=${CITP_PORT:-9443}; export DPI_CITP_PORT=$CITP_PORT
POLICIES=${POLICIES:-"none udp-block ports-lt1000 freeze16k udp-ban"}
K=$OUT/keys
C=198.18.1.2 M1=198.18.1.1 M2=198.18.2.254 S=198.18.2.1
mkdir -p "$OUT" "$K"
nc() { ip netns exec dpc "$@"; }
nm() { ip netns exec dpm "$@"; }
ns() { ip netns exec dps "$@"; }
log() { echo "[$(date +%T)] $*" | tee -a "$OUT/lab.log"; }

up() {
  down 2>/dev/null
  for n in dpc dpm dps; do ip netns add $n; ip -n $n link set lo up; done
  ip link add c0 netns dpc type veth peer name m1 netns dpm
  ip link add s0 netns dps type veth peer name m2 netns dpm
  ip -n dpc addr add $C/24 dev c0; ip -n dpc link set c0 up; ip -n dpc route add default via $M1
  ip -n dps addr add $S/24 dev s0; ip -n dps link set s0 up; ip -n dps route add default via $M2
  ip -n dpm addr add $M1/24 dev m1; ip -n dpm addr add $M2/24 dev m2
  ip -n dpm link set m1 up; ip -n dpm link set m2 up
  nm sysctl -qw net.ipv4.ip_forward=1 net.netfilter.nf_conntrack_acct=1 2>/dev/null || nm sysctl -qw net.ipv4.ip_forward=1
  for d in m1 m2; do nm tc qdisc add dev $d root netem delay 40ms 4ms limit 10000; done
  for d in c0 s0 m1 m2; do ip netns exec $( [ $d = c0 ] && echo dpc || { [ $d = s0 ] && echo dps || echo dpm; } ) ethtool -K $d tso off gso off gro off >/dev/null 2>&1; done
  [ -f $K/tls.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=bench.example.ru \
      -keyout $K/tls.key -out $K/tls.crt >/dev/null 2>&1
  ns setsid python3 $HERE/workload.py serve --port 8080 >/dev/null 2>&1 < /dev/null &
  ns setsid python3 $HERE/workload.py serve --port 443 --tls $K/tls.crt $K/tls.key >/dev/null 2>&1 < /dev/null &
  sleep 1; log "стенд поднят (RTT ~80 мс)"
}
down() {
  local n
  for n in dpc dps dpm; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; done
  sleep 0.5
  for n in dpc dps dpm; do ip netns del $n 2>/dev/null; done
  return 0
}

# --- протоколы: start_<p> поднимает туннель и печатает URL цели ----------------
start_ks() {
  [ -f $K/ks.key ] || $BIN/ks-vpn -genkey -keyfile $K/ks.key >/dev/null
  ns setsid $BIN/ks-vpn $KS_EXTRA -keyfile $K/ks.key -tun ksn -tunip 10.77.0.2/24 -listen 51830 -peerport 40001 \
     -outdir n2c -indir c2n >$OUT/ks-node.log 2>&1 </dev/null &
  sleep 0.5
  nc setsid $BIN/ks-vpn $KS_EXTRA -keyfile $K/ks.key -tun ksc -tunip 10.77.0.1/24 -peerhost $S -peerport 51830 \
     -listen 40001 >$OUT/ks-client.log 2>&1 </dev/null &
  sleep 2; echo http://10.77.0.2:8080
}
start_wg() {
  [ -f $K/wg.s ] || { wg genkey >$K/wg.s; wg genkey >$K/wg.c; }
  wg pubkey <$K/wg.s >$K/wg.s.pub; wg pubkey <$K/wg.c >$K/wg.c.pub
  ns ip link add wg0 type wireguard; ns wg set wg0 private-key $K/wg.s listen-port 51820 \
     peer $(cat $K/wg.c.pub) allowed-ips 10.78.0.1/32
  ns ip addr add 10.78.0.2/24 dev wg0; ns ip link set wg0 up
  nc ip link add wg0 type wireguard; nc wg set wg0 private-key $K/wg.c \
     peer $(cat $K/wg.s.pub) endpoint $S:51820 allowed-ips 10.78.0.0/24 persistent-keepalive 25
  nc ip addr add 10.78.0.1/24 dev wg0; nc ip link set wg0 up
  echo http://10.78.0.2:8080
}
start_ovpn() { # обычный TLS-режим OpenVPN (сертификаты, без tls-crypt) — как в большинстве инсталляций
  if [ ! -f $K/ovpn-ca.crt ]; then
    ( cd $K && openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=ovpn-ca -keyout ovpn-ca.key -out ovpn-ca.crt
      for r in server client; do
        openssl req -newkey rsa:2048 -nodes -subj /CN=$r -keyout ovpn-$r.key -out ovpn-$r.csr
        printf 'extendedKeyUsage=%s\n' $( [ $r = server ] && echo serverAuth || echo clientAuth ) >ovpn-$r.ext
        openssl x509 -req -in ovpn-$r.csr -CA ovpn-ca.crt -CAkey ovpn-ca.key -CAcreateserial -days 30 -extfile ovpn-$r.ext -out ovpn-$r.crt
      done ) >/dev/null 2>&1
  fi
  local o="--dev tun --proto udp --ca $K/ovpn-ca.crt --dh none --keepalive 10 60 --verb 1 --data-ciphers AES-256-GCM"
  ns setsid openvpn $o --tls-server --cert $K/ovpn-server.crt --key $K/ovpn-server.key --port 1194 \
     --ifconfig 10.79.0.2 10.79.0.1 >$OUT/ovpn-s.log 2>&1 </dev/null &
  nc setsid openvpn $o --tls-client --cert $K/ovpn-client.crt --key $K/ovpn-client.key --remote $S 1194 --nobind \
     --ifconfig 10.79.0.1 10.79.0.2 >$OUT/ovpn-c.log 2>&1 </dev/null &
  for i in $(seq 30); do nc ping -c1 -W1 10.79.0.2 >/dev/null 2>&1 && break; sleep 0.5; done
  echo http://10.79.0.2:8080
}
_citp() { # $1 = доп. флаги сервера/клиента (cbr)
  if [ ! -f $K/citp.node ]; then
    $BIN/dpi-citp -genkey >$K/citp.node; $BIN/dpi-citp -genkey >$K/citp.dev
    cut -d' ' -f1 $K/citp.node >$K/citp-server.key; cut -d' ' -f2 $K/citp.dev >$K/citp.allow
  fi
  ns setsid $BIN/cham-server -keyfile $K/citp-server.key -listen 0.0.0.0:$CITP_PORT -allowfile $K/citp.allow $1 \
     >$OUT/citp-s.log 2>&1 </dev/null &
  sleep 0.7
  nc setsid $BIN/dpi-citp $CITP_EXTRA -node $S:$CITP_PORT -pub $(cut -d' ' -f2 $K/citp.node) -key $(cut -d' ' -f1 $K/citp.dev) \
     -listen 127.0.0.1:18080 -target $S:8080 $1 >$OUT/citp-c.log 2>&1 </dev/null &
  sleep 1.5; echo http://127.0.0.1:18080
}
start_citp() { _citp ""; }
start_citp-cbr() { _citp "-cbr 40ms"; }
start_tls() { echo https://$S:443; }
stop_all() {
  local n
  for n in dpc dps; do
    local pids; pids=$(ip netns pids $n | paste -sd,)
    [ -n "$pids" ] && ps -o pid=,comm= -p "$pids" | awk '$2~/^(ks-vpn|openvpn|cham-server|dpi-citp)$/{print $1}' | xargs -r kill 2>/dev/null
    ip -n $n link del wg0 2>/dev/null
  done
  sleep 1
}
server_port() { case $1 in ks) echo udp 51830;; wg) echo udp 51820;; ovpn) echo udp 1194;; citp*) echo tcp $CITP_PORT;; tls) echo tcp 443;; esac; }

cap_start() { nm setsid tcpdump -i m1 -s 256 -B 32768 -w "$1" host $C >"$1.log" 2>&1 </dev/null & sleep 0.7; }
cap_stop() { nm pkill -INT -x tcpdump 2>/dev/null; sleep 1; }

capture() {
  local p=$1 url; mkdir -p $OUT/cap
  cap_start $OUT/cap/$p.pcap
  url=$(start_$p)
  nc python3 $HERE/workload.py run --url "$url" --out $OUT/cap/$p.phases.json --idle ${IDLE:-40} --bulk-mb ${BULK:-20} \
     >$OUT/cap/$p.result.json 2>>$OUT/lab.log
  cap_stop; stop_all
  log "capture $p: $(cat $OUT/cap/$p.result.json)"
}
sessions() {
  local p=$1 n=${2:-5} url; mkdir -p $OUT/sess
  for i in $(seq $n); do
    cap_start $OUT/sess/$p.$i.pcap
    url=$(start_$p)
    nc python3 $HERE/workload.py run --url "$url" --phases chat --short --timeout 6 >/dev/null 2>&1
    cap_stop; stop_all
  done
  log "sessions $p: $n"
}
probe() {
  local p=$1; mkdir -p $OUT/probe
  cap_start $OUT/probe/$p.real.pcap
  url=$(start_$p)
  nc python3 $HERE/workload.py run --url "$url" --phases chat --short --timeout 6 >/dev/null 2>&1
  cap_stop
  set -- $(server_port $p)
  nc python3 $HERE/probe.py --proto $1 --host $S --port $2 --replay $OUT/probe/$p.real.pcap --client $C \
     --out $OUT/probe/$p.json ${PROBE_ARGS:-} 2>>$OUT/lab.log
  stop_all
  log "probe $p: $(python3 -c "import json;d=json.load(open('$OUT/probe/$p.json'));print(d['summary'])")"
}

# --- политики цензора (nftables в dpm) ---------------------------------------
policy_set() {
  nm nft delete table inet cz 2>/dev/null
  nm nft add table inet cz
  nm nft add chain inet cz flt '{ type filter hook forward priority 0; policy accept; }'
  case $1 in
    none) ;;
    udp-block)      # «UDP в полном блоке» (NTC 2026-01-14): живы только TCP и DNS
      nm nft add rule inet cz flt udp dport != 53 udp sport != 53 drop ;;
    ports-lt1000)   # «работают только порты <1000, кроме 443» (NTC 2026-02-20): режем dport>=1000 (кроме 443)
      nm nft add rule inet cz flt ip saddr $C tcp dport '>=' 1000 drop
      nm nft add rule inet cz flt ip saddr $C udp dport '>=' 1000 drop ;;
    freeze16k)      # «заморозка после ~16 КБ» (Habr 2026-07-10): поток к зарубежному хостингу встаёт после 16 КБ
      nm nft add rule inet cz flt ip daddr $S ct original bytes '>' 16384 drop
      nm nft add rule inet cz flt ip saddr $S ct reply bytes '>' 16384 drop ;;
    udp-ban)        # «бан IP на 10 мин после любого UDP» (NTC 2025-06-12)
      nm nft add set inet cz ban '{ type ipv4_addr; timeout 10m; }'
      nm nft add rule inet cz flt ip daddr $S meta l4proto udp udp dport != 53 add @ban '{ ip daddr }'
      nm nft add rule inet cz flt ip daddr @ban drop
      nm nft add rule inet cz flt ip saddr @ban drop ;;
  esac
}
policy() {
  local p=$1 pol=$2 url; mkdir -p $OUT/policy
  nm conntrack -F >/dev/null 2>&1
  policy_set $pol
  url=$(start_$p)
  if ! nc python3 -c "import ssl,urllib.request as u;u.urlopen('$url/n/1024',timeout=10,context=ssl._create_unverified_context()).read()" 2>/dev/null; then
    echo '{"ok":0,"fail":1,"bytes":0,"unreachable":true}' >$OUT/policy/$p.$pol.json
  else
    timeout 150 ip netns exec dpc python3 $HERE/workload.py run --url "$url" --short --idle 3 --bulk-mb 3 --timeout 6 \
       >$OUT/policy/$p.$pol.json 2>/dev/null || echo '{"ok":0,"fail":99,"bytes":0,"timeout":true}' >$OUT/policy/$p.$pol.json
  fi
  stop_all; policy_set none
  log "policy $p/$pol: $(cat $OUT/policy/$p.$pol.json)"
}

step() { # чекпоинт: step <имя> <команда...>
  local s=$1; shift
  grep -qxF "$s" $OUT/state 2>/dev/null && return 0
  "$@" && echo "$s" >>$OUT/state
}
all() {
  up
  for p in $PROTOS; do step "cap:$p" capture $p; done
  for p in $PROTOS; do step "sess:$p" sessions $p ${SESSIONS:-5}; done
  for p in $PROTOS; do step "probe:$p" probe $p; done
  for p in $PROTOS; do for pol in $POLICIES; do step "pol:$p:$pol" policy $p $pol; done; done
  down
  python3 $HERE/analyze.py "$OUT" && log "отчёт: $OUT/report.md"
}

cmd=${1:-help}; shift || true
case $cmd in
  up|down|capture|sessions|probe|policy|all) $cmd "$@" ;;
  *) sed -n 2,15p "$0" ;;
esac
