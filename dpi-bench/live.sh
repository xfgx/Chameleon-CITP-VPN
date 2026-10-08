#!/usr/bin/env bash
# live.sh — прогон DPI-бенчмарка по НАСТОЯЩЕМУ пути РФ → зарубеж (через реальные ТСПУ на пути).
# Клиент — машина в РФ, сервер — за рубежом. Запись pcap на ОБЕИХ сторонах: compare.py
# показывает, что потерялось/подменилось/внедрилось по дороге (дропы, RST-инъекции, «заморозки»).
#
#   RU_RUN="ssh root@ru-host"  FX_RUN="ssh root@foreign-host" \
#   RU_IP=… FX_IP=… ./live.sh prepare|start|status|collect|stop
#
# RU_RUN/FX_RUN — команда, которой передаётся строка shell; на FX нужен root (ip/wg/nft/tcpdump).
# FX_COPY — команда для копирования (stdin → распаковка); по умолчанию = FX_RUN.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/.." && pwd)
OUT=${OUT:-$HERE/results/live-$(date +%Y%m%d)}; K=$OUT/keys; mkdir -p "$K"
RD=${RU_DIR:-/root/dpilive}; FD=${FX_DIR:-/tmp/dpilive}
: "${RU_RUN:?}" "${FX_RUN:?}" "${RU_IP:?}" "${FX_IP:?}"; FX_COPY=${FX_COPY:-$FX_RUN}

keys() {
  [ -f $K/ks.key ] || $ROOT/bin/ks-vpn -genkey -keyfile $K/ks.key >/dev/null
  [ -f $K/wg.s ] || { wg genkey >$K/wg.s; wg genkey >$K/wg.c; wg pubkey <$K/wg.s >$K/wg.s.pub; wg pubkey <$K/wg.c >$K/wg.c.pub; }
  [ -f $K/tls.crt ] || openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=bench.example.com \
      -keyout $K/tls.key -out $K/tls.crt >/dev/null 2>&1
  if [ ! -f $K/ovpn-ca.crt ]; then ( cd $K
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=ovpn-ca -keyout ovpn-ca.key -out ovpn-ca.crt
    for r in server client; do
      openssl req -newkey rsa:2048 -nodes -subj /CN=$r -keyout ovpn-$r.key -out ovpn-$r.csr
      printf 'extendedKeyUsage=%s\n' $( [ $r = server ] && echo serverAuth || echo clientAuth ) >ovpn-$r.ext
      openssl x509 -req -in ovpn-$r.csr -CA ovpn-ca.crt -CAkey ovpn-ca.key -CAcreateserial -days 30 -extfile ovpn-$r.ext -out ovpn-$r.crt
    done ) >/dev/null 2>&1; fi
  if [ ! -f $K/citp.node ]; then
    $ROOT/bin/dpi-citp -genkey >$K/citp.node; $ROOT/bin/dpi-citp -genkey >$K/citp.dev
    cut -d' ' -f1 $K/citp.node >$K/citp-server.key; cut -d' ' -f2 $K/citp.dev >$K/citp.allow
  fi
  echo '{"version":1,"tenant_id":"bench","service_id":"citp-core","deny_private_ranges":false,"deny_link_local":true,"deny_loopback":false,"max_streams_per_conn":256,"max_stream_lifetime_s":86400,"require_dns_binding":false}' >$K/citp-policy.json
}
prepare() {
  keys
  local t=$OUT/dpilive.tgz
  tar czf $t -C $ROOT bin/ks-vpn bin/cham-server bin/dpi-citp -C $HERE workload.py live-node.sh -C $OUT keys \
     --transform 's,^bin/,,'
  $FX_COPY "rm -rf $FD; mkdir -p $FD && tar xzf - -C $FD && chmod 755 $FD && ls $FD" <$t
  $RU_RUN "rm -rf $RD; mkdir -p $RD && tar xzf - -C $RD && ls $RD" <$t
  $FX_RUN "command -v wg openvpn tcpdump >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q wireguard-tools openvpn tcpdump >/dev/null 2>&1; command -v wg openvpn tcpdump"
  $RU_RUN "command -v wg openvpn tcpdump >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q wireguard-tools openvpn tcpdump >/dev/null 2>&1; systemctl disable --now openvpn >/dev/null 2>&1; command -v wg openvpn tcpdump"
}
start() {
  $FX_RUN "setsid nohup bash $FD/live-node.sh server $FD $RU_IP >$FD/server.out 2>&1 </dev/null & sleep 4; cat $FD/server.out"
  $RU_RUN "setsid nohup env PROTOS='${PROTOS:-ks citp citp-cbr wg ovpn tls}' IDLE=${IDLE:-40} BULK=${BULK:-20} bash $RD/live-node.sh client $RD $FX_IP >$RD/client.out 2>&1 </dev/null & echo started"
}
status() { $RU_RUN "cat $RD/cap/summary.txt 2>/dev/null; tail -n 2 $RD/client.out"; }
stop() { $RU_RUN "bash $RD/live-node.sh stop $RD"; $FX_RUN "bash $FD/live-node.sh stop $FD"; }
collect() {
  mkdir -p $OUT/cap
  $RU_RUN "tar czf - -C $RD cap" | tar xzf - -C $OUT
  $FX_RUN "cat $FD/server.pcap" >$OUT/server.pcap
  DPI_C=$RU_IP DPI_S=$FX_IP DPI_LIVE=1 python3 $HERE/analyze.py $OUT
  DPI_C=$RU_IP DPI_S=$FX_IP python3 $HERE/compare.py $OUT
}
case ${1:-} in prepare|start|status|stop|collect) $1 ;; *) sed -n 2,11p "$0" ;; esac
