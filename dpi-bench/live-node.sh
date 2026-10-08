#!/usr/bin/env bash
# live-node.sh — «живой» прогон через настоящую сеть РФ → зарубеж (запускается live.sh).
#   server <dir> <client_ip>   — на зарубежной ноде: все серверы сразу + tcpdump
#   client <dir> <server_ip>   — на RU-ноде: по очереди каждый протокол + tcpdump + workload
#   stop <dir>                 — остановить всё, что подняли
# Порты: KS udp/56001, WireGuard udp/56002, OpenVPN udp/56003, CITP tcp/9443, CITP+CBR tcp/9444, HTTPS tcp/443.
# Имена интерфейсов и подсети отдельные (ksb0/wgb0/ovb0, 10.177-179.0.0/24) — прод-туннели не трогаются.
set -uo pipefail
D=$2; cd "$D" || exit 1
W="python3 $D/workload.py"
case $1 in
server)
  CL=$3; IF=$(ip route get "$CL" | grep -o 'dev [^ ]*' | cut -d' ' -f2)
  nft delete table inet dpib 2>/dev/null; nft add table inet dpib
  nft add chain inet dpib in '{ type filter hook input priority 0; policy accept; }'
  nft add rule inet dpib in iifname "$IF" tcp dport 18080 drop
  setsid tcpdump -i "$IF" -s 256 -B 32768 -w $D/server.pcap host "$CL" and \( udp portrange 56001-56003 or tcp port 9443 or tcp port 9444 or tcp port 443 \) >$D/tcpdump.log 2>&1 </dev/null &
  setsid $W serve --port 18080 >/dev/null 2>&1 </dev/null &
  setsid $W serve --port 443 --tls $D/keys/tls.crt $D/keys/tls.key >/dev/null 2>&1 </dev/null &
  setsid $D/ks-vpn -keyfile $D/keys/ks.key -tun ksb0 -tunip 10.177.0.2/24 -listen 56001 -peerport 56001 \
     -outdir n2c -indir c2n >$D/ks.log 2>&1 </dev/null &
  ip link add wgb0 type wireguard; wg set wgb0 private-key $D/keys/wg.s listen-port 56002 \
     peer "$(cat $D/keys/wg.c.pub)" allowed-ips 10.178.0.1/32
  ip addr add 10.178.0.2/24 dev wgb0; ip link set wgb0 up
  O="--dev-type tun --proto udp --ca $D/keys/ovpn-ca.crt --dh none --keepalive 10 60 --verb 1 --data-ciphers AES-256-GCM"
  setsid openvpn $O --dev ovb0 --tls-server --cert $D/keys/ovpn-server.crt --key $D/keys/ovpn-server.key --port 56003 \
     --ifconfig 10.179.0.2 10.179.0.1 >$D/ovpn.log 2>&1 </dev/null &
  for x in "9443 " "9444 -cbr 40ms"; do set -- $x
    setsid $D/cham-server -keyfile $D/keys/citp-server.key -listen 0.0.0.0:$1 -allowfile $D/keys/citp.allow \
       -policy $D/keys/citp-policy.json ${2:-} ${3:-} >$D/citp-$1.log 2>&1 </dev/null &
  done
  sleep 2; echo "server up on $IF"
  ;;
client)
  SV=$3; IF=$(ip route get "$SV" | grep -o 'dev [^ ]*' | cut -d' ' -f2)
  mkdir -p $D/cap
  for p in ${PROTOS:-ks citp citp-cbr wg ovpn tls}; do
    case $p in ks) f="udp port 56001";; wg) f="udp port 56002";; ovpn) f="udp port 56003";; citp) f="tcp port 9443";;
      citp-cbr) f="tcp port 9444";; tls) f="tcp port 443";; esac
    setsid tcpdump -i "$IF" -s 256 -B 32768 -w $D/cap/$p.pcap host "$SV" and $f >$D/cap/$p.tcpdump.log 2>&1 </dev/null &
    sleep 1
    case $p in
      ks) setsid $D/ks-vpn -keyfile $D/keys/ks.key -tun ksb0 -tunip 10.177.0.1/24 -peerhost $SV -peerport 56001 \
             -listen 56001 >$D/cap/ks.log 2>&1 </dev/null & sleep 3; url=http://10.177.0.2:18080 ;;
      wg) ip link add wgb0 type wireguard; wg set wgb0 private-key $D/keys/wg.c peer "$(cat $D/keys/wg.s.pub)" \
             endpoint $SV:56002 allowed-ips 10.178.0.2/32 persistent-keepalive 25
          ip addr add 10.178.0.1/24 dev wgb0; ip link set wgb0 up; url=http://10.178.0.2:18080 ;;
      ovpn) setsid openvpn --dev-type tun --dev ovb0 --proto udp --ca $D/keys/ovpn-ca.crt --keepalive 10 60 --verb 1 \
             --data-ciphers AES-256-GCM --tls-client --cert $D/keys/ovpn-client.crt --key $D/keys/ovpn-client.key \
             --remote $SV 56003 --nobind --ifconfig 10.179.0.1 10.179.0.2 --route-nopull >$D/cap/ovpn.log 2>&1 </dev/null &
          for i in $(seq 40); do ping -c1 -W1 10.179.0.2 >/dev/null 2>&1 && break; sleep 0.5; done; url=http://10.179.0.2:18080 ;;
      citp|citp-cbr) port=9443; extra=""; [ $p = citp-cbr ] && { port=9444; extra="-cbr 40ms"; }
          setsid $D/dpi-citp -node $SV:$port -pub "$(cut -d' ' -f2 $D/keys/citp.node)" -key "$(cut -d' ' -f1 $D/keys/citp.dev)" \
             -listen 127.0.0.1:18081 -target 127.0.0.1:18080 $extra >$D/cap/$p.log 2>&1 </dev/null &
          sleep 3; url=http://127.0.0.1:18081 ;;
      tls) url=https://$SV:443 ;;
    esac
    timeout 400 $W run --url $url --out $D/cap/$p.phases.json --idle ${IDLE:-40} --bulk-mb ${BULK:-20} \
       >$D/cap/$p.result.json 2>$D/cap/$p.err || echo '{"ok":0,"fail":99,"timeout":true}' >$D/cap/$p.result.json
    pkill -INT -f "tcpdump -i $IF -s 256 -B 32768 -w $D/cap/$p.pcap"; sleep 1
    pkill -f "$D/ks-vpn" ; pkill -f "$D/dpi-citp"; pkill -f "openvpn --dev-type tun --dev ovb0"; ip link del wgb0 2>/dev/null
    sleep 2; echo "$p $(cat $D/cap/$p.result.json)" | tee -a $D/cap/summary.txt
  done
  echo DONE >>$D/cap/summary.txt
  ;;
stop)
  pkill -INT -f "tcpdump -i .* -w $D/" ; pkill -f "$D/ks-vpn"; pkill -f "$D/cham-server"; pkill -f "$D/dpi-citp"
  pkill -f "$D/workload.py"; pkill -f "openvpn --dev-type tun --dev ovb0"; ip link del wgb0 2>/dev/null
  nft delete table inet dpib 2>/dev/null; echo stopped
  ;;
esac
