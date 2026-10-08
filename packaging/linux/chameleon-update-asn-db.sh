#!/bin/sh
# Обновляет офлайн-таблицу IP→ASN для vpn-observer (только российские диапазоны).
# Сначала берёт готовую RU-выборку с зеркала (iptoasn.com из РФ сильно замедлен),
# при неудаче — полные таблицы iptoasn.com напрямую.
set -eu
dir=/var/lib/chameleon-observer
mirror=${ASN_MIRROR_URL:-https://vpn.example.com/home-assets/ip2asn-ru.tsv.gz}
mkdir -p "$dir"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if curl -fsS --retry 2 --max-time 120 -o "$tmp/ru.tsv.gz" "$mirror" &&
   curl -fsS --max-time 30 -o "$tmp/ru.sha256" "$mirror.sha256" &&
   [ "$(sha256sum "$tmp/ru.tsv.gz" | cut -d' ' -f1)" = "$(tr -d ' \n' < "$tmp/ru.sha256")" ]; then
  gzip -dc "$tmp/ru.tsv.gz" | awk -F'\t' '$4=="RU" && $3!="0"' > "$tmp/ru.tsv"
else
  echo "mirror unavailable, falling back to iptoasn.com" >&2
  for f in ip2asn-v4.tsv.gz ip2asn-v6.tsv.gz; do
    curl -fsS --retry 2 --max-time 600 -o "$tmp/$f" "https://iptoasn.com/data/$f"
  done
  { gzip -dc "$tmp/ip2asn-v4.tsv.gz"; gzip -dc "$tmp/ip2asn-v6.tsv.gz"; } | awk -F'\t' '$4=="RU" && $3!="0"' > "$tmp/ru.tsv"
fi
n=$(wc -l < "$tmp/ru.tsv")
[ "$n" -gt 1000 ] || { echo "asn table too small: $n" >&2; exit 1; }
install -m 0644 "$tmp/ru.tsv" "$dir/.ip2asn-ru.tsv.new"
mv -f "$dir/.ip2asn-ru.tsv.new" "$dir/ip2asn-ru.tsv"
echo "asn table updated: $n ranges"
