package chaossync

import "math/rand/v2"

// PadIP — дописать к маленькому IP-пакету случайное число нулевых байт
// (beta, 2026-10-08). Против детектора «ACK-эхо»: 97% датаграмм вверх были
// одной длины (TCP ACK внутри туннеля). Получатель ничего не меняет: ядро
// Linux обрезает IPv4/IPv6-пакет по длине из заголовка (ip_rcv_core /
// ip6_rcv_core: pskb_trim_rcsum), хвост просто отбрасывается.
//
// Пакеты длиннее limit не трогаются; добавка — равномерно 0..max, но не
// дальше limit. pkt дописывается на месте, если хватает ёмкости.
func PadIP(pkt []byte, max, limit int) []byte {
	if max <= 0 || len(pkt) < 20 || len(pkt) >= limit {
		return pkt
	}
	if v := pkt[0] >> 4; v != 4 && v != 6 {
		return pkt
	}
	n := rand.IntN(max + 1)
	if len(pkt)+n > limit {
		n = limit - len(pkt)
	}
	for i := 0; i < n; i++ {
		pkt = append(pkt, 0)
	}
	return pkt
}
