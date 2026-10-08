package chaossync

// SetWindow — уменьшить окно ожидаемых позиций приёмника (нагрузочный
// генератор cmd/ks-stress держит тысячи виртуальных клиентов и экономит
// CPU/память). Значение ограничено [64, ksWindow]; на провод не влияет.
func (r *Receiver) SetWindow(w uint64) {
	if w < 64 {
		w = 64
	}
	if w > ksWindow {
		w = ksWindow
	}
	r.window = w
}
