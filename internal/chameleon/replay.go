package chameleon

import (
	"sync"
	"time"
)

// replayCache — защита от повторного воспроизведения рукопожатия.
// Зонд, записавший валидный client hello и проигравший его позже,
// получает тот же ответ, что и мусор: молчание. Без этого активный
// зондирующий мог бы отличить ноду от «мёртвого» сервиса.
//
// Записи разбиты по публичному ключу клиента, а в кэш попадают только
// рукопожатия, прошедшие белый список (см. ServerHandshake). Поэтому
// посторонний, знающий лишь публичный ключ ноды, не может заполнить кэш,
// а один клиентский ключ не может вытеснить остальных: при переполнении
// своей корзины отказ получает только он.
const (
	maxReplayEntries   = 1 << 17 // общий жёсткий предел
	maxReplayPerClient = 1024    // предел на один ключ клиента за replayTTL
)

type replayCache struct {
	mu    sync.Mutex
	total int
	seen  map[[32]byte]map[[16]byte]time.Time // ключ клиента → nonce → истечение
}

func newReplayCache() *replayCache {
	return &replayCache{seen: make(map[[32]byte]map[[16]byte]time.Time)}
}

// seenOrAdd — вариант без ключа клиента (общая корзина).
func (r *replayCache) seenOrAdd(nonce [16]byte, ttl time.Duration) bool {
	return r.seenOrAddFor([32]byte{}, nonce, ttl)
}

// seenOrAddFor возвращает true, если nonce уже встречался у этого клиента
// (и не истёк) либо корзина клиента/весь кэш переполнены (fail closed).
func (r *replayCache) seenOrAddFor(client [32]byte, nonce [16]byte, ttl time.Duration) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	bucket := r.seen[client]
	if exp, ok := bucket[nonce]; ok {
		if now.Before(exp) {
			return true
		}
		bucket[nonce] = now.Add(ttl)
		return false
	}
	if len(bucket) >= maxReplayPerClient {
		r.sweepBucketLocked(client, bucket, now)
		bucket = r.seen[client]
		if len(bucket) >= maxReplayPerClient {
			return true
		}
	}
	if r.total >= maxReplayEntries {
		for key, b := range r.seen {
			r.sweepBucketLocked(key, b, now)
		}
		bucket = r.seen[client]
		if r.total >= maxReplayEntries {
			return true
		}
	}
	if bucket == nil {
		bucket = make(map[[16]byte]time.Time)
		r.seen[client] = bucket
	}
	bucket[nonce] = now.Add(ttl)
	r.total++
	return false
}

func (r *replayCache) sweepBucketLocked(client [32]byte, bucket map[[16]byte]time.Time, now time.Time) {
	for nonce, exp := range bucket {
		if !now.Before(exp) {
			delete(bucket, nonce)
			r.total--
		}
	}
	if len(bucket) == 0 {
		delete(r.seen, client)
	}
}

func (r *replayCache) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}
