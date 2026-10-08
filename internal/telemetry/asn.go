package telemetry

import (
	"bufio"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ASNDB — офлайн-сопоставление IP → ASN/оператор по файлу формата iptoasn.com
// (range_start, range_end, AS_number, country_code, AS_description через TAB).
// Файл обновляет отдельный таймер; при отсутствии файла Lookup возвращает 0.
type ASNDB struct {
	mu     sync.RWMutex
	path   string
	mod    time.Time
	size   int64
	ranges []asnRange
}

type asnRange struct {
	start, end netip.Addr
	asn        uint32
	org        string
}

func OpenASN(path string) *ASNDB {
	d := &ASNDB{path: path}
	_ = d.Reload()
	return d
}

func (d *ASNDB) Len() int {
	if d == nil {
		return 0
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.ranges)
}

// Reload перечитывает файл, если он изменился.
func (d *ASNDB) Reload() error {
	if d == nil || d.path == "" {
		return nil
	}
	st, err := os.Stat(d.path)
	if err != nil {
		return err
	}
	d.mu.RLock()
	same := st.ModTime().Equal(d.mod) && st.Size() == d.size
	d.mu.RUnlock()
	if same {
		return nil
	}
	f, err := os.Open(d.path)
	if err != nil {
		return err
	}
	defer f.Close()
	ranges, err := parseASN(f)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.ranges, d.mod, d.size = ranges, st.ModTime(), st.Size()
	d.mu.Unlock()
	return nil
}

func parseASN(f *os.File) ([]asnRange, error) {
	orgs := map[string]string{}
	var out []asnRange
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) < 5 {
			continue
		}
		start, e1 := netip.ParseAddr(parts[0])
		end, e2 := netip.ParseAddr(parts[1])
		asn, e3 := strconv.ParseUint(parts[2], 10, 32)
		if e1 != nil || e2 != nil || e3 != nil || asn == 0 || start.Is4() != end.Is4() {
			continue
		}
		org := strings.TrimSpace(parts[4])
		if len(org) > 48 {
			org = org[:48]
		}
		if o, ok := orgs[org]; ok {
			org = o
		} else {
			orgs[org] = org
		}
		out = append(out, asnRange{start: start, end: end, asn: uint32(asn), org: org})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start.Less(out[j].start) })
	return out, nil
}

func (d *ASNDB) Lookup(ip string) (uint32, string) {
	if d == nil {
		return 0, ""
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0, ""
	}
	a = a.Unmap().WithZone("")
	d.mu.RLock()
	defer d.mu.RUnlock()
	i := sort.Search(len(d.ranges), func(i int) bool { return a.Less(d.ranges[i].start) })
	if i == 0 {
		return 0, ""
	}
	r := d.ranges[i-1]
	if r.start.Is4() != a.Is4() || r.end.Less(a) {
		return 0, ""
	}
	return r.asn, r.org
}
