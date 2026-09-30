package telemetry

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Store struct {
	Dir       string
	Retention time.Duration
	MaxBytes  int64
	mu        sync.Mutex
	seq       uint64
	lastSweep time.Time
}

func (s *Store) Append(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.Normalize()
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	if s.Retention == 0 {
		s.Retention = 72 * time.Hour
	}
	if s.MaxBytes == 0 {
		s.MaxBytes = 96 << 20
	}
	if time.Since(s.lastSweep) > time.Minute {
		if err := s.sweep(); err != nil {
			return err
		}
		s.lastSweep = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > 16384 {
		return errors.New("telemetry event exceeds limit")
	}
	name := "events-" + time.Now().UTC().Format("20060102-15") + ".jsonl"
	f, err := os.OpenFile(filepath.Join(s.Dir, name), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}
func (s *Store) sweep() error {
	files, err := filepath.Glob(filepath.Join(s.Dir, "events-????????-??.jsonl"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	var total int64
	for i := len(files) - 1; i >= 0; i-- {
		st, err := os.Stat(files[i])
		if err != nil {
			continue
		}
		total += st.Size()
		if time.Since(st.ModTime()) > s.Retention || total > s.MaxBytes {
			if err = os.Remove(files[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

type Cursor struct {
	Name   string `json:"file"`
	Offset int64  `json:"offset"`
}
type Batch struct {
	Records []Event `json:"records"`
	Cursor  string  `json:"cursor"`
	More    bool    `json:"more"`
	Gap     bool    `json:"gap"`
}

func encodeCursor(c Cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}
func parseCursor(token string) (Cursor, error) {
	var c Cursor
	if token == "" {
		return c, nil
	}
	if len(token) > 512 {
		return c, errors.New("invalid cursor")
	}
	b, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil {
		return c, e
	}
	e = json.Unmarshal(b, &c)
	if e != nil || c.Offset < 0 || c.Name != filepath.Base(c.Name) || !strings.HasPrefix(c.Name, "events-") || !strings.HasSuffix(c.Name, ".jsonl") || strings.Contains(c.Name, "..") || strings.ContainsAny(c.Name, "/\\") {
		return c, errors.New("invalid cursor")
	}
	return c, nil
}
func Read(dir, token string, limit int) (Batch, error) {
	out := Batch{Records: []Event{}}
	if limit < 1 || limit > 1000 {
		return out, errors.New("batch limit")
	}
	cursor, err := parseCursor(token)
	if err != nil {
		return out, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "events-????????-??.jsonl"))
	if err != nil {
		return out, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		out.Cursor = token
		out.Gap = token != ""
		return out, nil
	}
	if cursor.Name != "" {
		exists := false
		for _, path := range files {
			if filepath.Base(path) == cursor.Name {
				exists = true
			}
		}
		if !exists {
			out.Gap = true
		}
	}
	for _, path := range files {
		name := filepath.Base(path)
		if cursor.Name != "" && name < cursor.Name {
			continue
		}
		offset := int64(0)
		if name == cursor.Name {
			offset = cursor.Offset
		}
		f, e := os.Open(path)
		if e != nil {
			return out, e
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return out, e
		}
		if offset > st.Size() {
			out.Gap = true
			offset = 0
		}
		if _, e = f.Seek(offset, 0); e != nil {
			f.Close()
			return out, e
		}
		reader := bufio.NewReaderSize(f, 32768)
		for {
			line, consumed, e := readBoundedLine(reader, 16385)
			if e == io.EOF {
				break
			}
			if e != nil {
				f.Close()
				return out, e
			}
			offset += consumed
			if line == nil {
				out.Gap = true
				continue
			}
			var row Event
			if json.Unmarshal(line, &row) != nil {
				out.Gap = true
				continue
			}
			out.Records = append(out.Records, row)
			cursor = Cursor{name, offset}
			if len(out.Records) >= limit {
				f.Close()
				out.Cursor = encodeCursor(cursor)
				out.More = true
				return out, nil
			}
		}
		f.Close()
		cursor = Cursor{name, offset}
	}
	out.Cursor = encodeCursor(cursor)
	return out, nil
}

// Drain an oversized complete line in bounded chunks. An incomplete tail is
// deliberately not consumed by the durable cursor, so the writer may finish it.
func readBoundedLine(r *bufio.Reader, maximum int) ([]byte, int64, error) {
	var out []byte
	var consumed int64
	overflow := false
	for {
		part, err := r.ReadSlice('\n')
		consumed += int64(len(part))
		if !overflow && len(out)+len(part) <= maximum {
			out = append(out, part...)
		} else {
			overflow = true
			out = nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, consumed, err
		}
		if overflow {
			return nil, consumed, nil
		}
		return out, consumed, nil
	}
}

type CapturedHeader struct {
	At          time.Time
	OriginalLen int
	Bytes       []byte
}

func WriteCapture(dir, id string, headers []CapturedHeader) error {
	if !ValidCaptureID(id) || len(headers) > 64 {
		return errors.New("invalid capture")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	p := filepath.Join(dir, id+".pcap")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	write := func(v any) error { return binary.Write(f, binary.LittleEndian, v) }
	if err = write([]uint32{0xa1b2c3d4, 0x00040002, 0, 0, 128, 101}); err != nil {
		return err
	}
	for _, h := range headers {
		if len(h.Bytes) > 60 || len(h.Bytes) < 28 || h.OriginalLen < len(h.Bytes) {
			return errors.New("capture contains non-base header")
		}
		version := h.Bytes[0] >> 4
		expected := 0
		if version == 4 && h.Bytes[0]&15 == 5 {
			if h.Bytes[9] == 6 && len(h.Bytes) >= 40 && h.Bytes[32]>>4 == 5 {
				expected = 40
			} else if h.Bytes[9] == 17 {
				expected = 28
			}
		} else if version == 6 {
			if h.Bytes[6] == 6 && len(h.Bytes) >= 60 && h.Bytes[52]>>4 == 5 {
				expected = 60
			} else if h.Bytes[6] == 17 {
				expected = 48
			}
		}
		if expected != len(h.Bytes) {
			return errors.New("only exact base IP/transport headers may be stored")
		}
		if h.Bytes[0]>>4 == 6 && len(h.Bytes) > 60 {
			return errors.New("IPv6 header bound")
		}
		if err = write([]uint32{uint32(h.At.Unix()), uint32(h.At.Nanosecond() / 1000), uint32(len(h.Bytes)), uint32(h.OriginalLen)}); err != nil {
			return err
		}
		if _, err = f.Write(h.Bytes); err != nil {
			return err
		}
	}
	return f.Sync()
}
func ValidCaptureID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
func ReadCapture(dir, id string) ([]byte, error) {
	if !ValidCaptureID(id) {
		return nil, errors.New("invalid capture id")
	}
	p := filepath.Join(dir, id+".pcap")
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 8192 || time.Since(st.ModTime()) > time.Hour {
		return nil, errors.New("capture expired or invalid")
	}
	return os.ReadFile(p)
}
func SweepCaptures(dir string) error {
	files, _ := filepath.Glob(filepath.Join(dir, "*.pcap"))
	for _, p := range files {
		if !ValidCaptureID(strings.TrimSuffix(filepath.Base(p), ".pcap")) {
			continue
		}
		st, e := os.Stat(p)
		if e == nil && time.Since(st.ModTime()) > time.Hour {
			if e = os.Remove(p); e != nil {
				return fmt.Errorf("capture retention: %w", e)
			}
		}
	}
	return nil
}
