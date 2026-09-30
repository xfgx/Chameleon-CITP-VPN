//go:build windows

package main

import (
	"chameleon/internal/clientactivation"
	"context"
	"errors"
	"net/http"
	"time"
)

// A CA-validated fixed HTTPS origin provides only a clock sanity check. No token.
// Never adjusts system time or expands the protocol's replay/epoch window.
func checkKSClock(ctx context.Context) error {
	req, e := http.NewRequestWithContext(ctx, "HEAD", clientactivation.Website, nil)
	if e != nil {
		return e
	}
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	before := time.Now()
	r, e := c.Do(req)
	if e != nil {
		return nil
	}
	defer r.Body.Close()
	after := time.Now()
	server, e := http.ParseTime(r.Header.Get("Date"))
	if e != nil || after.Sub(before) > 4*time.Second {
		return nil
	}
	delta := server.Sub(before.Add(after.Sub(before) / 2))
	if delta > 12*time.Second || delta < -12*time.Second {
		return productFailure("ks.clock", errors.New("system clock differs from HTTPS gateway"))
	}
	return nil
}
