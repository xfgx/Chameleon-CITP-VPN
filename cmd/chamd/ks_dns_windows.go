//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"time"
)

// DNS-over-HTTPS traverses the KS capture routes. No DNS bypass or payload log.
var ksResolver = &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
	Proxy: nil, TLSClientConfig: &tls.Config{ServerName: "dns.google", MinVersion: tls.VersionTLS12},
	DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", "8.8.8.8:443")
	},
	MaxIdleConnsPerHost: 2,
}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func handleKSDNS(conn net.PacketConn, source net.Addr, query []byte) {
	if len(query) < 12 || len(query) > 4096 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", "https://dns.google/dns-query", bytes.NewReader(query))
	if e != nil {
		return
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, e := ksResolver.Do(req)
	if e != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	answer, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || len(answer) < 12 || len(answer) > 4096 || answer[0] != query[0] || answer[1] != query[1] {
		return
	}
	_, _ = conn.WriteTo(answer, source)
}
