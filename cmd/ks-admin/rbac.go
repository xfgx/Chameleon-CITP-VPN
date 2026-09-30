//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"net/http"
	"os"
	"strings"
	"unicode"
)

var fRoles = flag.String("roles", "", "optional private role accounts JSON; existing administrator is preserved")

type principal struct {
	User string
	Role string
}
type principalKey struct{}
type roleAccount struct {
	User string `json:"user"`
	Role string `json:"role"`
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}

var roleAccounts = map[string]struct {
	Conf *adminConf
	Role string
}{}

func roleRank(role string) int {
	switch role {
	case "admin":
		return 3
	case "operator":
		return 2
	case "viewer":
		return 1
	}
	return 0
}
func loadRoles() error {
	if *fRoles == "" {
		return nil
	}
	st, err := os.Stat(*fRoles)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("role accounts require mode 0600")
	}
	var data struct {
		Version int           `json:"version"`
		Users   []roleAccount `json:"users"`
	}
	if err = readStrictJSON(*fRoles, &data, 65536); err != nil {
		return err
	}
	if data.Version != 1 || len(data.Users) > 32 {
		return errors.New("invalid role accounts")
	}
	out := map[string]struct {
		Conf *adminConf
		Role string
	}{}
	for _, a := range data.Users {
		salt, e := base64.StdEncoding.DecodeString(a.Salt)
		hash, e2 := base64.StdEncoding.DecodeString(a.Hash)
		if e != nil || e2 != nil || len(salt) < 16 || len(hash) != 32 || roleRank(a.Role) == 0 || a.User == "" || len(a.User) > 64 || strings.IndexFunc(a.User, unicode.IsControl) >= 0 || a.User == conf.User {
			return errors.New("invalid role account")
		}
		if _, ok := out[a.User]; ok {
			return errors.New("duplicate role account")
		}
		out[a.User] = struct {
			Conf *adminConf
			Role string
		}{&adminConf{User: a.User, Salt: salt, Hash: hash}, a.Role}
	}
	roleAccounts = out
	return nil
}
func authenticateRole(user, password string) (principal, bool) {
	if conf != nil && user == conf.User {
		return principal{user, "admin"}, checkPass(conf, user, password)
	}
	a, ok := roleAccounts[user]
	if !ok {
		_ = checkPass(conf, user, password)
		return principal{}, false
	}
	return principal{user, a.Role}, checkPass(a.Conf, user, password)
}
func (s *sessStore) createAs(p principal) (string, error) {
	if roleRank(p.Role) == 0 {
		return "", errors.New("invalid role")
	}
	token, err := s.create()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	if s.identities == nil {
		s.identities = map[string]principal{}
	}
	s.identities[token] = p
	s.mu.Unlock()
	return token, nil
}
func (s *sessStore) identity(token string) principal {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.identities[token]; ok {
		return p
	}
	user := "admin"
	if conf != nil {
		user = conf.User
	}
	return principal{user, "admin"}
}
func requestPrincipal(r *http.Request) principal {
	if p, ok := r.Context().Value(principalKey{}).(principal); ok {
		return p
	}
	if ck, e := r.Cookie(cookieName); e == nil && sessions != nil && sessions.valid(ck.Value) {
		return sessions.identity(ck.Value)
	}
	return principal{}
}
func requestActor(r *http.Request) string {
	p := requestPrincipal(r)
	if p.User != "" {
		return p.User
	}
	return "anonymous"
}
func requireRole(role string, h http.HandlerFunc) http.HandlerFunc {
	return requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if roleRank(requestPrincipal(r).Role) < roleRank(role) {
			http.Error(w, "Insufficient role", 403)
			return
		}
		h(w, r)
	})
}
func withPrincipal(r *http.Request, p principal) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
}
func markActivationManualRevoke(deviceID string) error {
	activationState.Lock()
	defer activationState.Unlock()
	if activationState.trusted == nil {
		return nil
	}
	for _, u := range activationState.data.Users {
		for _, b := range u.Devices {
			if b.DeviceID == deviceID || b.KSDeviceID == deviceID {
				b.Revoked = true
				return saveActivationsLocked()
			}
		}
	}
	return nil
}
