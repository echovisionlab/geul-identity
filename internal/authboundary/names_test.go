package authboundary

import (
	"strings"
	"testing"
)

func validNames() Names {
	return Names{
		AuthHeaderName:            "X-Authenticated-Context-B64",
		InternalServiceHeaderName: "X-Internal-Service",
		SessionCookieName:         "__Host-session",
	}
}

func TestNamesFromLookupRequiresEveryEnvironmentValue(t *testing.T) {
	base := map[string]string{
		AuthHeaderNameEnv:            validNames().AuthHeaderName,
		InternalServiceHeaderNameEnv: validNames().InternalServiceHeaderName,
		SessionCookieNameEnv:         validNames().SessionCookieName,
	}
	for _, missing := range []string{AuthHeaderNameEnv, InternalServiceHeaderNameEnv, SessionCookieNameEnv} {
		t.Run(missing, func(t *testing.T) {
			lookup := func(name string) (string, bool) {
				value, ok := base[name]
				if name == missing {
					return "", false
				}
				return value, ok
			}
			if _, err := NamesFromLookup(lookup); err == nil || !strings.Contains(err.Error(), missing) {
				t.Fatalf("NamesFromLookup() error = %v, want %s", err, missing)
			}
		})
	}
}

func TestNewNamesRejectsMalformedOrConflictingValues(t *testing.T) {
	base := validNames()
	tests := []struct {
		name   string
		mutate func(*Names)
		want   string
	}{
		{name: "header whitespace", mutate: func(n *Names) { n.AuthHeaderName = " X-Context" }, want: AuthHeaderNameEnv},
		{name: "header punctuation", mutate: func(n *Names) { n.AuthHeaderName = "X Context" }, want: AuthHeaderNameEnv},
		{name: "header collision", mutate: func(n *Names) { n.InternalServiceHeaderName = n.AuthHeaderName }, want: "must be different"},
		{name: "cookie punctuation", mutate: func(n *Names) { n.SessionCookieName = "session; Path=/" }, want: SessionCookieNameEnv},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := base
			tt.mutate(&names)
			_, err := NewNames(names.AuthHeaderName, names.InternalServiceHeaderName, names.SessionCookieName)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewNames() error = %v, want %q", err, tt.want)
			}
		})
	}
	for _, reserved := range reservedHeaderNames {
		for _, header := range []struct {
			env    string
			mutate func(*Names)
		}{
			{env: AuthHeaderNameEnv, mutate: func(names *Names) { names.AuthHeaderName = reserved }},
			{env: InternalServiceHeaderNameEnv, mutate: func(names *Names) { names.InternalServiceHeaderName = reserved }},
		} {
			t.Run(header.env+"/"+reserved, func(t *testing.T) {
				names := validNames()
				header.mutate(&names)
				_, err := NewNames(names.AuthHeaderName, names.InternalServiceHeaderName, names.SessionCookieName)
				if err == nil || !strings.Contains(err.Error(), header.env) {
					t.Fatalf("NewNames() accepted reserved %s %q: %v", header.env, reserved, err)
				}
			})
		}
	}
}
