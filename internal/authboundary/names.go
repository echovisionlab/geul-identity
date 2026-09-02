package authboundary

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	AuthHeaderNameEnv            = "AUTH_HEADER_NAME"
	InternalServiceHeaderNameEnv = "INTERNAL_SERVICE_HEADER_NAME"
	SessionCookieNameEnv         = "SESSION_COOKIE_NAME"

	AuthHeaderNamePlaceholder            = "__AUTH_HEADER_NAME__"
	InternalServiceHeaderNamePlaceholder = "__INTERNAL_SERVICE_HEADER_NAME__"
	SessionCookieNamePlaceholder         = "__SESSION_COOKIE_NAME__"
)

// Names is the deployment-owned naming contract for the authentication
// boundary. The generated Oathkeeper templates deliberately use placeholders
// until the deployment renderer validates and applies these names.
type Names struct {
	AuthHeaderName            string
	InternalServiceHeaderName string
	SessionCookieName         string
}

var tokenPattern = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

var reservedHeaderNames = [...]string{
	"Authorization",
	"Cookie",
	"X-Session-Id",
	"Proxy-Authorization",
	"Proxy-Authenticate",
	"Host",
	"Content-Length",
	"Connection",
	"Transfer-Encoding",
	"Upgrade",
	"TE",
	"Trailer",
}

// NamesFromEnv loads the complete authentication-boundary naming contract.
// Missing or malformed values are errors; callers must not fall back to a
// repository-specific name.
func NamesFromEnv() (Names, error) {
	return NamesFromLookup(os.LookupEnv)
}

// NamesFromLookup is split out so callers can test fail-closed environment
// loading without mutating process-global environment state.
func NamesFromLookup(lookup func(string) (string, bool)) (Names, error) {
	values := make(map[string]string, 3)
	for _, name := range []string{
		AuthHeaderNameEnv,
		InternalServiceHeaderNameEnv,
		SessionCookieNameEnv,
	} {
		value, ok := lookup(name)
		if !ok || strings.TrimSpace(value) == "" {
			return Names{}, fmt.Errorf("%s is required", name)
		}
		values[name] = value
	}
	return NewNames(
		values[AuthHeaderNameEnv],
		values[InternalServiceHeaderNameEnv],
		values[SessionCookieNameEnv],
	)
}

// NewNames validates a naming contract supplied by a caller such as the
// renderer. Header and cookie names are HTTP tokens, and the two internal
// projection headers must not collide with raw credential headers or each
// other.
func NewNames(authHeaderName, internalServiceHeaderName, sessionCookieName string) (Names, error) {
	names := Names{
		AuthHeaderName:            authHeaderName,
		InternalServiceHeaderName: internalServiceHeaderName,
		SessionCookieName:         sessionCookieName,
	}
	for _, candidate := range []struct {
		env   string
		value string
	}{
		{AuthHeaderNameEnv, names.AuthHeaderName},
		{InternalServiceHeaderNameEnv, names.InternalServiceHeaderName},
		{SessionCookieNameEnv, names.SessionCookieName},
	} {
		if candidate.value == "" || strings.TrimSpace(candidate.value) != candidate.value {
			return Names{}, fmt.Errorf("%s must be a non-empty HTTP token", candidate.env)
		}
		if !tokenPattern.MatchString(candidate.value) {
			return Names{}, fmt.Errorf("%s must be a valid HTTP token", candidate.env)
		}
	}

	if strings.EqualFold(names.AuthHeaderName, names.InternalServiceHeaderName) {
		return Names{}, fmt.Errorf("%s and %s must be different", AuthHeaderNameEnv, InternalServiceHeaderNameEnv)
	}
	for _, candidate := range []struct {
		env   string
		value string
	}{
		{AuthHeaderNameEnv, names.AuthHeaderName},
		{InternalServiceHeaderNameEnv, names.InternalServiceHeaderName},
	} {
		for _, reserved := range reservedHeaderNames {
			if strings.EqualFold(candidate.value, reserved) {
				return Names{}, fmt.Errorf("%s must not be a reserved credential or framing header %q", candidate.env, reserved)
			}
		}
	}
	return names, nil
}
