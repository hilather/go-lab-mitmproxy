package proxy

import (
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-mitmproxy/internal/model"
	"github.com/hilather/go-lab-mitmproxy/internal/snapshot"
)

const proxyAuthChallengeBody = "proxy authentication required\n"

func (s *Server) rejectHTTPAuth(w http.ResponseWriter, req *http.Request, host string, started time.Time, sess *ruleSession, connect bool) bool {
	if sess == nil || !sess.spec.Proxy.HTTPAuth.Enabled {
		return false
	}
	if matchHTTPAuth(req, s.httpAuthUsers(sess)) {
		return false
	}
	s.metrics.reject("proxy_auth")
	if connect {
		s.capture(connectFlow(req, host, http.StatusProxyAuthRequired, "proxy_auth", started), sess)
	} else {
		s.capture(s.flowFromReq(req, host, "http", http.StatusProxyAuthRequired, "proxy_auth", started), sess)
	}
	writeProxyAuthChallenge(w, sess.spec.Proxy.HTTPAuth.Realm)
	return true
}

func (s *Server) httpAuthUsers(sess *ruleSession) []snapshot.SOCKSUserDigest {
	if sess != nil && sess.snap != nil {
		return sess.snap.HTTPAuthUsers
	}
	if s == nil || s.snaps == nil {
		return nil
	}
	snap := s.snaps.Load()
	if snap == nil {
		return nil
	}
	return snap.HTTPAuthUsers
}

func matchHTTPAuth(req *http.Request, users []snapshot.SOCKSUserDigest) bool {
	if req == nil {
		return false
	}
	user, pass, ok := parseBasicProxyAuth(req.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	digest := snapshot.DigestSOCKSUser(user, pass)
	zeroSOCKSSecret(user)
	zeroSOCKSSecret(pass)
	_, matched := matchSOCKSUsers(users, digest)
	return matched
}

func parseBasicProxyAuth(h string) (user, pass []byte, ok bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return nil, nil, false
	}
	scheme, rest, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return nil, nil, false
	}
	raw := strings.TrimSpace(rest)
	if raw == "" {
		return nil, nil, false
	}
	dec, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, nil, false
	}
	i := -1
	for j, b := range dec {
		if b == ':' {
			i = j
			break
		}
	}
	if i < 0 {
		zeroSOCKSSecret(dec)
		return nil, nil, false
	}
	return dec[:i], dec[i+1:], true
}

func writeProxyAuthChallenge(w http.ResponseWriter, realm string) {
	if w == nil {
		return
	}
	body := proxyAuthChallengeBody
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Proxy-Authenticate", proxyAuthenticateValue(realm))
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = io.WriteString(w, body)
}

func proxyAuthenticateValue(realm string) string {
	if strings.TrimSpace(realm) == "" {
		realm = "labmitm-proxy"
	}
	return `Basic realm="` + quoteAuthRealm(realm) + `"`
}

func quoteAuthRealm(realm string) string {
	var b strings.Builder
	for _, r := range realm {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func h2cProxyAuthChallenge(realm string) []model.Header {
	return []model.Header{{Name: "proxy-authenticate", Value: proxyAuthenticateValue(realm)}}
}
