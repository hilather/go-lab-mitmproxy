package rest

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/hilather/go-lab-mitmproxy/internal/domainerr"
)

const (
	cursorIDLen  = 26
	cursorGenLen = 8
	cursorMACLen = 32
	cursorRawLen = cursorIDLen + cursorGenLen + cursorMACLen
)

func (s *Server) encodeCursor(id string, generation uint64) string {
	if id == "" {
		return ""
	}
	raw := make([]byte, cursorRawLen)
	copy(raw, id)
	binary.BigEndian.PutUint64(raw[cursorIDLen:cursorIDLen+cursorGenLen], generation)
	s.cursorMu.Lock()
	key := append([]byte(nil), s.cursorKey...)
	s.cursorMu.Unlock()
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw[:cursorIDLen+cursorGenLen])
	copy(raw[cursorIDLen+cursorGenLen:], mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *Server) decodeCursor(cur string) (string, uint64, error) {
	if cur == "" {
		return "", 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cur)
	if err != nil || len(raw) != cursorRawLen {
		return "", 0, domainerr.ValidationFailed("invalid cursor",
			domainerr.FieldViolation{Path: "cursor", Code: "invalid_value", Message: "cursor is not a valid LabMITM list cursor"})
	}
	s.cursorMu.Lock()
	key := append([]byte(nil), s.cursorKey...)
	s.cursorMu.Unlock()
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(raw[:cursorIDLen+cursorGenLen])
	if !hmac.Equal(mac.Sum(nil), raw[cursorIDLen+cursorGenLen:]) {
		return "", 0, domainerr.CursorStale("list cursor is not valid for this process")
	}
	gen := binary.BigEndian.Uint64(raw[cursorIDLen : cursorIDLen+cursorGenLen])
	id := string(raw[:cursorIDLen])
	return id, gen, nil
}
