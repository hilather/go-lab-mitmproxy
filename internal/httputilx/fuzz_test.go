package httputilx

import (
	"bufio"
	"bytes"
	"net/http"
	"testing"
)

func FuzzReadRequest(f *testing.F) {
	f.Add([]byte("GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	f.Add([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	f.Add([]byte("GET http://app.lab/ HTTP/1.1\r\nHost: app.lab\r\nConnection: close, X-Hop\r\nX-Hop: 1\r\nProxy-Authorization: Basic x\r\n\r\n"))
	f.Add([]byte("GET http://app.lab/ws HTTP/1.1\r\nHost: app.lab\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			data = data[:64*1024]
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
		if err != nil {
			return
		}
		// Hop-by-hop strip must not panic on any parseable request line/headers.
		PrepareRequest(req.Header)
		PrepareResponse(req.Header, IsWebSocketUpgrade(req.Header))
	})
}
