package proxy

import (
	"bytes"
	"testing"
)

func TestParseClientHelloSNIAndALPN(t *testing.T) {
	raw := minimalClientHello("app.lab")
	hello, err := parseClientHelloRecord(bytes.NewReader(raw), 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != "app.lab" {
		t.Fatalf("sni=%q", hello.ServerName)
	}
	if len(hello.ALPN) != 1 || hello.ALPN[0] != "http/1.1" {
		t.Fatalf("alpn=%v", hello.ALPN)
	}
}

func TestParseClientHelloEmptySNI(t *testing.T) {
	raw := minimalClientHello("")
	hello, err := parseClientHelloRecord(bytes.NewReader(raw), 16<<10)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != "" {
		t.Fatalf("sni=%q", hello.ServerName)
	}
}

func TestParseClientHelloRejectsHTTP(t *testing.T) {
	_, err := parseClientHelloRecord(bytes.NewReader([]byte("GET /")), 16<<10)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOrigDestInterceptDecision(t *testing.T) {
	t.Parallel()
	tlsSpec := loadSpec(t).TLS
	tlsSpec.Intercept = true
	tlsSpec.Ports = []int{443}
	if intercept, failHS, denied := origDestInterceptDecision(tlsSpec, "app.lab", "443"); !intercept || failHS || denied {
		t.Fatalf("empty hosts intercept=%v fail=%v denied=%v", intercept, failHS, denied)
	}
	tlsSpec.Hosts = []string{"app.lab"}
	if intercept, failHS, denied := origDestInterceptDecision(tlsSpec, "", "443"); intercept || !failHS || denied {
		t.Fatalf("empty SNI intercept=%v fail=%v denied=%v", intercept, failHS, denied)
	}
	if intercept, failHS, denied := origDestInterceptDecision(tlsSpec, "other.lab", "443"); intercept || failHS || !denied {
		t.Fatalf("mismatch intercept=%v fail=%v denied=%v", intercept, failHS, denied)
	}
	if intercept, failHS, denied := origDestInterceptDecision(tlsSpec, "app.lab", "80"); intercept || failHS || denied {
		t.Fatalf("unlisted port intercept=%v fail=%v denied=%v", intercept, failHS, denied)
	}
}

func minimalClientHello(sni string) []byte {
	random := make([]byte, 32)
	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0x00)                   // session_id
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // one cipher
	body = append(body, 0x01, 0x00)             // compression null
	var exts []byte
	if sni != "" {
		name := []byte{0x00, byte(len(sni) >> 8), byte(len(sni))}
		name = append(name, []byte(sni)...)
		list := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...)
		exts = append(exts, 0x00, 0x00, byte(len(list)>>8), byte(len(list)))
		exts = append(exts, list...)
	}
	alpnProto := []byte{0x08}
	alpnProto = append(alpnProto, []byte("http/1.1")...)
	alpnList := append([]byte{byte(len(alpnProto) >> 8), byte(len(alpnProto))}, alpnProto...)
	exts = append(exts, 0x00, 0x10, byte(len(alpnList)>>8), byte(len(alpnList)))
	exts = append(exts, alpnList...)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}
