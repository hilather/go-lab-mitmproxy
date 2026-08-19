// Package http2x is the HTTP/2 codec behind golang.org/x/net/http2 (D28).
//
// It is not a proxy or MITM library. Production files must not Dial
// (no Dial / DialContext / DialTimeout / net.Dialer). http2.Transport.DialTLS
// stays nil; origin connections use a ClientConnPool bound to an already
// dialed conn that errors `proxy: intercepted CONNECT refuses redial` on a
// second open.
package http2x
