// Package http2x is the HTTP/2 codec behind golang.org/x/net/http2 (D28).
//
// It is not a proxy or MITM library. Production files must not Dial
// (no Dial / DialContext / DialTimeout / net.Dialer). http2.Transport.DialTLS
// stays nil; origin connections use a ClientConnPool bound to an already
// dialed conn that errors `proxy: intercepted CONNECT refuses redial` on a
// second open. ServeClient is request/response-only. RFC 8441 inner
// websocket uses ServeConn with a TunnelHandler (D63). RFC 9113 CONNECT on
// client-facing h2c uses TunnelRaw splice or TunnelIntercept AfterAck (D62).
// ServeConn PrefaceTail consumes PRI leftover from bufrw (SM\r\n\r\n plus
// SETTINGS) and must not ReadFull ClientPreface from the raw conn after
// Hijack (D61).
package http2x
