// Package grpcx is the best-effort gRPC length-prefix + protobuf wire tree (D66).
//
// It is decode-only. Production files must not Dial, DialUDP, ListenPacket,
// or ListenUDP. There is no google.golang.org/protobuf and no MITM library.
package grpcx
