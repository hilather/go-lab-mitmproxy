// Package proxytest is a test-only HTTP/1.1 client for the LabMITM data plane.
//
// Production Dial isolation (D16) allows Dial idents here. Tests must not
// import this package from production files.
package proxytest
