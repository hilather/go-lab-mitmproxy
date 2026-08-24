package snapshot

import (
	"crypto/sha256"
	"testing"
)

func TestDigestSOCKSUserLengthPrefix(t *testing.T) {
	user := []byte("labuser")
	pass := []byte("labpass12")
	buf := make([]byte, 0, 2+len(user)+len(pass))
	buf = append(buf, byte(len(user)))
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	want := sha256.Sum256(buf)
	got := DigestSOCKSUser(user, pass)
	if got != want {
		t.Fatalf("digest=%x want %x", got, want)
	}
	if DigestSOCKSUser([]byte("labuser"), []byte("otherpass1")) == got {
		t.Fatal("different password hashed equal")
	}
}
