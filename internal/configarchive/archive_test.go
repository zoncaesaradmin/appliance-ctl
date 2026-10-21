package configarchive

import (
	"bytes"
	"testing"
)

func TestSealOpenAndRejectTamper(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	payload := []byte(`{"apiVersion":"configuration.zon/v1"}`)
	data, manifest, err := Seal("revision-1", "configuration.zon/v1", payload, key)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, opened, err := Open(data, key)
	if err != nil || got.ArchiveID != manifest.ArchiveID || !bytes.Equal(opened, payload) {
		t.Fatalf("Open = %#v %q %v", got, opened, err)
	}
	data[len(data)-1] ^= 1
	if _, _, err := Open(data, key); err == nil {
		t.Fatal("tampered archive accepted")
	}
}
