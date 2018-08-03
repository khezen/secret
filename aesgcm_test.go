package secret

import (
	"bytes"
	"testing"
	"time"
)

func TestAESGCM(t *testing.T) {
	now := time.Now().UTC()
	later := now.Add(time.Second)
	seed := []byte("test")
	key := TimeRotatedKey(seed, now)
	fakeKey := TimeRotatedKey(seed, later)
	cases := []struct {
		plainbytes []byte
	}{
		{[]byte("l'oeuf existe depuis plus longtemps que la poule.")},
		{[]byte("la poule existe depuis plus longtemps que l'oeuf.")},
	}
	for _, testCase := range cases {
		cipherbytes, err := CipherAESGCM(key, testCase.plainbytes)
		if err != nil {
			t.Error(err.Error())
		}
		plainbytes, err := DecipherAESGCM(fakeKey, cipherbytes)
		if err == nil {
			t.Error("expected err != nil")
		}
		if bytes.Compare(plainbytes, testCase.plainbytes) == 0 {
			t.Error("unexpected successful decipher with fake key")
		}
		plainbytes, err = DecipherAESGCM(key, cipherbytes)
		if err != nil {
			t.Error(err.Error())
		}
		if bytes.Compare(plainbytes, testCase.plainbytes) != 0 {
			t.Errorf("expected %s, got %s", string(testCase.plainbytes), string(plainbytes))
		}
	}
}
