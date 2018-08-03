package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

const (
	// NonceSizeGCM 12/96 bytes/bits - is the size of the initialization vector for AES GCM
	NonceSizeGCM = 12
)

// CipherAESGCM -
func CipherAESGCM(key [32]byte, plainbytes []byte) (cipherbytes []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSizeGCM)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cipherbytes = aesgcm.Seal(nil, nonce, plainbytes, nil)
	cipherbytes = append(cipherbytes, nonce...)
	return cipherbytes, nil
}

// DecipherAESGCM -
func DecipherAESGCM(key [32]byte, cipherbytes []byte) (plainbytes []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cipherbytesLen := len(cipherbytes)
	pivot := cipherbytesLen - NonceSizeGCM
	nonce := cipherbytes[pivot:]
	cipherbytes = cipherbytes[:pivot]
	plainbytes, err = aesgcm.Open(nil, nonce, cipherbytes, nil)
	if err != nil {
		return nil, err
	}
	return plainbytes, nil
}
