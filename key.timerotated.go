package secret

import (
	"bytes"
	"crypto/sha512"
	"time"
)

// TimeRotatedKey -
func TimeRotatedKey(seed []byte, salt time.Time) [32]byte {
	secretBuff := bytes.NewBuffer(seed)
	saltStr := salt.Format(time.RFC850)
	secretBuff.WriteString(saltStr)
	cipherKey := sha512.Sum512_256(secretBuff.Bytes())
	return cipherKey
}
