package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"io"
)

func GenSalt(length int) string {
	salt := make([]byte, length)
	io.ReadFull(rand.Reader, salt)
	return hex.EncodeToString(salt)
}
