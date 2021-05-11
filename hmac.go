package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

func Hmac256Sum(message, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	return h.Sum(nil)
}
