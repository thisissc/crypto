package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/nacl/secretbox"
)

func NaclEncrypt(key []byte, message string) (encmess string, err error) {
	var secretKey [32]byte
	copy(secretKey[:], key)

	var nonce [24]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}

	encrypted := secretbox.Seal(nonce[:], []byte(message), &nonce, &secretKey)
	encmess = base64.URLEncoding.EncodeToString(encrypted)
	return
}

func NaclDecrypt(key []byte, securemess string) (decodedmess string, err error) {
	var secretKey [32]byte
	copy(secretKey[:], key)

	encrypted, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil || len(encrypted) <= 24 {
		return
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open([]byte{}, encrypted[24:], &decryptNonce, &secretKey)
	if !ok {
		return
	}

	decodedmess = string(decrypted)
	return
}
