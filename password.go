package crypto

import (
	"encoding/hex"
)

func HashPwd(password, salt string, secret []byte) string {
	baseStr := password + salt
	sum256 := Hmac256Sum([]byte(baseStr), secret)
	tempPwd := hex.EncodeToString(sum256[:])
	return tempPwd
}
