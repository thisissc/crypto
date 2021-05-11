package crypto

import (
	"encoding/json"
	"time"
)

type EmailVercode struct {
	AESKeySecret []byte
}

func NewEmailVercode(secret []byte) *EmailVercode {
	return &EmailVercode{
		AESKeySecret: secret,
	}
}

func (v *EmailVercode) Generate(userid string) string {
	content := map[string]interface{}{
		"userid":    userid,
		"timestamp": time.Now().Unix(),
	}
	baseStr, _ := json.Marshal(content)
	result, _ := AesEncrypt(v.AESKeySecret, string(baseStr))
	return result
}

func (v *EmailVercode) Parse(code string) (string, bool) {
	origData, err := AesDecrypt(v.AESKeySecret, code)
	if err != nil {
		return "", false
	}

	var content map[string]interface{}
	json.Unmarshal([]byte(origData), &content)
	userid := content["userid"].(string)
	return userid, true
}
