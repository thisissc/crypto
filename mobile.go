package crypto

import (
	"fmt"
	"math"
	"time"
)

type MobileVercode struct {
	HMACKeySecret []byte
	Mobile        string
	From          string
}

func NewMobileVercode(mobile, from string, secret []byte) *MobileVercode {
	return &MobileVercode{
		HMACKeySecret: secret,
		Mobile:        mobile,
		From:          from,
	}
}

func (v *MobileVercode) Generate() string {
	curTime := time.Now().Unix()
	curMinute := int(math.Floor(float64(curTime) / 60))

	return v.Mobile2VerCode(v.Mobile, curMinute, v.From)
}

func (v *MobileVercode) Verify(verCode string) bool {
	curTime := time.Now().Unix()
	curMinute := int(math.Floor(float64(curTime) / 60))

	// verCode period, unit: minute
	period := 5
	for i := 0; i < period; i++ {
		if v.Mobile2VerCode(v.Mobile, curMinute-i, v.From) == verCode {
			return true
		}
	}

	return false
}

func (v *MobileVercode) Mobile2VerCode(mobile string, timeMinute int, from string) string {
	baseStr := fmt.Sprintf("%s|%d|%s", mobile, timeMinute, from)
	codeOrig := Hmac256Sum([]byte(baseStr), v.HMACKeySecret)[:3]
	s1 := fmt.Sprintf("%02d", int(codeOrig[0]))[:2]
	s2 := fmt.Sprintf("%02d", int(codeOrig[1]))[:2]
	s3 := fmt.Sprintf("%02d", int(codeOrig[2]))[:2]

	return fmt.Sprintf("%s%s%s", s1, s2, s3)
}
