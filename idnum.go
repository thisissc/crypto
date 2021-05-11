package crypto

import (
	"strconv"
)

type IDNum string

func (code IDNum) Valid() bool {
	if len(code) != 18 {
		return false
	}

	weight := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}        //十七位数字本体码权重
	validate := []string{"1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"} //mod11,对应校验码字符值

	sum := 0
	mode := 0
	verCode := string(code[17])

	for i, curCode := range code[:17] {
		curNum, err := strconv.Atoi(string(curCode))
		if err != nil {
			return false
		}

		sum = sum + curNum*weight[i]
	}

	mode = sum % 11
	return validate[mode] == verCode
}
