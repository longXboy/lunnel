package util

func IntToReadable(a uint64) []byte {
	var link []byte = make([]byte, 4)
	link = link[:0]
	for i := 0; i <= 12; i++ {
		temp := a & 31
		if temp > 9 {
			//convert to [a-v]
			temp += 87
		} else {
			//convert to [0-9]
			temp += 48
		}

		link = append(link, byte(temp))
		a = a >> 5
		if a == 0 {
			break
		}
	}
	return link
}
