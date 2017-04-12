package util

import (
	"fmt"
	"strconv"
	"strings"
)

func Int2Short(a uint64) []byte {
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

func ParseAddr(s string) (schema string, hostname string, port uint64, err error) {
	temp := strings.SplitN(s, "://", 2)
	if len(temp) == 1 {
		hostname = temp[0]
	} else {
		schema = temp[0]
		hostname = temp[1]
	}
	idx := strings.LastIndex(hostname, ":")
	if idx >= 0 {
		portStr := hostname[idx+1:]
		hostname = hostname[:idx]
		if portStr == "" {
			port = 0
		} else {
			port, err = strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				err = fmt.Errorf("port invalid %s", err.Error())
			}
			if port > 65535 {
				err = fmt.Errorf("port greater than 65535")
			}
		}
	}
	return
}
