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

type LoopQueue struct {
	queue     []interface{}
	maxLength int
	elemNum   int
	firstElem int
}

func NewLoopQueue(maxLength int) *LoopQueue {
	loop := LoopQueue{
		queue: make([]interface{}, maxLength),
	}
	return &loop
}

func (loop *LoopQueue) Put(a interface{}) bool {
	if loop.elemNum >= loop.maxLength {
		return false
	}
	idx := (loop.firstElem + loop.elemNum) % loop.maxLength
	loop.queue[idx] = a
	loop.elemNum++
	return true
}

func (loop *LoopQueue) Get() interface{} {
	if loop.elemNum <= 0 {
		return nil
	}
	elem := loop.queue[loop.firstElem]
	loop.firstElem++
	if loop.firstElem >= loop.elemNum {
		loop.firstElem = loop.firstElem % loop.maxLength
	}
	loop.elemNum--
	return elem
}
