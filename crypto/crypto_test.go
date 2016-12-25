package crypto

import (
	"bytes"
	"testing"
)

func Test_exchangePreMasterKey(t *testing.T) {
	privC, cx := GenerateKeyExChange()

	privS, sx := GenerateKeyExChange()
	preMasterKeyS, err := ProcessKeyExchange(privS, cx)
	if err != nil {
		t.Errorf("processKeyExchange error:%s", err.Error())
		return
	}

	preMasterKeyC, err := ProcessKeyExchange(privC, sx)
	if err != nil {
		t.Errorf("processKeyExchange error:%s", err.Error())
		return
	}

	if bytes.Compare(preMasterKeyC, preMasterKeyS) != 0 {
		t.Errorf("preMasterKeyC(%v) !=  preMasterKeyS(%v)", preMasterKeyC, preMasterKeyS)
		return
	}
}

func Test_generateMasterKey(t *testing.T) {
	preMasterKey := []byte{37, 31, 38, 235, 238, 241, 119, 224, 84, 162, 114, 93, 47, 155, 86, 130, 37, 220, 118, 217, 82, 142, 125, 203, 141, 6, 129, 193, 251, 191, 104, 152}

	prfunc := newPrf12()
	var seed []byte = make([]byte, 16)
	randBytes(seed)
	var result []byte = make([]byte, 16)
	prfunc(result, preMasterKey, []byte("haha"), seed)
	randBytes(seed)
	var result2 []byte = make([]byte, 16)
	prfunc(result2, preMasterKey, []byte("haha"), seed)
	if bytes.Compare(result, result2) == 0 {
		t.Errorf("error generate master secret randomly")
		return
	}
}

func Test_generateUUID(t *testing.T) {
	u := GenUUID()
	if len(u.Hex()) != 36 {
		t.Errorf("uuid len not equal 46")
	}
}
