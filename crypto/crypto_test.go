package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func Test_exchangePreMasterKey(t *testing.T) {
	privC, ckx := generateClientKeyExChange()
	ckx_bytes := ckx.marshal()

	new_ckx := new(exchangeMsg)
	if !new_ckx.unmarshal(ckx_bytes) {
		t.Errorf("new_ckx.unmarshal(%v) error", ckx_bytes)
		return
	}
	privS, skx := generateClientKeyExChange()
	preMasterKeyS, err := processClientKeyExchange(privS, new_ckx)
	if err != nil {
		t.Errorf("processClientKeyExchange error:%s", err.Error())
		return
	}
	skx_bytes := skx.marshal()

	new_skx := new(exchangeMsg)
	if !new_skx.unmarshal(skx_bytes) {
		t.Errorf("new_ckx.unmarshal(%v) error", ckx_bytes)
		return
	}
	preMasterKeyC, err := processClientKeyExchange(privC, new_skx)
	if err != nil {
		t.Errorf("processClientKeyExchange error:%s", err.Error())
		return
	}

	fmt.Println(preMasterKeyC, "  ", preMasterKeyS)
	if bytes.Compare(preMasterKeyC, preMasterKeyS) != 0 {
		t.Errorf("preMasterKeyC(%v) !=  preMasterKeyS(%v)", preMasterKeyC, preMasterKeyS)
		return
	}
}

func Test_masterKey(t *testing.T) {
	preMasterKey := []byte{37, 31, 38, 235, 238, 241, 119, 224, 84, 162, 114, 93, 47, 155, 86, 130, 37, 220, 118, 217, 82, 142, 125, 203, 141, 6, 129, 193, 251, 191, 104, 152}

	prfunc := newPrf12()
	var seed []byte = make([]byte, 16)
	randBytes(seed)
	var result []byte = make([]byte, 16)
	prfunc(result, preMasterKey, []byte("haha"), seed)
	var result2 []byte = make([]byte, 16)
	prfunc(result2, preMasterKey, []byte("haha"), seed)
	if bytes.Compare(result, result2) == 0 {
		t.Errorf("rand func error")
		return
	}
}
