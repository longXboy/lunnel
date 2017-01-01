package crypto

import (
	"bytes"
	"testing"
)

func Test_aesEncryptDecrypt(t *testing.T) {
	blocken, err := NewCryptoConn(nil, []byte("0123456789abcdef"))
	if err != nil {
		t.Errorf("NewAESBlockCrypt error:", err)
	}
	blockde, err := NewCryptoConn(nil, []byte("0123456789abcdef"))
	if err != nil {
		t.Errorf("NewAESBlockCrypt error:", err)
	}
	input := []byte("01a2c")
	blocken.encrypt(input, input)
	blockde.decrypt(input, input)
	if bytes.Compare(input, []byte("01a2c")) != 0 {
		t.Errorf("AES_CFB decrypt error:not compare")
	}

	input = make([]byte, 1472)
	randBytes(input)
	cmpBytes := make([]byte, len(input))
	copy(cmpBytes, input)
	blocken.encrypt(input, input)
	blockde.decrypt(input, input)
	if bytes.Compare(input, cmpBytes) != 0 {
		t.Errorf("AES_CFB decrypt error:not compare")
	}

	input = make([]byte, 100000)
	randBytes(input)
	cmpBytes = make([]byte, len(input))
	copy(cmpBytes, input)
	blocken.encrypt(input, input)
	blockde.decrypt(input, input)
	if bytes.Compare(input, cmpBytes) != 0 {
		t.Errorf("AES_CFB decrypt error:not compare")
	}
}
