// Copyright 2017 longXboy, longxboyhi@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"bytes"
	"testing"
)

func Test_aesEncryptDecrypt(t *testing.T) {
	blocken, err := NewCryptoStream(nil, []byte("0123456789abcdef"))
	if err != nil {
		t.Errorf("NewAESBlockCrypt error:", err)
	}
	blockde, err := NewCryptoStream(nil, []byte("0123456789abcdef"))
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
