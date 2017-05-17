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

func Test_EncryptDecryptBlock(t *testing.T) {
	key := make([]byte, 16)
	randBytes(key)

	buff := make([]byte, 6000)
	buff2 := make([]byte, 6000)
	for i := 0; i <= 6000; i++ {
		blocken, err := NewCryptoStream(nil, key)
		if err != nil {
			t.Errorf("NewAESBlockCrypt error:", err)
		}
		blockde, err := NewCryptoStream(nil, key)
		if err != nil {
			t.Errorf("NewAESBlockCrypt error:", err)
		}
		input := buff[:i]
		randBytes(input)
		cmpBytes := buff2[:i]
		copy(cmpBytes, input)
		blocken.encrypt(input, input)
		blockde.decrypt(input, input)
		if bytes.Compare(input, cmpBytes) != 0 {
			t.Fatalf("AES_CFB decrypt error:not compare")
		}
	}
}

func Test_EncryptDecryptStream(t *testing.T) {
	key := make([]byte, 16)
	randBytes(key)
	blocken, err := NewCryptoStream(nil, key)
	if err != nil {
		t.Errorf("NewAESBlockCrypt error:", err)
	}
	blockde, err := NewCryptoStream(nil, key)
	if err != nil {
		t.Errorf("NewAESBlockCrypt error:", err)
	}

	buff := make([]byte, 6000)
	buff2 := make([]byte, 6000)
	for i := 0; i <= 6000; i++ {
		input := buff[:i]
		randBytes(input)
		cmpBytes := buff2[:i]
		copy(cmpBytes, input)
		blocken.encrypt(input, input)
		blockde.decrypt(input, input)
		if bytes.Compare(input, cmpBytes) != 0 {
			t.Fatalf("AES_CFB decrypt error:not compare")
		}
	}
}
