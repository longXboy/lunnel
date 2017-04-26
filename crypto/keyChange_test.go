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

	prfunc := NewPrf12()
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
