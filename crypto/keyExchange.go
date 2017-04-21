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
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	mrand "math/rand"
	"time"
)

type CurveID int

const (
	CurveP256 CurveID = 23
	CurveP384 CurveID = 24
	CurveP521 CurveID = 25
)

func myRand() io.Reader {
	return crand.Reader
}

func curveForCurveID(id CurveID) elliptic.Curve {
	switch id {
	case CurveP256:
		return elliptic.P256()
	case CurveP384:
		return elliptic.P384()
	case CurveP521:
		return elliptic.P521()
	default:
		return nil
	}
}

func ProcessKeyExchange(priv []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || int(ciphertext[0]) != len(ciphertext)-1 {
		return nil, fmt.Errorf("error key exchange")
	}
	x, y := elliptic.Unmarshal(curveForCurveID(23), ciphertext[1:])
	if x == nil {
		return nil, fmt.Errorf("error key exchange")
	}
	if !curveForCurveID(23).IsOnCurve(x, y) {
		return nil, fmt.Errorf("error key exchange")
	}
	x, _ = curveForCurveID(23).ScalarMult(x, y, priv)
	preMasterSecret := make([]byte, (curveForCurveID(23).Params().BitSize+7)>>3)
	xBytes := x.Bytes()
	copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

	return preMasterSecret, nil
}

func GenerateKeyExChange() ([]byte, []byte) {
	priv, mx, my, err := elliptic.GenerateKey(curveForCurveID(23), myRand())
	if err != nil {
		return nil, nil
	}
	serialized := elliptic.Marshal(curveForCurveID(23), mx, my)

	ciphertext := make([]byte, 1+len(serialized))
	ciphertext[0] = byte(len(serialized))
	copy(ciphertext[1:], serialized)
	return priv, ciphertext
}

// pHash implements the P_hash function, as defined in RFC 4346, section 5.
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

func NewPrf12() func(result, secret, label, seed []byte) {
	return prf12(sha256.New)
}

func randBytes(x []byte) {
	length := len(x)
	n, err := crand.Read(x)

	if n != length || err != nil {
		mrand.Seed(time.Now().UnixNano())

		for length > 0 {
			length--
			x[length] = byte(mrand.Int31n(256))
		}
	}
}
