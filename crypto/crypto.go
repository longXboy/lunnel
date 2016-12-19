package crypto

import (
	"bytes"
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

type exchangeMsg struct {
	raw        []byte
	ciphertext []byte
}

func (m *exchangeMsg) equal(i interface{}) bool {
	m1, ok := i.(*exchangeMsg)
	if !ok {
		return false
	}

	return bytes.Equal(m.raw, m1.raw) &&
		bytes.Equal(m.ciphertext, m1.ciphertext)
}

var typeClientKeyExchange uint8 = 16

func (m *exchangeMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}
	length := len(m.ciphertext)
	x := make([]byte, length+4)
	x[0] = typeClientKeyExchange
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	copy(x[4:], m.ciphertext)

	m.raw = x
	return x
}

func (m *exchangeMsg) unmarshal(data []byte) bool {
	m.raw = data
	if len(data) < 4 {
		return false
	}
	l := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if l != len(data)-4 {
		return false
	}
	m.ciphertext = data[4:]
	return true
}

func processClientKeyExchange(priv []byte, ckx *exchangeMsg) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, fmt.Errorf("error key exchange")
	}
	x, y := elliptic.Unmarshal(curveForCurveID(23), ckx.ciphertext[1:])
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

func generateClientKeyExChange() ([]byte, *exchangeMsg) {
	priv, mx, my, err := elliptic.GenerateKey(curveForCurveID(23), myRand())
	if err != nil {
		return nil, nil
	}
	serialized := elliptic.Marshal(curveForCurveID(23), mx, my)

	ckx := new(exchangeMsg)
	ckx.ciphertext = make([]byte, 1+len(serialized))
	ckx.ciphertext[0] = byte(len(serialized))
	copy(ckx.ciphertext[1:], serialized)
	return priv, ckx
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

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, section 5.
func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

func newPrf12() func(result, secret, label, seed []byte) {
	return prf12(sha256.New)
}

// randBytes uses crypto random to get random numbers. If fails then it uses math random.
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
