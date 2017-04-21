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
	"crypto/aes"
	"crypto/cipher"
	"io"
)

var initialVector = []byte{55, 33, 111, 156, 18, 172, 34, 2, 164, 99, 252, 122, 252, 133, 12, 55}

type cryptoStream struct {
	rawConn io.ReadWriteCloser
	encbuf  []byte
	decbuf  []byte
	encNum  int
	decNum  int
	block   cipher.Block
}

func NewCryptoStream(conn io.ReadWriteCloser, key []byte) (*cryptoStream, error) {
	c := new(cryptoStream)
	c.rawConn = conn
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, block.BlockSize())
	copy(c.encbuf, initialVector[:block.BlockSize()])
	c.decbuf = make([]byte, block.BlockSize())
	copy(c.decbuf, initialVector[:block.BlockSize()])
	return c, nil
}

func (c *cryptoStream) Read(b []byte) (n int, err error) {
	nRead, err := c.rawConn.Read(b)
	if err != nil {
		return nRead, err
	}
	c.decrypt(b[:nRead], b[:nRead])
	return nRead, nil
}

func (c *cryptoStream) Write(b []byte) (n int, err error) {
	c.encrypt(b, b)
	return c.rawConn.Write(b)
}

func (c *cryptoStream) Close() error {
	return c.rawConn.Close()
}

func (c *cryptoStream) encrypt(dst, src []byte) {
	encrypt(c.block, dst, src, c.encbuf, &c.encNum)
}

func (c *cryptoStream) decrypt(dst, src []byte) {
	decrypt(c.block, dst, src, c.decbuf, &c.decNum)
}

//http://blog.csdn.net/charleslei/article/details/48710293
func encrypt(block cipher.Block, dst, src, ivec []byte, num *int) {
	n := *num
	for l := 0; l < len(src); l++ {
		if n == 0 {
			block.Encrypt(ivec, ivec)
		}
		ivec[n] ^= src[l]
		dst[l] = ivec[n]
		n = (n + 1) % block.BlockSize()
	}
	*num = n
}

func decrypt(block cipher.Block, dst, src, ivec []byte, num *int) {
	n := *num
	for l := 0; l < len(src); l++ {
		var c byte
		if n == 0 {
			block.Encrypt(ivec, ivec)
		}
		c = src[l]
		dst[l] = ivec[n] ^ c
		ivec[n] = c
		n = (n + 1) % block.BlockSize()
	}
	*num = n
}
