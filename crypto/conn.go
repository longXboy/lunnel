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

var initialVector = []byte{55, 33, 111, 156, 18, 172, 34, 2, 164, 99, 252, 122, 252, 133, 12, 90, 167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}

type cryptoStream struct {
	rawConn   io.ReadWriteCloser
	encbuf    []byte
	decbuf    []byte
	encNum    int
	decNum    int
	block     cipher.Block
	blockSize int
}

func NewCryptoStream(conn io.ReadWriteCloser, key []byte) (*cryptoStream, error) {
	c := new(cryptoStream)
	c.rawConn = conn
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.blockSize = block.BlockSize()
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

//http://blog.csdn.net/charleslei/article/details/48710293
func (c *cryptoStream) encrypt(dst, src []byte) {
	base := 0
	if c.encNum != 0 || len(src) < c.blockSize {
		if c.encNum == 0 {
			c.block.Encrypt(c.encbuf, c.encbuf)
		}
		for ; base < c.blockSize-c.encNum && base < len(src); base++ {
			c.encbuf[c.encNum] ^= src[base]
			dst[base] = c.encbuf[c.encNum]
			c.encNum++
		}
		c.encNum = c.encNum % 16
	}

	for ; (base + c.blockSize) < len(src); base += c.blockSize {
		if c.encNum == 0 {
			c.block.Encrypt(c.encbuf, c.encbuf)
		}
		xorWords(dst[base:], src[base:], c.encbuf)
		copy(c.encbuf, dst[base:base+c.blockSize])
		c.encNum = 0
	}

	if base < len(src) {
		if c.encNum == 0 {
			c.block.Encrypt(c.encbuf, c.encbuf)
		}
		for ; base < c.blockSize-c.encNum && base < len(src); base++ {
			c.encbuf[c.encNum] ^= src[base]
			dst[base] = c.encbuf[c.encNum]
			c.encNum++
		}
		c.encNum = c.encNum % 16
	}
}

func (c *cryptoStream) decrypt(dst, src []byte) {
	decrypt(c.block, dst, src, c.decbuf, &c.decNum)
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
