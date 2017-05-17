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
	temp      []byte
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
	c.block.Encrypt(c.encbuf, c.encbuf)

	c.decbuf = make([]byte, block.BlockSize())
	copy(c.decbuf, initialVector[:block.BlockSize()])
	c.block.Encrypt(c.decbuf, c.decbuf)

	c.temp = make([]byte, block.BlockSize())
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
		size := c.blockSize - c.encNum
		if size > len(src) {
			size = len(src)
		}
		xorBytes(dst[0:size], src[0:size], c.encbuf[c.encNum:c.encNum+size])
		copy(c.encbuf[c.encNum:c.encNum+size], dst[0:size])
		base += size
		c.encNum = c.encNum + size
		if c.encNum == c.blockSize {
			c.encNum = 0
			c.block.Encrypt(c.encbuf, c.encbuf)
		}
	}

	for ; (base + c.blockSize) <= len(src); base += c.blockSize {
		xorWords(dst[base:base+c.blockSize], src[base:base+c.blockSize], c.encbuf)
		c.block.Encrypt(c.encbuf, dst[base:base+c.blockSize])
	}

	//encrypt the remained bytes
	if base < len(src) {
		size := len(src) - base
		xorBytes(dst[base:base+size], src[base:base+size], c.encbuf[c.encNum:c.encNum+size])
		copy(c.encbuf[c.encNum:c.encNum+size], dst[base:base+size])
		c.encNum = c.encNum + size
		if c.encNum == c.blockSize {
			c.encNum = 0
			c.block.Encrypt(c.encbuf, c.encbuf)
		}
	}
}

func (c *cryptoStream) decrypt(dst, src []byte) {
	base := 0

	if c.decNum != 0 || len(src) < c.blockSize {
		size := c.blockSize - c.decNum
		if size > len(src) {
			size = len(src)
		}
		copy(c.temp[:size], src[:size])
		xorBytes(dst[:size], src[:size], c.decbuf[c.decNum:c.decNum+size])
		copy(c.decbuf[c.decNum:c.decNum+size], c.temp[:size])
		base += size
		c.decNum = c.decNum + size
		if c.decNum == c.blockSize {
			c.decNum = 0
			c.block.Encrypt(c.decbuf, c.decbuf)
		}
	}

	for ; (base + c.blockSize) <= len(src); base += c.blockSize {
		//we must copy src to temp first,in case of dst and src point to the same memory address
		copy(c.temp, src[base:base+c.blockSize])
		xorWords(dst[base:base+c.blockSize], src[base:base+c.blockSize], c.decbuf)
		c.block.Encrypt(c.decbuf, c.temp)
	}

	//decrypt the remained bytes
	if base < len(src) {
		size := len(src) - base
		copy(c.temp[:size], src[base:base+size])
		xorBytes(dst[base:base+size], src[base:base+size], c.decbuf[c.decNum:c.decNum+size])
		copy(c.decbuf[c.decNum:c.decNum+size], c.temp[:size])
		c.decNum = c.decNum + size
		if c.decNum == c.blockSize {
			c.decNum = 0
			c.block.Encrypt(c.decbuf, c.decbuf)
		}
	}
}
