package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
)

var initialVector = []byte{167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}

type cryptoConn struct {
	rawConn net.Conn
	encbuf  []byte
	decbuf  []byte
	encNum  int
	decNum  int
	block   cipher.Block
}

func NewCryptoConn(conn net.Conn, key []byte) (*cryptoConn, error) {
	c := new(cryptoConn)
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

func (c *cryptoConn) Read(b []byte) (n int, err error) {
	nRead, err := c.rawConn.Read(b)
	if err != nil {
		return nRead, err
	}
	c.decrypt(b[:nRead], b[:nRead])
	return nRead, nil
}

func (c *cryptoConn) Write(b []byte) (n int, err error) {
	c.encrypt(b, b)
	return c.rawConn.Write(b)
}

func (c *cryptoConn) Close() error {
	return c.rawConn.Close()
}

func (c *cryptoConn) encrypt(dst, src []byte) {
	encrypt(c.block, dst, src, c.encbuf, &c.encNum)
}

func (c *cryptoConn) decrypt(dst, src []byte) {
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
