package transport

import (
	"io"

	"github.com/klauspost/compress/snappy"
)

type CompStream struct {
	conn io.ReadWriteCloser
	w    *snappy.Writer
	r    *snappy.Reader
}

func NewCompStream(conn io.ReadWriteCloser) *CompStream {
	c := new(CompStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}
func (c *CompStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *CompStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	return n, err
}

func (c *CompStream) Close() error {
	return c.conn.Close()
}
