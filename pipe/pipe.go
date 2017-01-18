package pipe

import (
	"Lunnel/crypto"
	"net"

	"github.com/xtaci/smux"
)

func NewPipe(conn net.Conn) *Pipe {
	return &Pipe{pipeConn: conn}
}

type Pipe struct {
	pipeConn  net.Conn
	IsIdle    bool
	sess      *smux.Session
	MasterKey []byte
	ID        crypto.UUID
}

func (p *Pipe) SetSess(s *smux.Session) {
	p.sess = s
}
func (p *Pipe) StreamsNum() int {
	return p.sess.NumStreams()
}
func (p *Pipe) GetStream(tunnel string) (*smux.Stream, error) {
	return p.sess.OpenStream(tunnel)
}

func (p *Pipe) GeneratePipeID() crypto.UUID {
	p.ID = crypto.GenUUID()
	return p.ID
}

func (p *Pipe) IsClosed() bool {
	return p.sess.IsClosed()
}

func (p *Pipe) Close() error {

	return p.sess.Close()
}
