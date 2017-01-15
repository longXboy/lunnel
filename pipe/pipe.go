package pipe

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/xtaci/smux"
)

func NewPipe(conn net.Conn, ctl *Control) *Pipe {
	return &Pipe{pipeConn: conn, ctl: ctl}
}

type Pipe struct {
	pipeConn  net.Conn
	IsIdle    bool
	ctl       *Control
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

func (p *Pipe) Close() error {
	if p.sess == nil {
		return p.pipeConn.Close()
	} else {
		return p.sess.Close()
	}
}

func (p *Pipe) ClientHandShake() error {
	uuid := p.GeneratePipeID()
	var uuidm msg.PipeHandShake
	uuidm.PipeID = uuid
	uuidm.ClientID = p.ctl.ClientID
	err := msg.WriteMsg(p.pipeConn, msg.TypePipeHandShake, uuidm)
	if err != nil {
		return errors.Wrap(err, "write pipe handshake")
	}
	prf := crypto.NewPrf12()
	var masterKey []byte = make([]byte, 16)
	uuidmar := make([]byte, 16)
	for i := range uuidm.PipeID {
		uuidmar[i] = uuidm.PipeID[i]
	}
	fmt.Println("uuid:", uuidmar)

	prf(masterKey, p.ctl.preMasterSecret, []byte(fmt.Sprintf("%d", p.ctl.ClientID)), uuidmar)
	p.MasterKey = masterKey
	fmt.Println("masterKey:", masterKey)

	return nil
}
