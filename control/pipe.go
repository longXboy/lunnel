package control

import (
	"Lunnel/crypto"
	"Lunnel/msg"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/xtaci/smux"
)

var maxStreams uint = 4
var maxIdleStreams uint = 2

func NewPipe(conn net.Conn, ctl *Control) *Pipe {
	return &Pipe{pipeConn: conn, ctl: ctl}
}

type Pipe struct {
	pipeConn   net.Conn
	ctl        *Control
	busy       []*smux.Stream
	idle       []*smux.Stream
	maxStreams uint64
	maxIdles   uint64
	sess       *smux.Session

	MasterKey []byte
	ID        crypto.UUID
}

func (p *Pipe) GetStream(tunnel string) (*smux.Stream, error) {
	return p.sess.OpenStream(tunnel)
}

func (p *Pipe) GeneratePipeID() crypto.UUID {
	p.ID = crypto.GenUUID()
	return p.ID
}

func (p *Pipe) Close() error {
	return p.pipeConn.Close()
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

	p.ctl.idleLock.Lock()
	p.ctl.idle = append(p.ctl.idle, p)
	p.ctl.idleLock.Unlock()
	return nil
}

func (p *Pipe) ServerHandShake() error {
	_, body, err := msg.ReadMsg(p.pipeConn)
	if err != nil {
		return errors.Wrap(err, "pipe readMsg")
	}
	h := body.(*msg.PipeHandShake)
	p.ID = h.PipeID

	ControlMapLock.RLock()
	ctl := ControlMap[h.ClientID]
	ControlMapLock.RUnlock()
	p.ctl = ctl

	prf := crypto.NewPrf12()
	var masterKey []byte = make([]byte, 16)
	uuid := make([]byte, 16)
	for i := range uuid {
		uuid[i] = h.PipeID[i]
	}
	fmt.Println("uuid:", uuid)
	prf(masterKey, ctl.preMasterSecret, []byte(fmt.Sprintf("%d", h.ClientID)), uuid)
	p.MasterKey = masterKey
	fmt.Println("masterKey:", masterKey)

	cryptoConn, err := crypto.NewCryptoConn(p.pipeConn, p.MasterKey)
	if err != nil {
		return errors.Wrap(err, "crypto.NewCryptoConn")
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.MaxReceiveBuffer = 4194304
	sess, err := smux.Client(cryptoConn, smuxConfig)
	if err != nil {
		return errors.Wrap(err, "smux.Client")
	}
	p.sess = sess
	p.ctl.idleLock.Lock()
	p.ctl.idle = append(p.ctl.idle, p)
	p.ctl.idleLock.Unlock()
	return nil
}
