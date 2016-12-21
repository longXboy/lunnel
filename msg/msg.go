package msg

type MsgType uint8

const (
	TypeClientKeyExchange MsgType = 1
	TypeServerKeyExchange MsgType = 1
)

type KeyExchangeMsg struct {
	CipherText []byte
}
