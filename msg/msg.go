package msg

import (
	"Lunnel/crypto"
)

type MsgType uint8

const (
	TypeClientKeyExchange MsgType = 1
	TypeServerKeyExchange MsgType = 2
	TypeClientID          MsgType = 3
	TypePipeHandShake     MsgType = 4
)

type CipherKey []byte

type ClientID uint64

type PipeHandShake struct {
	PipeID   crypto.UUID
	ClientID uint64
}
