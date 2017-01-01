package msg

import (
	"Lunnel/crypto"
)

type MsgType uint8

const (
	TypeClientKeyExchange MsgType = 1
	TypeServerKeyExchange MsgType = 2
	TypeClientIdGenerate          = 3
	TypePipeHandShake             = 4
)

type KeyExchangeMsg struct {
	CipherText []byte
}

type ClientIdGenerate struct {
	ClientID uint64
}

type PipeHandShake struct {
	PipeID   crypto.UUID
	ClientID uint64
}
