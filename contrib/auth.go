package contrib

import (
	"github.com/longXboy/lunnel/msg"
)

func InitAuth(authUrl string) error {
	return nil
}

func Auth(chello *msg.ControlClientHello) (bool, error) {
	return true, nil
}
