package control

import (
	"Lunnel/kcp"
	"fmt"
	"net"

	"github.com/pkg/errors"
)

func CreateConn(addr string, noComp bool) (net.Conn, error) {
	fmt.Println("open conn:", addr)
	kcpconn, err := kcp.Dial(addr)
	if err != nil {
		return nil, errors.Wrap(err, "kcp dial")
	}
	return kcpconn, nil
}
