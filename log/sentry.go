package log

import (
	"errors"
	"fmt"
	"runtime/debug"

	"github.com/getsentry/raven-go"
)

func CapturePanic() {
	if rval := recover(); rval != nil {
		debug.PrintStack()
		rvalStr := fmt.Sprint(rval)
		packet := raven.NewPacket(rvalStr, raven.NewException(errors.New(rvalStr), raven.NewStacktrace(2, 3, nil)))
		raven.Capture(packet, nil)
	}
}
