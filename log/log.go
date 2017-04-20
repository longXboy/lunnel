package log

import (
	"errors"
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/getsentry/raven-go"
)

func Init(isDebug bool, fileWriter *os.File) {
	if isDebug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	if fileWriter != nil {
		logrus.SetOutput(fileWriter)
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetOutput(os.Stdout)
		logrus.SetFormatter(&logrus.TextFormatter{})
	}
}

type Fields map[string]interface{}

type Entry struct {
	entry *logrus.Entry
}

func (e *Entry) Infoln(args ...interface{}) {
	e.entry.Infoln(args...)
}

func (e *Entry) Debugln(args ...interface{}) {
	e.entry.Debugln(args...)
}

func (e *Entry) Errorln(args ...interface{}) {
	m := make(map[string]string)
	for k, v := range e.entry.Data {
		m[k] = fmt.Sprintf("%v", v)
	}
	raven.CaptureError(errors.New(fmt.Sprintln(args...)), m)
	e.entry.Errorln(args...)
}

func (e *Entry) Fatalln(args ...interface{}) {
	e.entry.Fatalln(args...)
}

func (e *Entry) Warningln(args ...interface{}) {
	m := make(map[string]string)
	for k, v := range e.entry.Data {
		m[k] = fmt.Sprintf("%v", v)
	}

	raven.CaptureMessage(fmt.Sprintln(args...), m)
	e.entry.Warningln(args...)
}

func (e *Entry) Warnln(args ...interface{}) {
	m := make(map[string]string)
	for k, v := range e.entry.Data {
		m[k] = fmt.Sprintf("%v", v)
	}

	raven.CaptureMessage(fmt.Sprintln(args...), m)
	e.entry.Warnln(args...)
}

func WithField(key string, value interface{}) *Entry {
	return &Entry{logrus.WithField(key, value)}
}

func WithFields(fields Fields) *Entry {
	entry := Entry{logrus.WithFields(logrus.Fields(fields))}
	return &entry
}

func Infoln(args ...interface{}) {
	logrus.Infoln(args...)
}

func Debugln(args ...interface{}) {
	logrus.Debugln(args...)
}
func Errorln(args ...interface{}) {
	raven.CaptureError(errors.New(fmt.Sprintln(args...)), nil)
	logrus.Errorln(args...)
}
func Fatalln(args ...interface{}) {
	logrus.Fatalln(args...)
}

func Warnln(args ...interface{}) {
	logrus.Warnln(args...)
}
func Warningln(args ...interface{}) {
	logrus.Warningln(args...)
}
