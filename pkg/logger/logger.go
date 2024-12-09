package logger

import (
	"github.com/sirupsen/logrus"
)

var L Logger

func SetLogger(logger Logger) {
	L = logger
}

type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
}

func init() {
	l := logrus.New()
	l.SetReportCaller(true)

	L = Logger(l)
}
