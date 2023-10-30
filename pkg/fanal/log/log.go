package log

import (
	"go.uber.org/zap"
)

var Logger = NewLazyLogger(func() (*zap.SugaredLogger, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
})

func SetLogger(l *zap.SugaredLogger) {
	Logger = NewLazyLogger(func() (*zap.SugaredLogger, error) { return l, nil })
}
