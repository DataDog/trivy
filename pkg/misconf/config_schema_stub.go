package misconf

import (
	"golang.org/x/xerrors"
)

type ConfigFileSchema struct {
	path   string
	name   string
	source []byte
}

func LoadConfigSchemas(paths []string) ([]*ConfigFileSchema, error) {
	return nil, xerrors.New("pkg/misconf not implemented")
}
