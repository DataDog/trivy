package misconf

import (
	"golang.org/x/xerrors"
)

type ConfigFileSchema struct{}

func LoadConfigSchemas(_ []string) ([]*ConfigFileSchema, error) {
	return nil, xerrors.New("pkg/misconf not implemented")
}
