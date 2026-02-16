package misconf

import (
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/xerrors"
)

type ConfigFileSchema struct {
	path   string
	name   string
	source []byte
	schema *gojsonschema.Schema
}

func LoadConfigSchemas(paths []string) ([]*ConfigFileSchema, error) {
	return nil, xerrors.New("pkg/misconf not implemented")
}
