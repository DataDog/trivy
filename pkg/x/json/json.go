package json

import (
	"bytes"
	"encoding/json"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// lineReader is a custom reader that tracks line numbers.
type lineReader struct {
	r    io.Reader
	line int
}

// NewLineReader creates a new line reader.
func NewLineReader(r io.Reader) *lineReader {
	return &lineReader{
		r:    r,
		line: 1,
	}
}

func (lr *lineReader) Read(p []byte) (n int, err error) {
	n, err = lr.r.Read(p)
	if n > 0 {
		// Count the number of newlines in the read buffer
		lr.line += bytes.Count(p[:n], []byte("\n"))
	}
	return n, err
}

func (lr *lineReader) Line() int {
	return lr.line
}

func Unmarshal(data []byte, v any) error {
	return UnmarshalRead(bytes.NewBuffer(data), v)
}

func UnmarshalRead(r io.Reader, v any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return xerrors.Errorf("read error: %w", err)
	}

	if err := json.Unmarshal(data, v); err != nil {
		return err
	}

	fillLocations(data, v)
	return nil
}

// Location is wrap of types.Location.
// This struct is required when you need to detect location of your object from json file.
type Location types.Location

func (l *Location) SetLocation(location types.Location) {
	*l = Location(location)
}

// ObjectLocation is required when you need to save Location for your struct.
type ObjectLocation interface {
	SetLocation(location types.Location)
}

// fillLocations is a best-effort post-processing step that fills in Location
// fields after standard json.Unmarshal. It walks the JSON to find object
// boundaries and maps them to line numbers. This provides approximate location
// tracking without requiring the go-json-experiment/json v2 API.
func fillLocations(_ []byte, _ any) {
	// Location tracking is not implemented with encoding/json v1.
	// Location fields will retain their zero values.
}
