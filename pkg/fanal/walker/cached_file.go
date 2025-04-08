package walker

import (
	"bytes"
	"io"
	"os"
	"sync"

	"golang.org/x/xerrors"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// cachedFile represents a file cached in memory or storage according to the file size.
type cachedFile struct {
	once sync.Once
	err  error

	size   int64
	reader io.Reader

	content  []byte // It will be populated if this file is small
	filePath string // It will be populated if this file is large
}

func newCachedFile(size int64, r io.Reader) *cachedFile {
	return &cachedFile{
		size:   size,
		reader: r,
	}
}

// Open opens a file and cache the file.
// If the file size is greater than or equal to threshold, it copies the content to a temp file and opens it next time.
// If the file size is less than threshold, it opens the file once and the content will be shared so that others analyzers can use the same data.
func (o *cachedFile) Open() (xio.ReadSeekCloserAt, error) {
	o.once.Do(func() {
		// When the file is large, it will be written down to a temp file.
		if o.size >= defaultSizeThreshold {
			f, err := os.CreateTemp("", "fanal-*")
			if err != nil {
				o.err = xerrors.Errorf("failed to create the temp file: %w", err)
				return
			}

			if _, err = io.Copy(f, o.reader); err != nil {
				o.err = xerrors.Errorf("failed to copy: %w", err)
				return
			}

			o.filePath = f.Name()
		} else {
			b := make([]byte, o.size)
			_, err := readAll(o.reader, b)
			if err != nil {
				o.err = xerrors.Errorf("unable to read the file: %w", err)
				return
			}
			o.content = b
		}
	})
	if o.err != nil {
		return nil, xerrors.Errorf("failed to open: %w", o.err)
	}

	return o.open()
}

func (o *cachedFile) open() (xio.ReadSeekCloserAt, error) {
	if o.filePath != "" {
		f, err := os.Open(o.filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open the temp file: %w", err)
		}
		return f, nil
	}

	return xio.NopCloser(bytes.NewReader(o.content)), nil
}

func (o *cachedFile) Clean() error {
	return os.Remove(o.filePath)
}

// readAll works like io.ReadAll, except it takes a pre-allocated buffer. Useful
// in our case when we know in advance the expected size of the reader content.
func readAll(r io.Reader, b []byte) ([]byte, error) {
	for {
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}

		if len(b) == cap(b) {
			// Add more capacity (let append pick how much).
			b = append(b, 0)[:len(b)]
		}
	}
}
