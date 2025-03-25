package walker

import (
	"bytes"
	"io"
	"os"
	"sync"

	"golang.org/x/xerrors"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var cachedFileBufPool = sync.Pool{
	New: func() interface{} {
		const cachedFileBufPoolSize = 256 * 1024
		b := make([]byte, cachedFileBufPoolSize)
		return &b // classic pointer trick to avoid keep interface stack-allocated
	},
}

// cachedFile represents a file cached in memory or storage according to the file size.
type cachedFile struct {
	once sync.Once
	err  error

	size   int64
	reader io.Reader

	content  []byte // It will be populated if this file is small, or used as copy buffer if this file is large
	filePath string // It will be populated if this file is large
}

func newCachedFile(size int64, r io.Reader) *cachedFile {
	content := *cachedFileBufPool.Get().(*[]byte)
	if size >= defaultSizeThreshold {
		content = content[:cap(content)]
	} else {
		if cap(content) < int(size) {
			content = make([]byte, size)
		}
		content = content[:size]
	}
	return &cachedFile{
		reader:  r,
		size:    size,
		content: content,
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

			// HACK: anonymous struct hack to actually reuse the buffer passed to
			// CopyBuffer. Without this, the CopyBuffer will rely on os.genericReadFrom
			// which will not reuse our buffer.
			// ref: https://github.com/golang/go/issues/16474
			if _, err = io.CopyBuffer(struct{ io.Writer }{f}, o.reader, o.content); err != nil {
				o.err = xerrors.Errorf("failed to copy: %w", err)
				return
			}
			o.filePath = f.Name()
		} else {
			_, err := io.ReadFull(o.reader, o.content)
			if err != nil {
				o.err = xerrors.Errorf("unable to read the file: %w", err)
				return
			}
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
	cachedFileBufPool.Put(&o.content)
	return os.Remove(o.filePath)
}
