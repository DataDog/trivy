package downloader

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

// DownloadToTempDir downloads the configured source to a temp dir.
func DownloadToTempDir(ctx context.Context, url string) (string, error) {
	tempDir, err := os.MkdirTemp("", "trivy-plugin")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return "", xerrors.Errorf("unable to get the current dir: %w", err)
	}

	if err = Download(ctx, url, tempDir, pwd); err != nil {
		return "", xerrors.Errorf("download error: %w", err)
	}

	return tempDir, nil
}

// Download downloads the configured source to the destination.
func Download(ctx context.Context, src, dst, pwd string) error {
	var rc io.ReadCloser

	u, err := url.ParseRequestURI(src)
	if err != nil {
		return xerrors.Errorf("failed to parse url: %w", err)
	}
	if u.Scheme != "" {
		resp, err := http.Get(src)
		if err != nil {
			return xerrors.Errorf("failed to get: %w", err)
		}
		rc = resp.Body
	} else {
		f, err := os.Open(src)
		if err != nil {
			return xerrors.Errorf("failed to open: %w", err)
		}
		rc = f
	}
	defer rc.Close()

	r, err := uncompress(rc, src)
	if err != nil {
		return xerrors.Errorf("failed to uncompress: %w", err)
	}

	err = Untar(r, dst)
	if err != nil {
		return xerrors.Errorf("failed to untar: %w", err)
	}

	return nil
}

func uncompress(r io.Reader, name string) (io.Reader, error) {
	switch filepath.Ext(name) {
	case ".bz2":
		return bzip2.NewReader(r), nil
	case ".gz":
		return gzip.NewReader(r)
	}
	return r, nil
}
