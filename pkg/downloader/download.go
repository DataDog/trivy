package downloader

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

var ErrSkipDownload = errors.New("skip download")

type Options struct {
	Insecure bool
	Auth     Auth
	ETag     string
}

type Auth struct {
	Username string
	Password string
	Token    string
}

// DownloadToTempDir downloads the configured source to a temp dir.
func DownloadToTempDir(ctx context.Context, src string, opts Options) (string, error) {
	tempDir, err := os.MkdirTemp("", "trivy-download")
	if err != nil {
		return "", xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return "", xerrors.Errorf("unable to get the current dir: %w", err)
	}

	if _, err = Download(ctx, src, tempDir, pwd, opts); err != nil {
		return "", xerrors.Errorf("download error: %w", err)
	}

	return tempDir, nil
}

// Download downloads the configured source to the destination.
func Download(ctx context.Context, src, dst, pwd string, opts Options) (string, error) {
	var rc io.ReadCloser

	u, err := url.ParseRequestURI(src)
	if err != nil {
		return "", xerrors.Errorf("failed to parse url: %w", err)
	}
	if u.Scheme != "" {
		insecure := false
		if opts.Insecure {
			insecure = true
		}
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		}
		client := &http.Client{Transport: tr}
		resp, err := client.Get(src)
		if err != nil {
			return "", xerrors.Errorf("failed to get: %w", err)
		}
		rc = resp.Body
	} else {
		f, err := os.Open(src)
		if err != nil {
			return "", xerrors.Errorf("failed to open: %w", err)
		}
		rc = f
	}
	defer rc.Close()

	r, err := uncompress(rc, src)
	if err != nil {
		return "", xerrors.Errorf("failed to uncompress: %w", err)
	}

	err = Untar(r, dst)
	if err != nil {
		return "", xerrors.Errorf("failed to untar: %w", err)
	}

	return "", nil
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
