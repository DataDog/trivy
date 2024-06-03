package downloader

import (
	"cmp"
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
	"strings"

	"github.com/google/go-github/v62/github"
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

type CustomTransport struct {
	auth       Auth
	cachedETag string
	newETag    string
	insecure   bool
}

func NewCustomTransport(opts Options) *CustomTransport {
	return &CustomTransport{
		auth:       opts.Auth,
		cachedETag: opts.ETag,
		insecure:   opts.Insecure,
	}
}

func (t *CustomTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.cachedETag != "" {
		req.Header.Set("If-None-Match", t.cachedETag)
	}
	if t.auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.auth.Token)
	} else if t.auth.Username != "" || t.auth.Password != "" {
		req.SetBasicAuth(t.auth.Username, t.auth.Password)
	}

	var transport http.RoundTripper
	if req.URL.Host == "github.com" {
		transport = NewGitHubTransport(req.URL, t.insecure, t.auth.Token)
	}
	if transport == nil {
		transport = httpTransport(t.insecure)
	}

	res, err := transport.RoundTrip(req)
	if err != nil {
		return nil, xerrors.Errorf("failed to round trip: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		// Update the ETag
		t.newETag = res.Header.Get("ETag")
	case http.StatusNotModified:
		return nil, ErrSkipDownload
	}

	return res, nil
}

func NewGitHubTransport(u *url.URL, insecure bool, token string) http.RoundTripper {
	client := newGitHubClient(insecure, token)
	ss := strings.SplitN(u.Path, "/", 4)
	if len(ss) < 4 || strings.HasPrefix(ss[3], "archive/") || strings.HasPrefix(ss[3], "releases/") ||
		strings.HasPrefix(ss[3], "tags/") {
		// Use the default transport from go-github for authentication
		return client.Client().Transport
	}

	return &GitHubContentTransport{
		owner:    ss[1],
		repo:     ss[2],
		filePath: ss[3],
		client:   client,
	}
}

// GitHubContentTransport is a round tripper for downloading the GitHub content.
type GitHubContentTransport struct {
	owner    string
	repo     string
	filePath string
	client   *github.Client
}

// RoundTrip calls the GitHub API to download the content.
func (t *GitHubContentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	_, res, err := t.client.Repositories.DownloadContents(req.Context(), t.owner, t.repo, t.filePath, nil)
	if err != nil {
		return nil, xerrors.Errorf("failed to get the file content: %w", err)
	}
	return res.Response, nil
}

func newGitHubClient(insecure bool, token string) *github.Client {
	client := github.NewClient(&http.Client{Transport: httpTransport(insecure)})
	token = cmp.Or(token, os.Getenv("GITHUB_TOKEN"))
	if token != "" {
		client = client.WithAuthToken(token)
	}
	return client
}

func httpTransport(insecure bool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure}
	return tr
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
