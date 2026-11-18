package javadb_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
)

// TestUpdateCanceled checks that Update returns once its context is done,
// while the registry has yet to answer.
func TestUpdateCanceled(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	repo, err := name.NewTag(strings.TrimPrefix(srv.URL, "http://") + "/trivy-java-db:1")
	require.NoError(t, err)
	javadb.Init(t.TempDir(), []name.Reference{repo}, false, true, ftypes.RegistryOptions{})
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- javadb.Update(ctx) }()
	select {
	case err := <-errc:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(10 * time.Second):
		t.Fatal("Update still running 10s after its context was done")
	}
}
