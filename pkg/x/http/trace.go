package http

import "net/http"

// NewTraceTransport returns the underlying transport unchanged. The full HTTP
// tracing functionality (with secret scrubbing) has been stripped from this
// build to avoid linking the secret-scanning package in agent binaries.
func NewTraceTransport(rt http.RoundTripper) http.RoundTripper {
	return rt
}
