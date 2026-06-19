package engine

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxBodyBytes bounds the HTTP body the detector reads when matching a provider
// fingerprint. Provider "unclaimed" strings live in small error pages; 1 MiB is
// ample and bounds memory against a hostile server.
const maxBodyBytes = 1 << 20 // 1 MiB

// engineTransport is shared by the engine's body fetcher. InsecureSkipVerify is
// deliberate (see pkg/detectors): a dangling/unclaimed edge characteristically
// serves a certificate that does not match the probed host, and the detector
// must still read the body fingerprint behind it. This is a recon probe.
var engineTransport = &http.Transport{
	ResponseHeaderTimeout: 8 * time.Second,
	TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // recon probe
}

// fetchBounded GETs host over HTTPS, falling back to HTTP on a transport-level
// failure, and returns a bounded prefix of the response body plus the winning
// scheme. A non-transport HTTP error (e.g. a 404 with a body) is NOT an error
// here — the body is exactly what carries the provider fingerprint.
func fetchBounded(ctx context.Context, host string) ([]byte, string, error) {
	try := func(scheme string) ([]byte, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host, nil)
		if err != nil {
			return nil, scheme, err
		}
		req.Header.Set("User-Agent", "graverobber/engine")
		client := &http.Client{Transport: engineTransport, Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, scheme, err
		}
		defer resp.Body.Close()
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		return body, scheme, rerr
	}

	body, scheme, err := try("https")
	if err == nil {
		return body, scheme, nil
	}
	if !isTransportError(err) {
		return body, scheme, err
	}
	return try("http")
}

// isTransportError reports whether err is a connection/TLS failure (warranting
// the HTTP fallback) rather than an HTTP-level error.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, m := range []string{"connection refused", "no such host", "i/o timeout", "tls:", "TLS", "EOF", "context deadline"} {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}
