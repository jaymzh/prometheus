// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"time"
)

// redactedRequestHeaders lists headers whose values must never be printed
// verbatim by debugRoundTripper, since they carry credentials.
var redactedRequestHeaders = map[string]bool{
	"authorization":           true,
	"cf-access-token":         true,
	"cf-access-client-id":     true,
	"cf-access-client-secret": true,
	"proxy-authorization":     true,
}

// debugBodyPreviewLimit caps how many bytes of a response body debugRoundTripper prints.
const debugBodyPreviewLimit = 512

// debugRoundTripper prints outgoing requests and their responses to stderr,
// to help diagnose HTTP-level issues (wrong path, unexpected redirects,
// authentication failures, etc.). Credential-bearing headers are redacted.
//
// Header names and values are captured via httptrace.WroteHeaderField
// rather than read directly off the *http.Request, so that debugRoundTripper
// reports exactly what is written to the wire regardless of where in the
// RoundTripper chain it is placed relative to wrappers that add headers of
// their own, such as those built by promconfig.NewRoundTripperFromConfig or
// newCFAccessRoundTripper.
type debugRoundTripper struct {
	next http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (rt *debugRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Fprintf(os.Stderr, "--> %s %s\n", req.Method, req.URL)

	trace := &httptrace.ClientTrace{
		WroteHeaderField: func(key string, values []string) {
			fmt.Fprintf(os.Stderr, "    %s: %s\n", key, redactHeader(key, values))
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	start := time.Now()
	resp, err := rt.next.RoundTrip(req)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "<-- error after %s: %v\n", elapsed, err)
		return resp, err
	}

	fmt.Fprintf(os.Stderr, "<-- %s in %s (content-type: %s)\n", resp.Status, elapsed, resp.Header.Get("Content-Type"))

	if resp.Body != nil {
		preview := make([]byte, debugBodyPreviewLimit)
		n, _ := io.ReadFull(resp.Body, preview)
		resp.Body = &previewedBody{
			preview: preview[:n],
			rest:    resp.Body,
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "    body preview: %q\n", preview[:n])
		}
	}

	return resp, nil
}

// redactHeader returns a printable representation of an HTTP header's
// values, replacing the values of sensitive headers with a placeholder.
func redactHeader(name string, values []string) string {
	if redactedRequestHeaders[strings.ToLower(name)] {
		return "<redacted>"
	}
	return strings.Join(values, ", ")
}

// previewedBody re-assembles a response body after debugRoundTripper has
// peeked at its first bytes, so downstream consumers still see the full
// stream.
type previewedBody struct {
	preview []byte
	off     int
	rest    io.ReadCloser
}

// Read implements io.Reader.
func (b *previewedBody) Read(p []byte) (int, error) {
	if b.off < len(b.preview) {
		n := copy(p, b.preview[b.off:])
		b.off += n
		return n, nil
	}
	return b.rest.Read(p)
}

// Close implements io.Closer.
func (b *previewedBody) Close() error {
	return b.rest.Close()
}
