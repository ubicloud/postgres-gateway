package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// route is what the control plane knows about a cell endpoint.
type route struct {
	CellID    string `json:"cell_id"`
	State     string `json:"state"`
	TargetIP6 string `json:"target_ip6"`
	Port      int    `json:"port"`

	// UpstreamTLS asks for a second TLS session to the cell, verified
	// against the cell root CA with CertCN as the expected common name.
	//
	// The default is off: the cell runs PostgreSQL without ssl and the hop
	// is encrypted below PostgreSQL instead. That is deliberate. A
	// TLS-terminating gateway cannot satisfy SCRAM channel binding — the
	// client binds to the gateway's certificate and the cell verifies
	// against its own — so with ssl on in the cell every default libpq
	// connection fails. Opting in is explicit so that the secure-looking
	// setting cannot be reached by accident, and so that the transport can be
	// switched back per cell if the gateway ever terminates SCRAM itself.
	UpstreamTLS bool   `json:"upstream_tls"`
	CertCN      string `json:"cert_cn"`
}

func (r *route) addr() string {
	return net.JoinHostPort(r.TargetIP6, fmt.Sprint(r.Port))
}

func (r *route) running() bool { return r.State == "running" }

// activityReport is the per-cell usage the control plane needs for idle
// detection (design doc 7.4).
type activityReport struct {
	CellID         string    `json:"cell_id"`
	LastActivityAt time.Time `json:"last_activity_at"`
	Connections    int       `json:"connections"`
	Bytes          int64     `json:"bytes"`
}

// errCellStarting means the cell is not ready yet and the client should
// retry, rather than that anything is broken.
type errCellStarting struct{ cellID string }

func (e *errCellStarting) Error() string {
	return "cell " + e.cellID + " is still starting"
}

// errNoSuchCell means the SNI host did not resolve.
type errNoSuchCell struct{ host string }

func (e *errNoSuchCell) Error() string { return "no cell for " + e.host }

type controlPlane interface {
	lookup(ctx context.Context, host string) (*route, error)
	resume(ctx context.Context, cellID string) (*route, error)
	// reportActivity sends the window's activity and the hosts still in the
	// route cache, and returns the ones the control plane says are stale.
	reportActivity(ctx context.Context, reports []activityReport, cached []string) ([]string, error)
}

// httpControlPlane talks to the control plane's internal endpoints.
type httpControlPlane struct {
	baseURL string
	secret  []byte
	client  *http.Client
}

func newHTTPControlPlane(baseURL string, secret []byte, timeout time.Duration) *httpControlPlane {
	return &httpControlPlane{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		secret:  secret,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (c *httpControlPlane) lookup(ctx context.Context, host string) (*route, error) {
	var r route
	status, err := c.do(ctx, http.MethodGet,
		"/internal/cell/route?host="+url.QueryEscape(host), nil, &r)
	switch {
	case err != nil:
		return nil, err
	case status == http.StatusNotFound:
		return nil, &errNoSuchCell{host: host}
	case status != http.StatusOK:
		return nil, fmt.Errorf("route lookup for %q returned %d", host, status)
	}
	return &r, nil
}

func (c *httpControlPlane) resume(ctx context.Context, cellID string) (*route, error) {
	var r route
	status, err := c.do(ctx, http.MethodPost,
		"/internal/cell/"+url.PathEscape(cellID)+"/resume", nil, &r)
	switch {
	case err != nil:
		return nil, err
	// The control plane answers 503 while a resume is still in progress; that
	// is a retry, not a failure.
	case status == http.StatusServiceUnavailable:
		return nil, &errCellStarting{cellID: cellID}
	case status == http.StatusNotFound:
		return nil, &errNoSuchCell{host: cellID}
	case status != http.StatusOK && status != http.StatusCreated:
		return nil, fmt.Errorf("resume of %q returned %d", cellID, status)
	}
	return &r, nil
}

func (c *httpControlPlane) reportActivity(ctx context.Context, reports []activityReport, cached []string) ([]string, error) {
	if len(reports) == 0 && len(cached) == 0 {
		return nil, nil
	}
	body := activityRequest{Reports: reports, Cached: cached}
	var out struct {
		Invalidate []string `json:"invalidate"`
	}
	status, err := c.do(ctx, http.MethodPost, "/internal/gateway/activity", body, &out)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, fmt.Errorf("activity report returned %d", status)
	}
	return out.Invalidate, nil
}

// activityRequest carries the window's reports and, with them, the hosts this
// gateway still has cached.
//
// The cached list is how a pause reaches the gateway at all. The admin port
// that would take an invalidation is bound to localhost, so the control plane
// cannot push one; this is the only channel that already runs in the right
// direction, and it runs on a timer the gateway controls.
type activityRequest struct {
	Reports []activityReport `json:"reports"`
	Cached  []string         `json:"cached"`
}

func (c *httpControlPlane) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+mintJWT(c.secret, time.Now()))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	if out != nil && res.StatusCode >= 200 && res.StatusCode < 300 {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			return res.StatusCode, fmt.Errorf("decoding response: %w", err)
		}
	} else {
		_, _ = io.Copy(io.Discard, res.Body)
	}
	return res.StatusCode, nil
}

// mintJWT builds a short-lived HS256 token. Hand-rolled to keep this binary
// dependency-free, as cli/ubi is.
func mintJWT(secret []byte, now time.Time) string {
	encode := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := encode(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload := encode(map[string]any{
		"iss": "postgres-gateway",
		"iat": now.Unix(),
		"exp": now.Add(60 * time.Second).Unix(),
	})
	signing := header + "." + payload
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
