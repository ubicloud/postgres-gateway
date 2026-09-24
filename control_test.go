package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMintJWTShape(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	token := mintJWT([]byte("secret"), now)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected three JWT segments, got %d", len(parts))
	}
	var header map[string]string
	decode(t, parts[0], &header)
	if header["alg"] != "HS256" {
		t.Errorf("alg = %q", header["alg"])
	}
	var payload map[string]any
	decode(t, parts[1], &payload)
	if payload["iat"].(float64) != float64(now.Unix()) {
		t.Errorf("iat = %v", payload["iat"])
	}
	// Short-lived, as the design requires of host and gateway tokens.
	if payload["exp"].(float64)-payload["iat"].(float64) > 60 {
		t.Errorf("token lifetime is too long: %v to %v", payload["iat"], payload["exp"])
	}
	if mintJWT([]byte("other"), now) == token {
		t.Error("a different secret produced the same signature")
	}
}

func decode(t *testing.T, segment string, out any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decoding %q: %v", segment, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("unmarshalling %q: %v", raw, err)
	}
}

func TestLookupSendsATokenAndParsesTheRoute(t *testing.T) {
	var gotAuth, gotHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotHost = r.URL.Query().Get("host")
		_ = json.NewEncoder(w).Encode(route{
			CellID: "sb1", State: "running", TargetIP6: "fd00::2", Port: 5432, CertCN: "sb1",
		})
	}))
	defer server.Close()

	cp := newHTTPControlPlane(server.URL, []byte("secret"), 5*time.Second)
	r, err := cp.lookup(context.Background(), "sb1.sb.test")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ey") {
		t.Errorf("Authorization = %q, expected a bearer JWT", gotAuth)
	}
	if gotHost != "sb1.sb.test" {
		t.Errorf("host = %q", gotHost)
	}
	if r.addr() != "[fd00::2]:5432" {
		t.Errorf("addr = %q", r.addr())
	}
	if !r.running() {
		t.Error("expected the route to be running")
	}
}

func TestLookupMapsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cp := newHTTPControlPlane(server.URL, []byte("secret"), 5*time.Second)
	_, err := cp.lookup(context.Background(), "nope")
	var missing *errNoSuchCell
	if !errors.As(err, &missing) {
		t.Fatalf("expected errNoSuchCell, got %v", err)
	}
}

func TestResumeMapsServiceUnavailableToStarting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	cp := newHTTPControlPlane(server.URL, []byte("secret"), 5*time.Second)
	_, err := cp.resume(context.Background(), "sb1")
	var starting *errCellStarting
	if !errors.As(err, &starting) {
		t.Fatalf("expected errCellStarting, got %v", err)
	}
}

func TestResumeSurfacesOtherStatuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cp := newHTTPControlPlane(server.URL, []byte("secret"), 5*time.Second)
	if _, err := cp.resume(context.Background(), "sb1"); err == nil {
		t.Fatal("expected an error for a 500")
	}
}

func TestReportActivityPostsBatchAndTakesInvalidations(t *testing.T) {
	var got activityRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"invalidate":["sb2.sb.test"]}`))
	}))
	defer server.Close()

	cp := newHTTPControlPlane(server.URL, []byte("secret"), 5*time.Second)
	reports := []activityReport{{CellID: "sb1", Connections: 2, Bytes: 4096}}
	stale, err := cp.reportActivity(context.Background(), reports, []string{"sb1.sb.test", "sb2.sb.test"})
	if err != nil {
		t.Fatalf("reportActivity: %v", err)
	}
	if len(got.Reports) != 1 || got.Reports[0].CellID != "sb1" || got.Reports[0].Bytes != 4096 {
		t.Errorf("control plane received %+v", got.Reports)
	}
	if len(got.Cached) != 2 {
		t.Errorf("cached hosts were not sent: %+v", got.Cached)
	}
	if len(stale) != 1 || stale[0] != "sb2.sb.test" {
		t.Errorf("invalidations were not returned: %+v", stale)
	}
}

func TestReportActivitySkipsEmptyBatches(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer server.Close()

	cp := newHTTPControlPlane(server.URL, []byte("secret"), 5*time.Second)
	if _, err := cp.reportActivity(context.Background(), nil, nil); err != nil {
		t.Fatalf("reportActivity: %v", err)
	}
	if called {
		t.Error("an empty batch should not reach the control plane")
	}
}
