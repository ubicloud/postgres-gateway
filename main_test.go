package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestAdmin(t *testing.T) (http.Handler, *router, *fakeControlPlane) {
	t.Helper()
	cp := &fakeControlPlane{lookupResult: runningRoute()}
	rt := newRouter(cp, routerOptions{positiveTTL: time.Minute})
	return adminHandler(rt, newActivityTracker(20), discardLogger()), rt, cp
}

func TestInvalidateDropsOneHost(t *testing.T) {
	handler, rt, cp := newTestAdmin(t)
	if _, err := rt.lookup(t.Context(), "sb1.sb.test"); err != nil {
		t.Fatal(err)
	}

	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/invalidate",
		strings.NewReader(`{"host":"sb1.sb.test"}`)))
	if res.Code != http.StatusNoContent {
		t.Fatalf("status = %d", res.Code)
	}

	if _, err := rt.lookup(t.Context(), "sb1.sb.test"); err != nil {
		t.Fatal(err)
	}
	if got := cp.lookups.Load(); got != 2 {
		t.Errorf("expected invalidation to force a refetch, saw %d lookups", got)
	}
}

func TestInvalidateAll(t *testing.T) {
	handler, rt, cp := newTestAdmin(t)
	for _, host := range []string{"a.sb.test", "b.sb.test"} {
		if _, err := rt.lookup(t.Context(), host); err != nil {
			t.Fatal(err)
		}
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/invalidate", strings.NewReader(`{"all":true}`)))
	if res.Code != http.StatusNoContent {
		t.Fatalf("status = %d", res.Code)
	}
	for _, host := range []string{"a.sb.test", "b.sb.test"} {
		if _, err := rt.lookup(t.Context(), host); err != nil {
			t.Fatal(err)
		}
	}
	if got := cp.lookups.Load(); got != 4 {
		t.Errorf("expected both hosts to be refetched, saw %d lookups", got)
	}
}

func TestInvalidateRejectsAnEmptyBody(t *testing.T) {
	handler, _, _ := newTestAdmin(t)
	for _, body := range []string{`{}`, `not json`} {
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodPost, "/invalidate", strings.NewReader(body)))
		if res.Code != http.StatusBadRequest {
			t.Errorf("body %q: status = %d, want 400", body, res.Code)
		}
	}
}

func TestHealth(t *testing.T) {
	handler, _, _ := newTestAdmin(t)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/health", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d", res.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding health: %v", err)
	}
	if body["ok"] != true {
		t.Errorf("ok = %v", body["ok"])
	}
	if body["max_conns_per_cell"].(float64) != 20 {
		t.Errorf("max_conns_per_cell = %v", body["max_conns_per_cell"])
	}
}

func TestRunRequiresItsFlags(t *testing.T) {
	err := run(runConfig{log: discardLogger()})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected a missing-flag error, got %v", err)
	}
}
