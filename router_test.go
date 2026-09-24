package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeControlPlane struct {
	mu sync.Mutex

	lookups  atomic.Int64
	resumes  atomic.Int64
	reported []activityReport
	cached   []string
	// What the control plane answers an activity report with.
	invalidate []string

	lookupResult *route
	// When set, the second and later lookups answer with this instead, which
	// is how a route that has gone stale inside the cache TTL is modelled.
	lookupResultAfterFirst *route
	lookupErr              error
	resumeResult           *route
	resumeErr              error
	resumeDelay            time.Duration
}

func (f *fakeControlPlane) lookup(_ context.Context, _ string) (*route, error) {
	if f.lookups.Add(1) > 1 && f.lookupResultAfterFirst != nil {
		return f.lookupResultAfterFirst, f.lookupErr
	}
	return f.lookupResult, f.lookupErr
}

func (f *fakeControlPlane) resume(ctx context.Context, _ string) (*route, error) {
	f.resumes.Add(1)
	if f.resumeDelay > 0 {
		select {
		case <-time.After(f.resumeDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.resumeResult, f.resumeErr
}

func (f *fakeControlPlane) reportActivity(_ context.Context, reports []activityReport, cached []string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reported = append(f.reported, reports...)
	f.cached = append(f.cached, cached...)
	return f.invalidate, nil
}

func runningRoute() *route {
	return &route{CellID: "sb1", State: "running", TargetIP6: "fd00::2", Port: 5432, CertCN: "sb1"}
}

func TestLookupCachesPositiveResults(t *testing.T) {
	cp := &fakeControlPlane{lookupResult: runningRoute()}
	rt := newRouter(cp, routerOptions{})
	for range 5 {
		if _, err := rt.lookup(context.Background(), "sb1.sb.loc"); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if got := cp.lookups.Load(); got != 1 {
		t.Errorf("expected 1 control-plane lookup, got %d", got)
	}
}

func TestLookupCachesNegativeResultsBriefly(t *testing.T) {
	cp := &fakeControlPlane{lookupErr: &errNoSuchCell{host: "nope"}}
	rt := newRouter(cp, routerOptions{positiveTTL: time.Minute, negativeTTL: 50 * time.Millisecond})
	fake := time.Now()
	rt.now = func() time.Time { return fake }

	for range 3 {
		if _, err := rt.lookup(context.Background(), "nope"); err == nil {
			t.Fatal("expected an error")
		}
	}
	if got := cp.lookups.Load(); got != 1 {
		t.Errorf("negative result was not cached: %d lookups", got)
	}

	// Once the short negative TTL passes, the next connection retries.
	fake = fake.Add(100 * time.Millisecond)
	if _, err := rt.lookup(context.Background(), "nope"); err == nil {
		t.Fatal("expected an error")
	}
	if got := cp.lookups.Load(); got != 2 {
		t.Errorf("expected a retry after the negative TTL, got %d lookups", got)
	}
}

func TestInvalidateForcesRefetch(t *testing.T) {
	cp := &fakeControlPlane{lookupResult: runningRoute()}
	rt := newRouter(cp, routerOptions{})
	_, _ = rt.lookup(context.Background(), "sb1.sb.loc")
	rt.invalidate("sb1.sb.loc")
	_, _ = rt.lookup(context.Background(), "sb1.sb.loc")
	if got := cp.lookups.Load(); got != 2 {
		t.Errorf("expected invalidation to force a refetch, got %d lookups", got)
	}
}

// The reason this exists: the control plane serialises resumes of one cell
// on its row lock, so N concurrent connections must not become N resumes.
func TestConcurrentResumesCollapseToOne(t *testing.T) {
	cp := &fakeControlPlane{resumeResult: runningRoute(), resumeDelay: 100 * time.Millisecond}
	rt := newRouter(cp, routerOptions{})

	const waiters = 20
	var wg sync.WaitGroup
	errs := make([]error, waiters)
	started := time.Now()
	for i := range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = rt.resume(context.Background(), "sb1.sb.loc", "sb1")
		}()
	}
	wg.Wait()
	elapsed := time.Since(started)

	if got := cp.resumes.Load(); got != 1 {
		t.Errorf("expected 20 waiters to share 1 resume, got %d resumes", got)
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("waiter %d: %v", i, err)
		}
	}
	// Serialised, twenty 100 ms resumes would take two seconds.
	if elapsed > time.Second {
		t.Errorf("waiters appear to have serialised: took %v", elapsed)
	}
	if rt.inFlightResumes() != 0 {
		t.Error("in-flight resume was not cleaned up")
	}
}

func TestResumeSurvivesTheLeaderHangingUp(t *testing.T) {
	cp := &fakeControlPlane{resumeResult: runningRoute(), resumeDelay: 150 * time.Millisecond}
	rt := newRouter(cp, routerOptions{})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := rt.resume(leaderCtx, "sb1.sb.loc", "sb1")
		leaderDone <- err
	}()

	// A second connection joins, then the client that triggered the resume
	// disconnects. The cell is coming up regardless.
	time.Sleep(20 * time.Millisecond)
	followerDone := make(chan error, 1)
	go func() {
		_, err := rt.resume(context.Background(), "sb1.sb.loc", "sb1")
		followerDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancelLeader()

	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Errorf("leader should see its own cancellation, got %v", err)
	}
	select {
	case err := <-followerDone:
		if err != nil {
			t.Errorf("follower should still get its answer, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("follower was abandoned when the leader hung up")
	}
	if got := cp.resumes.Load(); got != 1 {
		t.Errorf("expected exactly 1 resume, got %d", got)
	}
}

func TestSuccessfulResumeIsCached(t *testing.T) {
	cp := &fakeControlPlane{resumeResult: runningRoute()}
	rt := newRouter(cp, routerOptions{})
	if _, err := rt.resume(context.Background(), "sb1.sb.loc", "sb1"); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if _, err := rt.lookup(context.Background(), "sb1.sb.loc"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got := cp.lookups.Load(); got != 0 {
		t.Errorf("a resumed route should already be cached, saw %d lookups", got)
	}
}

func TestFailedResumeIsNotCached(t *testing.T) {
	cp := &fakeControlPlane{resumeErr: &errCellStarting{cellID: "sb1"}, lookupResult: runningRoute()}
	rt := newRouter(cp, routerOptions{})
	if _, err := rt.resume(context.Background(), "sb1.sb.loc", "sb1"); err == nil {
		t.Fatal("expected the resume to fail")
	}
	// The next connection must be free to try again rather than inherit the
	// failure from the cache.
	if _, err := rt.lookup(context.Background(), "sb1.sb.loc"); err != nil {
		t.Fatalf("lookup after a failed resume: %v", err)
	}
	if got := cp.lookups.Load(); got != 1 {
		t.Errorf("expected a fresh lookup after a failed resume, got %d", got)
	}
}
