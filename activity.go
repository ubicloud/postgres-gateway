package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// activityTracker holds the per-cell counters the control plane needs for
// idle detection, and enforces the per-cell connection cap.
//
// Counters are atomic so the splice path never takes the map lock; the lock is
// only for finding or creating a cell's entry.
type activityTracker struct {
	maxConns int

	mu    sync.RWMutex
	cells map[string]*cellActivity
}

type cellActivity struct {
	bytes        atomic.Int64
	conns        atomic.Int64
	lastUnixNano atomic.Int64
}

func newActivityTracker(maxConns int) *activityTracker {
	return &activityTracker{maxConns: maxConns, cells: map[string]*cellActivity{}}
}

func (t *activityTracker) entry(cellID string) *cellActivity {
	t.mu.RLock()
	a, ok := t.cells[cellID]
	t.mu.RUnlock()
	if ok {
		return a
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if a, ok = t.cells[cellID]; ok {
		return a
	}
	a = &cellActivity{}
	t.cells[cellID] = a
	return a
}

// acquire takes a connection slot, or reports that the cell is at its cap.
func (t *activityTracker) acquire(cellID string, now time.Time) bool {
	a := t.entry(cellID)
	if a.conns.Add(1) > int64(t.maxConns) {
		a.conns.Add(-1)
		return false
	}
	a.lastUnixNano.Store(now.UnixNano())
	return true
}

func (t *activityTracker) release(cellID string, now time.Time) {
	a := t.entry(cellID)
	a.conns.Add(-1)
	a.lastUnixNano.Store(now.UnixNano())
}

func (t *activityTracker) addBytes(cellID string, n int64, now time.Time) {
	a := t.entry(cellID)
	a.bytes.Add(n)
	a.lastUnixNano.Store(now.UnixNano())
}

// tracked reports how many cells have counters, for the health endpoint.
func (t *activityTracker) tracked() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.cells)
}

func (t *activityTracker) connections(cellID string) int {
	return int(t.entry(cellID).conns.Load())
}

// drain snapshots and resets the byte counters, and forgets cells that
// have no connections and no traffic since the last drain, so an idle gateway
// does not accumulate an entry per cell it has ever seen.
func (t *activityTracker) drain() []activityReport {
	t.mu.Lock()
	defer t.mu.Unlock()

	reports := make([]activityReport, 0, len(t.cells))
	for id, a := range t.cells {
		bytes := a.bytes.Swap(0)
		conns := a.conns.Load()
		if bytes == 0 && conns == 0 {
			delete(t.cells, id)
			continue
		}
		reports = append(reports, activityReport{
			CellID:         id,
			LastActivityAt: time.Unix(0, a.lastUnixNano.Load()).UTC(),
			Connections:    int(conns),
			Bytes:          bytes,
		})
	}
	return reports
}

// routeCache is the part of the router this loop needs: what is cached, and
// how to throw an entry away.
type routeCache interface {
	cachedHosts() []string
	invalidate(host string)
}

// reportLoop ships batched activity to the control plane until ctx is done,
// and applies the invalidations that come back with each answer.
func (t *activityTracker) reportLoop(ctx context.Context, cp controlPlane, rc routeCache, every time.Duration, onError func(error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// One last report so a clean shutdown does not lose the window.
			t.report(context.WithoutCancel(ctx), cp, rc, onError)
			return
		case <-ticker.C:
			t.report(ctx, cp, rc, onError)
		}
	}
}

func (t *activityTracker) report(ctx context.Context, cp controlPlane, rc routeCache, onError func(error)) {
	reports := t.drain()
	var cached []string
	if rc != nil {
		cached = rc.cachedHosts()
	}
	if len(reports) == 0 && len(cached) == 0 {
		return
	}
	reportCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stale, err := cp.reportActivity(reportCtx, reports, cached)
	if err != nil {
		if onError != nil {
			onError(err)
		}
		return
	}
	// Whatever the control plane says is no longer running: dropping it here
	// is what keeps a reconnect after a pause from paying a dial timeout
	// before it discovers the cell moved.
	for _, host := range stale {
		rc.invalidate(host)
	}
}
