package main

import (
	"context"
	"sync"
	"time"
)

// router resolves an SNI host to a cell endpoint, caching what the control
// plane says and making sure that a crowd arriving at one paused cell
// produces exactly one resume.
type router struct {
	cp          controlPlane
	positiveTTL time.Duration
	negativeTTL time.Duration
	resumeWait  time.Duration
	now         func() time.Time

	mu      sync.Mutex
	entries map[string]*cacheEntry
	resumes map[string]*resumeCall
}

type cacheEntry struct {
	r       *route
	err     error
	expires time.Time
}

// resumeCall is one in-flight resume that several waiting connections share.
type resumeCall struct {
	done chan struct{}
	r    *route
	err  error
}

type routerOptions struct {
	positiveTTL time.Duration
	negativeTTL time.Duration
	resumeWait  time.Duration
}

func newRouter(cp controlPlane, opts routerOptions) *router {
	if opts.positiveTTL == 0 {
		opts.positiveTTL = 30 * time.Second
	}
	if opts.negativeTTL == 0 {
		opts.negativeTTL = 2 * time.Second
	}
	if opts.resumeWait == 0 {
		opts.resumeWait = 15 * time.Second
	}
	return &router{
		cp:          cp,
		positiveTTL: opts.positiveTTL,
		negativeTTL: opts.negativeTTL,
		resumeWait:  opts.resumeWait,
		now:         time.Now,
		entries:     map[string]*cacheEntry{},
		resumes:     map[string]*resumeCall{},
	}
}

// lookup resolves a host, using the cache when it is fresh. Negative results
// are cached too, briefly, so a flood of connections for a name that does not
// exist does not become a flood of control-plane requests.
func (rt *router) lookup(ctx context.Context, host string) (*route, error) {
	rt.mu.Lock()
	if e, ok := rt.entries[host]; ok && rt.now().Before(e.expires) {
		rt.mu.Unlock()
		return e.r, e.err
	}
	rt.mu.Unlock()

	r, err := rt.cp.lookup(ctx, host)
	rt.store(host, r, err)
	return r, err
}

func (rt *router) store(host string, r *route, err error) {
	ttl := rt.positiveTTL
	if err != nil {
		ttl = rt.negativeTTL
	}
	rt.mu.Lock()
	rt.entries[host] = &cacheEntry{r: r, err: err, expires: rt.now().Add(ttl)}
	rt.mu.Unlock()
}

// invalidate drops a cached host, for the control plane's push on pause,
// resume and destroy.
func (rt *router) invalidate(host string) {
	rt.mu.Lock()
	delete(rt.entries, host)
	rt.mu.Unlock()
}

// cachedHosts is every host with a live positive entry, which is what the
// control plane needs in order to say which of them have gone stale.
func (rt *router) cachedHosts() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := rt.now()
	hosts := make([]string, 0, len(rt.entries))
	for host, entry := range rt.entries {
		if entry.err == nil && entry.r != nil && now.Before(entry.expires) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func (rt *router) invalidateAll() {
	rt.mu.Lock()
	rt.entries = map[string]*cacheEntry{}
	rt.mu.Unlock()
}

// resume brings a paused cell up, collapsing concurrent callers onto one
// request.
//
// This matters more than it looks. The control plane serialises resumes of one
// cell on its row lock, so twenty connections arriving together at a paused
// cell would otherwise queue twenty sequential resumes and the last client
// would wait for all of them. Sharing one call keeps the wait at one resume.
func (rt *router) resume(ctx context.Context, host string, cellID string) (*route, error) {
	rt.mu.Lock()
	if call, ok := rt.resumes[cellID]; ok {
		rt.mu.Unlock()
		return call.wait(ctx)
	}
	call := &resumeCall{done: make(chan struct{})}
	rt.resumes[cellID] = call
	rt.mu.Unlock()

	go func() {
		// Detached from the leader's context: whoever started the resume may
		// hang up, but the cell is coming up regardless and the other
		// waiters still want the answer.
		callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rt.resumeWait)
		defer cancel()

		call.r, call.err = rt.cp.resume(callCtx, cellID)
		rt.mu.Lock()
		delete(rt.resumes, cellID)
		rt.mu.Unlock()
		if call.err == nil {
			rt.store(host, call.r, nil)
		} else {
			// Do not cache a resume failure against the host: the next
			// connection should be free to try again.
			rt.invalidate(host)
		}
		close(call.done)
	}()

	return call.wait(ctx)
}

func (c *resumeCall) wait(ctx context.Context) (*route, error) {
	select {
	case <-c.done:
		return c.r, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// inFlightResumes is for tests and metrics.
func (rt *router) inFlightResumes() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.resumes)
}
