package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// The default: the hop is encrypted below PostgreSQL, so no second TLS
// session and no per-cell certificate.
func cellRoute(s *fakeCell, state string) *route {
	return &route{CellID: "sb1", State: state, TargetIP6: s.host(), Port: s.port()}
}

// The opt-in: a second TLS session verified against the cell root CA.
func tlsCellRoute(s *fakeCell, state string) *route {
	r := cellRoute(s, state)
	r.UpstreamTLS = true
	r.CertCN = "sb1"
	return r
}

func TestEndToEndThroughToTheCell(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	startup := startupFor("postgres", "app")
	if err := writeAll(conn, startup); err != nil {
		t.Fatalf("sending startup: %v", err)
	}

	// The cell must receive the startup packet unchanged.
	select {
	case got := <-cell.startups:
		if !bytes.Equal(got, startup) {
			t.Errorf("startup packet was altered:\n got %q\nwant %q", got, startup)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cell never received a startup packet")
	}

	// And bytes must flow both ways.
	if err := writeAll(conn, []byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Errorf("got %q back, want %q", buf, "ping")
	}
}

func TestPlaintextConnectionIsToldToUseTLS(t *testing.T) {
	ca := newTestCA(t)
	cp := &fakeControlPlane{lookupResult: &route{}}
	addr := startGateway(t, cp, ca, nil)

	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	// A client that goes straight to the startup packet without asking for TLS.
	if err := writeAll(raw, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	fields := readErrorResponse(t, raw)
	if fields['C'] != sqlStateConnectionFailure {
		t.Errorf("SQLSTATE = %q, want %q", fields['C'], sqlStateConnectionFailure)
	}
	if fields['M'] != "cell endpoints require TLS" {
		t.Errorf("message = %q", fields['M'])
	}
}

func TestGSSEncRequestIsDeclinedThenTLSProceeds(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))

	gssRequest := make([]byte, 8)
	gssRequest[3] = 8
	gssRequest[4], gssRequest[5], gssRequest[6], gssRequest[7] = 0x04, 0xd2, 0x16, 0x30
	if err := writeAll(raw, gssRequest); err != nil {
		t.Fatal(err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(raw, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 'N' {
		t.Fatalf("expected GSSAPI encryption to be declined with N, got %q", reply[0])
	}
	// libpq then falls back to asking for TLS on the same connection.
	if err := writeAll(raw, sslRequestPacket()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(raw, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 'S' {
		t.Fatalf("expected TLS to be accepted after declining GSSAPI, got %q", reply[0])
	}
}

func TestUnknownCellIsReported(t *testing.T) {
	ca := newTestCA(t)
	cp := &fakeControlPlane{lookupErr: &errNoSuchCell{host: "nope.sb.test"}}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "nope.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	fields := readErrorResponse(t, conn)
	if fields['C'] != sqlStateConnectionFailure {
		t.Errorf("SQLSTATE = %q", fields['C'])
	}
	if fields['M'] != "no such cell: nope" {
		t.Errorf("message = %q", fields['M'])
	}
}

func TestPausedCellIsResumedOnConnect(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{
		lookupResult: cellRoute(cell, "paused"),
		resumeResult: cellRoute(cell, "running"),
	}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-cell.startups:
	case <-time.After(5 * time.Second):
		t.Fatal("connection never reached the cell after a resume")
	}
	if got := cp.resumes.Load(); got != 1 {
		t.Errorf("expected 1 resume, got %d", got)
	}
}

func TestCellStillStartingGetsARetryableError(t *testing.T) {
	ca := newTestCA(t)
	cp := &fakeControlPlane{
		lookupResult: &route{CellID: "sb1", State: "paused"},
		resumeErr:    &errCellStarting{cellID: "sb1"},
	}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	fields := readErrorResponse(t, conn)
	// 57P03 is what a starting postmaster sends, so libpq retries rather than
	// treating this as a hard failure.
	if fields['C'] != sqlStateCannotConnectNow {
		t.Errorf("SQLSTATE = %q, want %q", fields['C'], sqlStateCannotConnectNow)
	}
}

func TestPerCellConnectionCap(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, func(g *gateway) {
		g.cfg.maxConnsPerCell = 2
		g.tracker = newActivityTracker(2)
	})

	// Hold the cap open.
	for range 2 {
		conn, err := dialClient(t, addr, "sb1.sb.test", ca)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
			t.Fatal(err)
		}
		if _, err := <-cell.startups, error(nil); err != nil {
			t.Fatal(err)
		}
	}

	over, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(over, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	fields := readErrorResponse(t, over)
	if fields['C'] != sqlStateTooManyConnections {
		t.Errorf("SQLSTATE = %q, want %q", fields['C'], sqlStateTooManyConnections)
	}
}

func TestCellCertificateWithTheWrongCommonNameIsRejected(t *testing.T) {
	ca := newTestCA(t)
	// A cell presenting a certificate for a *different* cell: a
	// compromised guest must not be able to impersonate its neighbour.
	cell := newTLSFakeCell(t, ca.issue(t, "sb-other", nil, []net.IP{net.ParseIP("127.0.0.1")}))
	cp := &fakeControlPlane{lookupResult: tlsCellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	fields := readErrorResponse(t, conn)
	if fields['M'] != "could not reach cell sb1" {
		t.Errorf("message = %q, expected the connection to be refused", fields['M'])
	}
	select {
	case <-cell.startups:
		t.Fatal("the startup packet reached a cell with the wrong certificate")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestCellCertificateFromAnUntrustedCAIsRejected(t *testing.T) {
	ca := newTestCA(t)
	rogue := newTestCA(t)
	cell := newTLSFakeCell(t, rogue.issue(t, "sb1", nil, []net.IP{net.ParseIP("127.0.0.1")}))
	cp := &fakeControlPlane{lookupResult: tlsCellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	if fields := readErrorResponse(t, conn); fields['M'] != "could not reach cell sb1" {
		t.Errorf("message = %q", fields['M'])
	}
}

func TestUserSuffixFallbackRewritesTheUser(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	// No SNI, so the cell id has to come from the user name.
	conn, err := dialClient(t, addr, "", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres@sb1", "app")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-cell.startups:
		req, err := readStartupRequest(bytes.NewReader(got))
		if err != nil {
			t.Fatal(err)
		}
		params, err := parseStartupParams(req)
		if err != nil {
			t.Fatal(err)
		}
		// PostgreSQL knows nothing about cell ids, so the suffix must be
		// stripped before the packet gets there.
		if params["user"] != "postgres" {
			t.Errorf("user = %q, want %q", params["user"], "postgres")
		}
		if params["database"] != "app" {
			t.Errorf("database = %q", params["database"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cell never received a startup packet")
	}
}

func TestOptionsFallback(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	startup := encodeStartup(startupParams{"user": "postgres", "options": "-c cell=sb1"})
	if err := writeAll(conn, startup); err != nil {
		t.Fatal(err)
	}
	// The selector routed the connection and must not survive into the
	// startup packet: PostgreSQL rejects a GUC it has never heard of.
	want := encodeStartup(startupParams{"user": "postgres"})
	select {
	case got := <-cell.startups:
		if !bytes.Equal(got, want) {
			t.Errorf("cell selector was not stripped:\n got %q\nwant %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cell never received a startup packet")
	}
}

func TestOptionsFallbackKeepsOtherOptions(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	startup := encodeStartup(startupParams{
		"user":    "postgres",
		"options": "-c statement_timeout=5s -c cell=sb1 -c work_mem=8MB",
	})
	if err := writeAll(conn, startup); err != nil {
		t.Fatal(err)
	}
	want := encodeStartup(startupParams{
		"user":    "postgres",
		"options": "-c statement_timeout=5s -c work_mem=8MB",
	})
	select {
	case got := <-cell.startups:
		if !bytes.Equal(got, want) {
			t.Errorf("other options were not preserved:\n got %q\nwant %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cell never received a startup packet")
	}
}

func TestUnroutableConnectionExplainsItself(t *testing.T) {
	ca := newTestCA(t)
	cp := &fakeControlPlane{}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	fields := readErrorResponse(t, conn)
	if fields['M'] != "could not tell which cell this connection is for" {
		t.Errorf("message = %q", fields['M'])
	}
	if fields['H'] == "" {
		t.Error("expected a hint naming the three ways to address a cell")
	}
}

func TestActivityIsRecordedAndReported(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	var tracker *activityTracker
	addr := startGateway(t, cp, ca, func(g *gateway) { tracker = g.tracker })

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	<-cell.startups
	if err := writeAll(conn, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}

	if got := tracker.connections("sb1"); got != 1 {
		t.Errorf("connections = %d, want 1", got)
	}
	tracker.report(context.Background(), cp, newRouter(cp, routerOptions{}), nil)
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.reported) == 0 {
		t.Fatal("no activity was reported")
	}
	report := cp.reported[0]
	if report.CellID != "sb1" {
		t.Errorf("cell = %q", report.CellID)
	}
	// Five bytes each way through the echo.
	if report.Bytes < 10 {
		t.Errorf("bytes = %d, want at least 10", report.Bytes)
	}
	if report.Connections != 1 {
		t.Errorf("connections = %d, want 1", report.Connections)
	}
}

func TestConcurrentConnectionsToAPausedCellResumeOnce(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{
		lookupResult: cellRoute(cell, "paused"),
		resumeResult: cellRoute(cell, "running"),
		resumeDelay:  200 * time.Millisecond,
	}
	addr := startGateway(t, cp, ca, nil)

	const clients = 10
	var wg sync.WaitGroup
	started := time.Now()
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialClient(t, addr, "sb1.sb.test", ca)
			if err != nil {
				return
			}
			_ = writeAll(conn, startupFor("postgres", "app"))
			// Round-trip a byte through the cell's echo so the client waits
			// for the connection to be usable, not for a timeout.
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			_ = writeAll(conn, []byte("x"))
			buf := make([]byte, 1)
			_, _ = io.ReadFull(conn, buf)
		}()
	}
	wg.Wait()

	if got := cp.resumes.Load(); got != 1 {
		t.Errorf("expected 10 concurrent clients to trigger 1 resume, got %d", got)
	}
	// Serialised, ten 200 ms resumes would take two seconds.
	if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
		t.Errorf("clients appear to have serialised behind separate resumes: %v", elapsed)
	}
}

func TestUpstreamTLSPathStillWorksWhenOptedIn(t *testing.T) {
	// The transport the design started with, kept live so it can be switched
	// back on per cell if the gateway ever terminates SCRAM itself.
	ca := newTestCA(t)
	cell := newTLSFakeCell(t, ca.issue(t, "sb1", nil, []net.IP{net.ParseIP("127.0.0.1")}))
	cp := &fakeControlPlane{lookupResult: tlsCellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	startup := startupFor("postgres", "app")
	if err := writeAll(conn, startup); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-cell.startups:
		if !bytes.Equal(got, startup) {
			t.Errorf("startup packet was altered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cell never received a startup packet over the TLS hop")
	}
}

func TestUpstreamTLSWithoutAnExpectedCommonNameIsRefused(t *testing.T) {
	// Half-configured is refused rather than silently accepting any
	// certificate the cell happens to present.
	ca := newTestCA(t)
	cell := newTLSFakeCell(t, ca.issue(t, "sb1", nil, []net.IP{net.ParseIP("127.0.0.1")}))
	r := cellRoute(cell, "running")
	r.UpstreamTLS = true // but no CertCN
	cp := &fakeControlPlane{lookupResult: r}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	if fields := readErrorResponse(t, conn); fields['M'] != "could not reach cell sb1" {
		t.Errorf("message = %q", fields['M'])
	}
}

func TestUpstreamTLSWithoutACellCAIsRefused(t *testing.T) {
	ca := newTestCA(t)
	cell := newTLSFakeCell(t, ca.issue(t, "sb1", nil, []net.IP{net.ParseIP("127.0.0.1")}))
	cp := &fakeControlPlane{lookupResult: tlsCellRoute(cell, "running")}
	// A gateway started without -cell-ca cannot verify anything, so a route
	// asking for TLS must fail rather than fall back to plaintext.
	addr := startGateway(t, cp, ca, func(g *gateway) { g.cellCAs = nil })

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, startupFor("postgres", "app")); err != nil {
		t.Fatal(err)
	}
	if fields := readErrorResponse(t, conn); fields['M'] != "could not reach cell sb1" {
		t.Errorf("message = %q", fields['M'])
	}
}

func TestPlaintextUpstreamDoesNotSendAnSSLRequest(t *testing.T) {
	// If the gateway sent an SSLRequest to a cell with ssl off, PostgreSQL
	// would answer N and the gateway would have to fall back; instead the
	// startup packet must be the first thing the cell sees.
	ca := newTestCA(t)
	cell := newFakeCell(t)
	cp := &fakeControlPlane{lookupResult: cellRoute(cell, "running")}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	startup := startupFor("postgres", "app")
	if err := writeAll(conn, startup); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-cell.startups:
		if !bytes.Equal(got, startup) {
			t.Errorf("first packet was %q, want the startup packet", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cell never received a startup packet")
	}
}

// A route cached as running, for a cell that has since been paused, must
// not fail the connection: the entry is thrown away and resolved again, which
// resumes the cell.
func TestStaleCachedRouteIsReResolved(t *testing.T) {
	ca := newTestCA(t)
	cell := newFakeCell(t)

	// First lookup points at an address nothing is listening on. After the
	// resume, the route points at the cell that is actually there.
	cp := &fakeControlPlane{
		lookupResult:           &route{CellID: "sb1", State: "running", TargetIP6: "127.0.0.1", Port: 1},
		lookupResultAfterFirst: &route{CellID: "sb1", State: "paused"},
		resumeResult:           cellRoute(cell, "running"),
	}
	addr := startGateway(t, cp, ca, nil)

	conn, err := dialClient(t, addr, "sb1.sb.test", ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := writeAll(conn, encodeStartup(startupParams{"user": "postgres"})); err != nil {
		t.Fatal(err)
	}

	select {
	case <-cell.startups:
	case <-time.After(5 * time.Second):
		t.Fatal("connection was not re-resolved onto the resumed cell")
	}
	if got := cp.resumes.Load(); got != 1 {
		t.Errorf("expected the re-resolve to resume the cell once, got %d", got)
	}
}
