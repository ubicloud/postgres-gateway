package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
)

type gatewayConfig struct {
	hostnameSuffix   string // e.g. "sb.eu-central-h1.ubicloud.com"
	maxConnsPerCell  int
	resumeWait       time.Duration
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
}

type gateway struct {
	cfg       gatewayConfig
	router    *router
	tracker   *activityTracker
	serverTLS *tls.Config
	cellCAs   *x509.CertPool
	log       *slog.Logger
	now       func() time.Time
}

const spliceBufferSize = 32 * 1024

// serve accepts connections until the listener is closed.
func (g *gateway) serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go g.handle(ctx, conn)
	}
}

// handle takes one client connection all the way from the PostgreSQL
// SSLRequest to a spliced session, or explains to the client why it cannot.
func (g *gateway) handle(ctx context.Context, raw net.Conn) {
	defer func() { _ = raw.Close() }()
	if tcp, ok := raw.(*net.TCPConn); ok {
		// Small request/response exchanges; Nagle only adds latency here.
		_ = tcp.SetNoDelay(true)
	}

	// Everything up to the point where bytes start flowing is bounded; a
	// client must not be able to hold a slot open by going quiet mid-handshake.
	deadline := g.now().Add(g.cfg.handshakeTimeout)
	_ = raw.SetDeadline(deadline)

	client, err := g.negotiateTLS(raw)
	if err != nil {
		g.log.Debug("tls negotiation failed", "remote", raw.RemoteAddr().String(), "error", err)
		return
	}
	defer func() { _ = client.Close() }()

	startup, err := readStartupRequest(client)
	if err != nil {
		g.log.Debug("reading startup packet failed", "error", err)
		return
	}
	if startup.isCancelRequest() {
		// Routing a cancel needs the backend key of the session it belongs to,
		// which the gateway does not track. Closing is what the protocol
		// expects when a cancel cannot be honoured.
		g.log.Debug("ignoring cancel request")
		return
	}
	params, err := parseStartupParams(startup)
	if err != nil {
		_ = writeAll(client, errorResponse(sqlStateProtocolViolation,
			"expected a startup message", ""))
		return
	}

	sni := ""
	if state := client.ConnectionState(); state.ServerName != "" {
		sni = state.ServerName
	}
	host, cellID, forward, err := g.resolveCell(sni, startup, params)
	if err != nil {
		_ = writeAll(client, errorResponse(sqlStateConnectionFailure, err.Error(),
			"connect to <cell-id>."+g.cfg.hostnameSuffix+", or pass the cell id "+
				"as options=-c cell=<id> or as user=<user>@<cell-id>"))
		return
	}

	r, err := g.route(ctx, host, cellID)
	if err != nil {
		g.writeRouteError(client, cellID, err)
		return
	}

	if !g.tracker.acquire(r.CellID, g.now()) {
		_ = writeAll(client, errorResponse(sqlStateTooManyConnections,
			fmt.Sprintf("cell %s already has %d connections", r.CellID, g.cfg.maxConnsPerCell),
			"close an existing connection and retry"))
		return
	}
	defer g.tracker.release(r.CellID, g.now())

	upstream, err := g.dialCell(ctx, r)
	if err != nil {
		// A cached route that will not dial is a route that has gone stale:
		// the cell was paused, or moved to another host, inside the cache
		// TTL. Throw the entry away and resolve it again -- which resumes the
		// cell if it is now paused -- rather than failing a connection on
		// the strength of something we were told up to a TTL ago.
		g.log.Debug("cached route did not dial, re-resolving",
			"cell", r.CellID, "addr", r.addr(), "error", err)
		g.router.invalidate(host)
		if r, err = g.route(ctx, host, cellID); err == nil {
			upstream, err = g.dialCell(ctx, r)
		}
	}
	if err != nil {
		g.log.Warn("dialing cell failed", "cell", cellID, "error", err)
		_ = writeAll(client, errorResponse(sqlStateConnectionFailure,
			"could not reach cell "+cellID, ""))
		return
	}
	defer func() { _ = upstream.Close() }()

	if err := writeAll(upstream, forward); err != nil {
		g.log.Warn("forwarding startup packet failed", "cell", r.CellID, "error", err)
		return
	}

	// From here the session belongs to the client and the cell; the only
	// bound left is the idle detection the control plane does with activity.
	_ = raw.SetDeadline(time.Time{})
	g.splice(r.CellID, client, upstream)
}

// negotiateTLS answers the PostgreSQL pre-TLS handshake and upgrades. Plain
// connections are refused with an error the client can print.
func (g *gateway) negotiateTLS(raw net.Conn) (*tls.Conn, error) {
	for {
		startup, err := readStartupRequest(raw)
		if err != nil {
			return nil, err
		}
		switch {
		case startup.isGSSEncRequest():
			// Decline GSSAPI encryption; libpq then offers TLS.
			if _, err := raw.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		case startup.isSSLRequest():
			if _, err := raw.Write([]byte{'S'}); err != nil {
				return nil, err
			}
			conn := tls.Server(raw, g.serverTLS)
			if err := conn.Handshake(); err != nil {
				return nil, fmt.Errorf("tls handshake: %w", err)
			}
			return conn, nil
		default:
			_ = writeAll(raw, errorResponse(sqlStateConnectionFailure,
				"cell endpoints require TLS", "connect with sslmode=require or stronger"))
			return nil, errors.New("client did not request TLS")
		}
	}
}

// resolveCell works out which cell a connection is for, and returns the
// cache key, the cell id, and the startup packet to forward.
//
// SNI is the normal path. The fallbacks exist for clients that cannot set SNI,
// and the user-name form has to be rewritten before it reaches PostgreSQL,
// which knows nothing about cell ids.
func (g *gateway) resolveCell(sni string, startup *startupRequest, params startupParams) (
	host string, cellID string, forward []byte, err error) {
	if sni != "" {
		if label, _, found := strings.Cut(sni, "."); found && label != "" {
			return sni, label, startup.encode(), nil
		}
	}
	if id := cellIDFromOptions(params["options"]); id != "" {
		// The option routed the connection; PostgreSQL has never heard of a
		// "cell" GUC and refuses the startup if it still sees one.
		rewritten := make(startupParams, len(params))
		for k, v := range params {
			rewritten[k] = v
		}
		if rest := optionsWithoutCell(params["options"]); rest == "" {
			delete(rewritten, "options")
		} else {
			rewritten["options"] = rest
		}
		return id, id, encodeStartup(rewritten), nil
	}
	if user, id, found := strings.Cut(params["user"], "@"); found && id != "" && user != "" {
		rewritten := make(startupParams, len(params))
		for k, v := range params {
			rewritten[k] = v
		}
		rewritten["user"] = user
		return id, id, encodeStartup(rewritten), nil
	}
	return "", "", nil, errors.New("could not tell which cell this connection is for")
}

// optionsWithoutCell is the same options string with the cell selector
// removed, and the `-c` that introduced it dropped along with it.
func optionsWithoutCell(options string) string {
	fields := strings.Fields(options)
	kept := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		if strings.HasPrefix(fields[i], "cell=") {
			// Drop a bare "-c" immediately before it too.
			if n := len(kept); n > 0 && kept[n-1] == "-c" {
				kept = kept[:n-1]
			}
			continue
		}
		kept = append(kept, fields[i])
	}
	return strings.Join(kept, " ")
}

// cellIDFromOptions pulls the id out of an `options=-c cell=<id>` string.
func cellIDFromOptions(options string) string {
	for _, field := range strings.Fields(options) {
		if value, ok := strings.CutPrefix(field, "cell="); ok {
			return value
		}
	}
	return ""
}

// route resolves the cell and resumes it if it is paused.
func (g *gateway) route(ctx context.Context, host, cellID string) (*route, error) {
	r, err := g.router.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if r.running() {
		return r, nil
	}
	resumeCtx, cancel := context.WithTimeout(ctx, g.cfg.resumeWait)
	defer cancel()
	r, err = g.router.resume(resumeCtx, host, cellID)
	if err != nil {
		return nil, err
	}
	if !r.running() {
		return nil, &errCellStarting{cellID: cellID}
	}
	return r, nil
}

func (g *gateway) writeRouteError(client io.Writer, cellID string, err error) {
	var starting *errCellStarting
	var missing *errNoSuchCell
	switch {
	case errors.As(err, &starting), errors.Is(err, context.DeadlineExceeded):
		// 57P03 is what a starting postmaster sends, so libpq retries cleanly.
		_ = writeAll(client, errorResponse(sqlStateCannotConnectNow,
			"cell "+cellID+" is starting up", "retry in a moment"))
	case errors.As(err, &missing):
		_ = writeAll(client, errorResponse(sqlStateConnectionFailure,
			"no such cell: "+cellID, ""))
	default:
		g.log.Warn("routing failed", "cell", cellID, "error", err)
		_ = writeAll(client, errorResponse(sqlStateConnectionFailure,
			"could not route to cell "+cellID, ""))
	}
}

// dialCell opens the second TLS session, to the cell itself.
func (g *gateway) dialCell(ctx context.Context, r *route) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, g.cfg.dialTimeout)
	defer cancel()

	dialer := &net.Dialer{}
	raw, err := dialer.DialContext(dialCtx, "tcp", r.addr())
	if err != nil {
		return nil, err
	}
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}

	if !r.UpstreamTLS {
		// The hop is protected below PostgreSQL, so the cell has ssl off
		// and there is no pre-TLS handshake to do.
		_ = raw.SetDeadline(time.Time{})
		return raw, nil
	}
	if g.cellCAs == nil {
		_ = raw.Close()
		return nil, errors.New("route asks for upstream TLS but no cell CA was configured")
	}
	if r.CertCN == "" {
		_ = raw.Close()
		return nil, errors.New("route asks for upstream TLS but names no expected common name")
	}

	// PostgreSQL's own pre-TLS handshake, this time as the client.
	if err := writeAll(raw, sslRequestPacket()); err != nil {
		_ = raw.Close()
		return nil, err
	}
	var reply [1]byte
	if _, err := io.ReadFull(raw, reply[:]); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("reading cell SSL reply: %w", err)
	}
	if reply[0] != 'S' {
		_ = raw.Close()
		return nil, fmt.Errorf("cell refused TLS (replied %q)", reply[0])
	}

	conn := tls.Client(raw, g.cellTLSConfig(r))
	if err := conn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("cell tls handshake: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// cellTLSConfig verifies the cell's certificate by hand.
//
// The certificate is issued by a per-host CA under the cell root CA with
// CN=<cell ubid> and a SAN for the slot address, and we dial it by address,
// so Go's hostname verification has nothing to match. Verifying the chain
// explicitly and then checking the common name is what binds this connection
// to this cell, which is the whole point of per-cell certificates
// (design doc 8.3).
func (g *gateway) cellTLSConfig(r *route) *tls.Config {
	expectedCN := r.CertCN
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("cell presented no certificate")
			}
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, der := range rawCerts {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					return fmt.Errorf("parsing cell certificate: %w", err)
				}
				certs = append(certs, cert)
			}
			intermediates := x509.NewCertPool()
			for _, cert := range certs[1:] {
				intermediates.AddCert(cert)
			}
			if _, err := certs[0].Verify(x509.VerifyOptions{
				Roots:         g.cellCAs,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return fmt.Errorf("cell certificate is not trusted: %w", err)
			}
			if certs[0].Subject.CommonName != expectedCN {
				return fmt.Errorf("cell certificate is for %q, expected %q",
					certs[0].Subject.CommonName, expectedCN)
			}
			return nil
		},
	}
}

func sslRequestPacket() []byte {
	packet := make([]byte, 8)
	packet[3] = 8
	packet[4], packet[5], packet[6], packet[7] = 0x04, 0xd2, 0x16, 0x2f
	return packet
}

// splice moves bytes both ways until either side finishes, counting them for
// idle detection.
func (g *gateway) splice(cellID string, client, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		g.copyCounting(cellID, upstream, client)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		g.copyCounting(cellID, client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
}

func (g *gateway) copyCounting(cellID string, dst io.Writer, src io.Reader) {
	buf := make([]byte, spliceBufferSize)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			g.tracker.addBytes(cellID, int64(n), g.now())
			if err := writeAll(dst, buf[:n]); err != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// writeAll is a named wrapper so that the places which deliberately ignore a
// write error read as deliberate. Errors writing an ErrorResponse are ignored
// on purpose: the connection is being torn down regardless.
func writeAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}
