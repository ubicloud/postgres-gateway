package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cell root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue mints a leaf certificate, as the per-host CA does for each cell.
func (ca *testCA) issue(t *testing.T, commonName string, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// fakeCell is a PostgreSQL-shaped TLS endpoint: it answers the SSLRequest,
// terminates TLS with its per-cell certificate, records the startup packet
// it was sent, and echoes whatever follows.
type fakeCell struct {
	ln       net.Listener
	startups chan []byte
}

// newFakeCell builds the default shape: PostgreSQL with ssl off, because
// the hop is encrypted below PostgreSQL.
func newFakeCell(t *testing.T) *fakeCell {
	return startFakeCell(t, nil)
}

// newTLSFakeCell builds the opt-in shape, where the cell terminates its
// own TLS with a per-cell certificate.
func newTLSFakeCell(t *testing.T, cert tls.Certificate) *fakeCell {
	return startFakeCell(t, &cert)
}

func startFakeCell(t *testing.T, cert *tls.Certificate) *fakeCell {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeCell{ln: ln, startups: make(chan []byte, 8)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn, cert)
		}
	}()
	return s
}

func (s *fakeCell) serve(raw net.Conn, cert *tls.Certificate) {
	defer func() { _ = raw.Close() }()
	stream := raw
	if cert != nil {
		req, err := readStartupRequest(raw)
		if err != nil || !req.isSSLRequest() {
			return
		}
		if _, err := raw.Write([]byte{'S'}); err != nil {
			return
		}
		conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
		if err := conn.Handshake(); err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		stream = conn
	}
	startup, err := readStartupRequest(stream)
	if err != nil {
		return
	}
	select {
	case s.startups <- startup.encode():
	default:
	}
	_, _ = io.Copy(stream, stream)
}

func (s *fakeCell) addr() string { return s.ln.Addr().String() }

func (s *fakeCell) host() string {
	host, _, _ := net.SplitHostPort(s.addr())
	return host
}

func (s *fakeCell) port() int {
	_, port, _ := net.SplitHostPort(s.addr())
	var n int
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	return n
}

// startGateway wires a gateway in front of a control plane and returns its
// address.
func startGateway(t *testing.T, cp controlPlane, ca *testCA, opts func(*gateway)) string {
	t.Helper()
	serverCert := ca.issue(t, "*.sb.test", []string{"*.sb.test"}, nil)
	g := &gateway{
		cfg: gatewayConfig{
			hostnameSuffix:   "sb.test",
			maxConnsPerCell:  20,
			resumeWait:       5 * time.Second,
			dialTimeout:      5 * time.Second,
			handshakeTimeout: 5 * time.Second,
		},
		router:  newRouter(cp, routerOptions{}),
		tracker: newActivityTracker(20),
		serverTLS: &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12,
		},
		cellCAs: ca.pool,
		log:     discardLogger(),
		now:     time.Now,
	}
	if opts != nil {
		opts(g)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = g.serve(t.Context(), ln) }()
	return ln.Addr().String()
}

// dialClient performs the client half: SSLRequest on the raw socket, then TLS
// with the given SNI.
func dialClient(t *testing.T, addr, sni string, ca *testCA) (*tls.Conn, error) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeAll(raw, sslRequestPacket()); err != nil {
		_ = raw.Close()
		return nil, err
	}
	var reply [1]byte
	if _, err := io.ReadFull(raw, reply[:]); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if reply[0] != 'S' {
		_ = raw.Close()
		return nil, errPlainRefused{got: reply[0]}
	}
	clientCfg := &tls.Config{RootCAs: ca.pool, ServerName: sni, MinVersion: tls.VersionTLS12}
	if sni == "" {
		// A client that sends no SNI at all, which is what the startup-packet
		// fallbacks exist for.
		clientCfg.InsecureSkipVerify = true
	}
	conn := tls.Client(raw, clientCfg)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

type errPlainRefused struct{ got byte }

func (e errPlainRefused) Error() string { return "server replied " + string(e.got) }

// readErrorResponse reads one ErrorResponse and returns its fields by code.
func readErrorResponse(t *testing.T, r io.Reader) map[byte]string {
	t.Helper()
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		t.Fatalf("reading error response: %v", err)
	}
	if header[0] != 'E' {
		t.Fatalf("expected an ErrorResponse, got tag %q", header[0])
	}
	length := binary.BigEndian.Uint32(header[1:5])
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatalf("reading error body: %v", err)
	}
	fields := map[byte]string{}
	for _, part := range strings.Split(string(body), "\x00") {
		if part == "" {
			continue
		}
		fields[part[0]] = part[1:]
	}
	return fields
}

func startupFor(user, database string) []byte {
	return encodeStartup(startupParams{"user": user, "database": database})
}
