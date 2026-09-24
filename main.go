// Command postgres-gateway terminates client PostgreSQL connections, routes
// them to the right cell by SNI, resumes paused cells on connect, and
// splices the session through (design doc section 8).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	var (
		listenAddr     = flag.String("listen", ":5432", "address to serve PostgreSQL clients on")
		adminAddr      = flag.String("admin-listen", "127.0.0.1:8453", "address for cache invalidation and health")
		certFile       = flag.String("cert", "", "wildcard certificate for *.<hostname-suffix>")
		keyFile        = flag.String("key", "", "key for the wildcard certificate")
		cellCAFile     = flag.String("cell-ca", "", "PEM bundle of the cell root CA; only needed if routes set upstream_tls")
		controlPlane   = flag.String("control-plane", "", "base URL of the control plane's internal API")
		hostnameSuffix = flag.String("hostname-suffix", "sb.ubicloud.com", "suffix after the cell id in the SNI name")
		maxConns       = flag.Int("max-conns-per-cell", 20, "per-cell connection cap")
		resumeWait     = flag.Duration("resume-wait", 15*time.Second, "how long to hold a client while a cell resumes")
		activityEvery  = flag.Duration("activity-interval", 15*time.Second, "how often to report activity")
		positiveTTL    = flag.Duration("route-ttl", 30*time.Second, "how long to cache a resolved route")
		negativeTTL    = flag.Duration("route-negative-ttl", 2*time.Second, "how long to cache a failed lookup")
		logLevel       = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	log := newLogger(*logLevel)
	if err := run(runConfig{
		listenAddr:     *listenAddr,
		adminAddr:      *adminAddr,
		certFile:       *certFile,
		keyFile:        *keyFile,
		cellCAFile:     *cellCAFile,
		controlPlane:   *controlPlane,
		hostnameSuffix: *hostnameSuffix,
		maxConns:       *maxConns,
		resumeWait:     *resumeWait,
		activityEvery:  *activityEvery,
		positiveTTL:    *positiveTTL,
		negativeTTL:    *negativeTTL,
		log:            log,
	}); err != nil {
		log.Error("gateway exited", "error", err)
		os.Exit(1)
	}
}

type runConfig struct {
	listenAddr     string
	adminAddr      string
	certFile       string
	keyFile        string
	cellCAFile     string
	controlPlane   string
	hostnameSuffix string
	maxConns       int
	resumeWait     time.Duration
	activityEvery  time.Duration
	positiveTTL    time.Duration
	negativeTTL    time.Duration
	log            *slog.Logger
}

func run(cfg runConfig) error {
	for name, value := range map[string]string{
		"-cert": cfg.certFile, "-key": cfg.keyFile,
		"-control-plane": cfg.controlPlane,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	secret := os.Getenv("POSTGRES_GATEWAY_TOKEN_SECRET")
	if secret == "" {
		return fmt.Errorf("POSTGRES_GATEWAY_TOKEN_SECRET is required")
	}

	cert, err := tls.LoadX509KeyPair(cfg.certFile, cfg.keyFile)
	if err != nil {
		return fmt.Errorf("loading the wildcard certificate: %w", err)
	}
	// Only needed for routes that opt into a second TLS session; see the
	// comment on route.UpstreamTLS.
	var cellCAs *x509.CertPool
	if cfg.cellCAFile != "" {
		caPEM, err := os.ReadFile(cfg.cellCAFile)
		if err != nil {
			return fmt.Errorf("reading the cell CA: %w", err)
		}
		cellCAs = x509.NewCertPool()
		if !cellCAs.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("no certificates found in %s", cfg.cellCAFile)
		}
	}

	cp := newHTTPControlPlane(cfg.controlPlane, []byte(secret), 20*time.Second)
	rt := newRouter(cp, routerOptions{
		positiveTTL: cfg.positiveTTL,
		negativeTTL: cfg.negativeTTL,
		resumeWait:  cfg.resumeWait,
	})
	tracker := newActivityTracker(cfg.maxConns)

	g := &gateway{
		cfg: gatewayConfig{
			hostnameSuffix:   cfg.hostnameSuffix,
			maxConnsPerCell:  cfg.maxConns,
			resumeWait:       cfg.resumeWait,
			dialTimeout:      10 * time.Second,
			handshakeTimeout: 30 * time.Second,
		},
		router:  rt,
		tracker: tracker,
		serverTLS: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		cellCAs: cellCAs,
		log:     cfg.log,
		now:     time.Now,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", cfg.listenAddr, err)
	}
	defer func() { _ = ln.Close() }()

	admin := &http.Server{
		Addr:              cfg.adminAddr,
		Handler:           adminHandler(rt, tracker, cfg.log),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			cfg.log.Error("admin server exited", "error", err)
		}
	}()
	go tracker.reportLoop(ctx, cp, rt, cfg.activityEvery, func(err error) {
		cfg.log.Warn("reporting activity failed", "error", err)
	})
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = admin.Shutdown(shutdownCtx)
	}()

	cfg.log.Info("gateway listening",
		"addr", cfg.listenAddr, "admin", cfg.adminAddr, "suffix", cfg.hostnameSuffix)
	return g.serve(ctx, ln)
}

// adminHandler serves the control plane's cache invalidation push and a health
// endpoint. It is bound to localhost by default; the control plane reaches it
// over the private subnet.
func adminHandler(rt *router, tracker *activityTracker, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /invalidate", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Host string `json:"host"`
			All  bool   `json:"all"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch {
		case body.All:
			rt.invalidateAll()
		case body.Host != "":
			rt.invalidate(body.Host)
		default:
			http.Error(w, "host or all is required", http.StatusBadRequest)
			return
		}
		log.Debug("cache invalidated", "host", body.Host, "all", body.All)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":                 true,
			"in_flight_resumes":  rt.inFlightResumes(),
			"tracked_cells":      len(tracker.cells),
			"max_conns_per_cell": tracker.maxConns,
		})
	})
	return mux
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
