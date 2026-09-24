# postgres-gateway

The PostgreSQL entry point for Postgres Cells. One fleet per location sits
behind the location's TCP load balancer and a wildcard certificate; clients
connect to `<cell-id>.sb.<location>.ubicloud.com:5432` and the gateway puts
them through to the right cell, resuming it first if it was paused.

Like `cli/ubi`, this is a standalone Go module with no third-party
dependencies.

## What it does

1. Answers the PostgreSQL pre-TLS handshake. `GSSENCRequest` is declined so
   libpq falls back to TLS; a client that never asks for TLS is told
   `cell endpoints require TLS` rather than having its socket closed.
2. Terminates the client's TLS with the location's wildcard certificate and
   takes the cell id from the first label of the SNI name. Clients that
   cannot set SNI can instead pass `options=-c cell=<id>` or connect as
   `<user>@<cell-id>`; in the latter case the user name is rewritten before
   the startup packet is forwarded, since PostgreSQL knows nothing about
   cell ids.
3. Resolves the route through the control plane, caching results (30 s for a
   hit, 2 s for a miss) and accepting invalidation pushes.
4. Resumes a paused cell and holds the client while it comes up, answering
   `57P03` if it is not ready in time so libpq retries cleanly. Concurrent
   connections to one paused cell share a single resume.
5. Connects to the cell, forwards the startup packet and splices the
   session, counting bytes for idle detection.

## The hop to the cell

By default the gateway connects to the cell in plaintext, and that hop is
expected to be encrypted below PostgreSQL by a tunnel between the gateway
replicas and the cell hosts.

This is not laziness. A TLS-terminating gateway cannot satisfy SCRAM channel
binding: libpq defaults to `channel_binding=prefer`, which selects
`SCRAM-SHA-256-PLUS` whenever the server advertises it, and
`tls-server-end-point` binding hashes *the server's* certificate. The client
would hash the gateway's wildcard certificate while the cell verified
against its own, so they could never match, and every default `psql`
connection would fail with `SCRAM channel binding check failed`. Running the
cell's PostgreSQL without `ssl` means no `-PLUS` is advertised, plain SCRAM
runs end to end between client and cell, and the gateway still cannot read
credentials.

A route may still opt into a second TLS session with `"upstream_tls": true`
and a `cert_cn`, in which case the cell's certificate is verified against
the cell root CA and its common name checked. That path is tested and kept
live so the transport can be switched per cell if the gateway ever
terminates SCRAM itself, which is the change that would make channel binding
work properly. A route that asks for TLS without a `cert_cn`, or against a
gateway started without `-cell-ca`, is refused rather than downgraded.

The gateway is a compiled binary because every tenant byte is decrypted here,
so it is the one component whose CPU cost scales with tenant traffic.

## Running

    go build -o postgres-gateway .
    POSTGRES_GATEWAY_TOKEN_SECRET=... ./postgres-gateway \
      -listen :5432 \
      -cert /etc/postgres-gateway/wildcard.crt \
      -key /etc/postgres-gateway/wildcard.key \
      -cell-ca /etc/postgres-gateway/cell-ca.crt \  # only for upstream_tls routes
      -control-plane https://internal.ubicloud.com \
      -hostname-suffix sb.eu-central-h1.ubicloud.com

`-admin-listen` (default `127.0.0.1:8453`) serves `POST /invalidate`
(`{"host":"..."}` or `{"all":true}`) and `GET /health`.

## Tests

    go test -race ./...

The tests stand up a real TLS cell with certificates from a test CA and
drive the whole path, including the cases that matter for isolation: a cell
presenting a certificate for a different cell, or one signed by a CA the
gateway does not trust, is refused.
