package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Enough of the PostgreSQL v3 frontend/backend protocol to decide where a
// connection should go and to tell the client why it cannot.
//
// https://www.postgresql.org/docs/current/protocol-message-formats.html

const (
	sslRequestCode     = 80877103
	gssEncRequestCode  = 80877104
	cancelRequestCode  = 80877102
	protocolVersion3   = 196608
	maxStartupLen      = 10000 // libpq's own limit on the startup packet
	startupHeaderBytes = 8
)

var errNotStartup = errors.New("not a startup packet")

// startupRequest is the first thing a client sends, before any TLS.
type startupRequest struct {
	code   int32
	body   []byte // for a v3 startup packet: everything after the version
	length int32
}

// readStartupRequest reads one length-prefixed startup-style packet.
func readStartupRequest(r io.Reader) (*startupRequest, error) {
	var header [startupHeaderBytes]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := int32(binary.BigEndian.Uint32(header[0:4]))
	code := int32(binary.BigEndian.Uint32(header[4:8]))
	if length < startupHeaderBytes || length > maxStartupLen {
		return nil, fmt.Errorf("startup packet length %d out of range", length)
	}
	body := make([]byte, length-startupHeaderBytes)
	if len(body) > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
	}
	return &startupRequest{code: code, body: body, length: length}, nil
}

func (s *startupRequest) isSSLRequest() bool {
	return s.length == startupHeaderBytes && s.code == sslRequestCode
}

func (s *startupRequest) isGSSEncRequest() bool {
	return s.length == startupHeaderBytes && s.code == gssEncRequestCode
}

func (s *startupRequest) isCancelRequest() bool {
	return s.code == cancelRequestCode
}

// encode rebuilds the packet exactly as it arrived, so it can be forwarded
// upstream unchanged.
func (s *startupRequest) encode() []byte {
	out := make([]byte, startupHeaderBytes+len(s.body))
	binary.BigEndian.PutUint32(out[0:4], uint32(s.length))
	binary.BigEndian.PutUint32(out[4:8], uint32(s.code))
	copy(out[startupHeaderBytes:], s.body)
	return out
}

// startupParams are the key/value pairs of a v3 startup packet.
type startupParams map[string]string

// parseStartupParams reads the null-terminated key/value pairs that follow the
// protocol version.
func parseStartupParams(s *startupRequest) (startupParams, error) {
	if s.code != protocolVersion3 {
		return nil, errNotStartup
	}
	params := startupParams{}
	fields := strings.Split(string(s.body), "\x00")
	// The body ends with an empty terminator, so the usable fields come in
	// pairs before it.
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "" {
			break
		}
		params[fields[i]] = fields[i+1]
	}
	return params, nil
}

// encodeStartup builds a v3 startup packet from parameters. Used when the
// user name carried the cell id and has to be rewritten before the packet
// reaches PostgreSQL, which knows nothing about cell ids.
func encodeStartup(params startupParams) []byte {
	var b strings.Builder
	// Keep `user` first, as libpq does; the rest of the order does not matter
	// to the server but a stable order keeps tests readable.
	if user, ok := params["user"]; ok {
		b.WriteString("user")
		b.WriteByte(0)
		b.WriteString(user)
		b.WriteByte(0)
	}
	for _, k := range sortedKeys(params) {
		if k == "user" {
			continue
		}
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(params[k])
		b.WriteByte(0)
	}
	b.WriteByte(0)

	body := b.String()
	out := make([]byte, startupHeaderBytes+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(startupHeaderBytes+len(body)))
	binary.BigEndian.PutUint32(out[4:8], uint32(protocolVersion3))
	copy(out[startupHeaderBytes:], body)
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Small maps; insertion sort keeps this dependency-free and obvious.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// SQLSTATE codes the gateway can produce.
const (
	sqlStateConnectionFailure  = "08006"
	sqlStateCannotConnectNow   = "57P03" // what a starting postmaster sends; libpq retries
	sqlStateProtocolViolation  = "08P01"
	sqlStateTooManyConnections = "53300"
)

// errorResponse builds an ErrorResponse ('E') message. Sending this instead of
// closing the socket is what makes psql and libpq print something useful.
func errorResponse(sqlState, message, hint string) []byte {
	var fields []byte
	add := func(code byte, value string) {
		if value == "" {
			return
		}
		fields = append(fields, code)
		fields = append(fields, value...)
		fields = append(fields, 0)
	}
	add('S', "FATAL")
	add('V', "FATAL")
	add('C', sqlState)
	add('M', message)
	add('H', hint)
	fields = append(fields, 0)

	out := make([]byte, 5+len(fields))
	out[0] = 'E'
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(fields)))
	copy(out[5:], fields)
	return out
}
