package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

func startupPacket(code int32, body string) []byte {
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(body)))
	binary.BigEndian.PutUint32(out[4:8], uint32(code))
	copy(out[8:], body)
	return out
}

func TestReadSSLRequest(t *testing.T) {
	req, err := readStartupRequest(bytes.NewReader(startupPacket(sslRequestCode, "")))
	if err != nil {
		t.Fatalf("readStartupRequest: %v", err)
	}
	if !req.isSSLRequest() {
		t.Error("expected an SSLRequest")
	}
	if req.isGSSEncRequest() || req.isCancelRequest() {
		t.Error("SSLRequest misidentified")
	}
}

func TestReadGSSEncAndCancelRequests(t *testing.T) {
	gss, err := readStartupRequest(bytes.NewReader(startupPacket(gssEncRequestCode, "")))
	if err != nil || !gss.isGSSEncRequest() {
		t.Errorf("expected a GSSENCRequest, got %v (err %v)", gss, err)
	}
	// A CancelRequest carries the backend pid and secret key.
	cancel, err := readStartupRequest(bytes.NewReader(startupPacket(cancelRequestCode, "12345678")))
	if err != nil || !cancel.isCancelRequest() {
		t.Errorf("expected a CancelRequest, got %v (err %v)", cancel, err)
	}
}

func TestReadStartupRequestRejectsAbsurdLength(t *testing.T) {
	// A length field a client could use to make the gateway allocate freely.
	packet := make([]byte, 8)
	binary.BigEndian.PutUint32(packet[0:4], 1<<30)
	binary.BigEndian.PutUint32(packet[4:8], protocolVersion3)
	if _, err := readStartupRequest(bytes.NewReader(packet)); err == nil {
		t.Fatal("expected an oversized startup packet to be rejected")
	}

	short := make([]byte, 8)
	binary.BigEndian.PutUint32(short[0:4], 4)
	if _, err := readStartupRequest(bytes.NewReader(short)); err == nil {
		t.Fatal("expected an undersized startup packet to be rejected")
	}
}

func TestReadStartupRequestTruncated(t *testing.T) {
	full := startupPacket(protocolVersion3, "user\x00bob\x00\x00")
	if _, err := readStartupRequest(bytes.NewReader(full[:len(full)-3])); err != io.ErrUnexpectedEOF {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestParseStartupParams(t *testing.T) {
	req, err := readStartupRequest(bytes.NewReader(
		startupPacket(protocolVersion3, "user\x00bob\x00database\x00app\x00options\x00-c cell=sb123\x00\x00")))
	if err != nil {
		t.Fatalf("readStartupRequest: %v", err)
	}
	params, err := parseStartupParams(req)
	if err != nil {
		t.Fatalf("parseStartupParams: %v", err)
	}
	for k, want := range map[string]string{"user": "bob", "database": "app", "options": "-c cell=sb123"} {
		if params[k] != want {
			t.Errorf("param %q = %q, want %q", k, params[k], want)
		}
	}
}

func TestParseStartupParamsRejectsSSLRequest(t *testing.T) {
	req, _ := readStartupRequest(bytes.NewReader(startupPacket(sslRequestCode, "")))
	if _, err := parseStartupParams(req); err != errNotStartup {
		t.Fatalf("expected errNotStartup, got %v", err)
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	// A forwarded packet must reach PostgreSQL byte for byte.
	original := startupPacket(protocolVersion3, "user\x00bob\x00database\x00app\x00\x00")
	req, err := readStartupRequest(bytes.NewReader(original))
	if err != nil {
		t.Fatalf("readStartupRequest: %v", err)
	}
	if !bytes.Equal(req.encode(), original) {
		t.Errorf("encode did not round trip:\n got %q\nwant %q", req.encode(), original)
	}
}

func TestEncodeStartupPutsUserFirstAndParses(t *testing.T) {
	encoded := encodeStartup(startupParams{"database": "app", "user": "bob", "application_name": "psql"})
	if !bytes.HasPrefix(encoded[8:], []byte("user\x00bob\x00")) {
		t.Errorf("expected user first, got %q", encoded[8:])
	}
	req, err := readStartupRequest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("re-reading encoded startup: %v", err)
	}
	params, err := parseStartupParams(req)
	if err != nil {
		t.Fatalf("parseStartupParams: %v", err)
	}
	if params["user"] != "bob" || params["database"] != "app" || params["application_name"] != "psql" {
		t.Errorf("round trip lost parameters: %v", params)
	}
}

func TestErrorResponseShape(t *testing.T) {
	msg := errorResponse(sqlStateCannotConnectNow, "the cell is starting up", "retry shortly")
	if msg[0] != 'E' {
		t.Fatalf("expected an ErrorResponse tag, got %q", msg[0])
	}
	declared := binary.BigEndian.Uint32(msg[1:5])
	if int(declared) != len(msg)-1 {
		t.Errorf("declared length %d does not match body length %d", declared, len(msg)-1)
	}
	if msg[len(msg)-1] != 0 {
		t.Error("expected a terminating zero byte")
	}
	body := string(msg[5:])
	for _, want := range []string{"FATAL", sqlStateCannotConnectNow, "the cell is starting up", "retry shortly"} {
		if !strings.Contains(body, want) {
			t.Errorf("error body missing %q: %q", want, body)
		}
	}
}

func TestErrorResponseOmitsEmptyHint(t *testing.T) {
	msg := errorResponse(sqlStateConnectionFailure, "no such cell", "")
	if bytes.Contains(msg, []byte{'H'}) {
		t.Error("expected no hint field when the hint is empty")
	}
}
