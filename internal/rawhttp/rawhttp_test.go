package rawhttp

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func read(t *testing.T, raw string, isReq bool) *Message {
	t.Helper()
	br := bufio.NewReader(strings.NewReader(raw))
	m, err := ReadMessage(br, isReq)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}
	return m
}

func TestRequestNoBody(t *testing.T) {
	raw := "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
	m := read(t, raw, true)
	if string(m.Raw) != raw {
		t.Errorf("Raw mismatch:\n got %q\nwant %q", m.Raw, raw)
	}
	if m.StartLn != "GET /path HTTP/1.1" {
		t.Errorf("StartLn = %q", m.StartLn)
	}
	if m.Get("host") != "example.com" {
		t.Errorf("Host = %q", m.Get("host"))
	}
}

// Побайтовая точность: порядок и регистр заголовков, дубли сохраняются как есть.
func TestHeaderOrderAndCasePreserved(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: x\r\nX-Weird-CASE: 1\r\nx-weird-case: 2\r\nZ-Last: z\r\n\r\n"
	m := read(t, raw, true)
	if string(m.Raw) != raw {
		t.Fatalf("raw bytes not preserved byte-for-byte")
	}
	if len(m.Headers) != 4 {
		t.Fatalf("headers = %d, want 4 (дубли сохранены)", len(m.Headers))
	}
	if m.Headers[1].Name != "X-Weird-CASE" || m.Headers[2].Name != "x-weird-case" {
		t.Errorf("регистр/порядок заголовков потерян: %+v", m.Headers)
	}
}

func TestResponseContentLength(t *testing.T) {
	body := "hello world"
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n" + body
	m := read(t, raw, false)
	if string(m.Raw) != raw {
		t.Errorf("Raw mismatch: %q", m.Raw)
	}
	if string(m.Body) != body {
		t.Errorf("Body = %q, want %q", m.Body, body)
	}
	code, ok := m.StatusCode()
	if !ok || code != 200 {
		t.Errorf("StatusCode = %d,%v", code, ok)
	}
}

func TestResponseChunked(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
	m := read(t, raw, false)
	if string(m.Raw) != raw {
		t.Errorf("chunked raw not preserved:\n got %q\nwant %q", m.Raw, raw)
	}
}

func TestResponseUntilClose(t *testing.T) {
	// нет ни Content-Length, ни chunked — читаем до EOF
	raw := "HTTP/1.1 200 OK\r\nServer: x\r\n\r\nsome body until close"
	m := read(t, raw, false)
	if string(m.Raw) != raw {
		t.Errorf("until-close raw mismatch: %q", m.Raw)
	}
}

func TestExactBodyBytesBinary(t *testing.T) {
	// тело с произвольными байтами (в т.ч. \x00) не должно теряться
	body := []byte{0x00, 0x01, 0xff, 0x0d, 0x0a, 0x41}
	var buf bytes.Buffer
	buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n")
	buf.Write(body)
	br := bufio.NewReader(&buf)
	m, err := ReadMessage(br, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Body, body) {
		t.Errorf("binary body mismatch: %v", m.Body)
	}
}
