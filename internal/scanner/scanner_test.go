package scanner

import (
	"encoding/base64"
	"strings"
	"testing"
)

func rules(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

func TestMissingSecurityHeaders(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: t\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>")
	f := rules(Scan(req, resp))
	if _, ok := f["missing-security-headers"]; !ok {
		t.Fatal("ожидалась находка missing-security-headers")
	}
	// с полным набором заголовков — находки быть не должно
	resp2 := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" +
		"Content-Security-Policy: default-src 'self'\r\nX-Frame-Options: DENY\r\n" +
		"Strict-Transport-Security: max-age=1\r\nX-Content-Type-Options: nosniff\r\n\r\n<html></html>")
	if _, ok := rules(Scan(req, resp2))["missing-security-headers"]; ok {
		t.Error("не ожидалась находка при полном наборе заголовков")
	}
}

func TestReflectedParam(t *testing.T) {
	req := []byte("GET /search?q=uniquevalue123 HTTP/1.1\r\nHost: t\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 40\r\n\r\n<p>results for uniquevalue123 shown</p>")
	if _, ok := rules(Scan(req, resp))["reflected-parameter"]; !ok {
		t.Error("ожидалось отражение параметра q")
	}
}

func TestVerboseError(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: t\r\n\r\n")
	resp := []byte("HTTP/1.1 500 err\r\nContent-Type: text/plain\r\nContent-Length: 40\r\n\r\nTraceback (most recent call last): boom!!!")
	if _, ok := rules(Scan(req, resp))["verbose-error"]; !ok {
		t.Error("ожидалась находка verbose-error")
	}
}

func TestJWTNone(t *testing.T) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	tok := hdr + ".eyJzdWIiOiIxIn0."
	req := []byte("GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer " + tok + "\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if _, ok := rules(Scan(req, resp))["jwt-alg-none"]; !ok {
		t.Error("ожидалась находка jwt-alg-none")
	}
}

func TestSensitivePath(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: t\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 30\r\n\r\n<a href=/backup/.git/config>x</a>")
	if _, ok := rules(Scan(req, resp))["sensitive-path-reference"]; !ok {
		t.Error("ожидалась находка sensitive-path-reference")
	}
}

func TestNoFindingsOnClean(t *testing.T) {
	req := []byte("GET /static/app.js HTTP/1.1\r\nHost: t\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: 11\r\n\r\nvar x = 1;;")
	if got := Scan(req, resp); len(got) != 0 {
		t.Errorf("ожидалось 0 находок на чистом JS, получено %v", got)
	}
}

func TestScanNoResponse(t *testing.T) {
	if got := Scan([]byte("GET / HTTP/1.1\r\n\r\n"), nil); len(got) != 0 {
		t.Errorf("без ответа находок быть не должно, got %v", got)
	}
}

func TestReflectedParamIgnoresShort(t *testing.T) {
	// значение короче 4 символов не должно триггерить (шумно)
	req := []byte("GET /p?x=ab HTTP/1.1\r\nHost: t\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 10\r\n\r\nab ab ab ab")
	if _, ok := rules(Scan(req, resp))["reflected-parameter"]; ok {
		t.Error("короткое значение не должно триггерить reflected-parameter")
	}
	_ = strings.TrimSpace("")
}
