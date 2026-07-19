package domlogger

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/loginovartem/haqproxy/internal/rawhttp"
)

func parseResp(t *testing.T, raw string) *rawhttp.Message {
	t.Helper()
	m, err := rawhttp.ReadMessage(bufio.NewReader(strings.NewReader(raw)), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

func TestInjectHTML(t *testing.T) {
	body := "<html><head><title>x</title></head><body>hi</body></html>"
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	msg := parseResp(t, raw)
	out, ok := Inject(msg)
	if !ok {
		t.Fatal("ожидалась инъекция в HTML")
	}
	if !bytes.Contains(out, []byte(MagicPath)) {
		t.Error("сниппет не внедрён (нет magic path)")
	}
	// сниппет должен идти сразу после <head>
	idxHead := bytes.Index(out, []byte("<head>"))
	idxSnippet := bytes.Index(out, []byte("<script>"))
	if idxSnippet < idxHead {
		t.Error("сниппет должен идти после <head>")
	}
	// Content-Length должен быть пересчитан и соответствовать реальному телу
	m2 := parseResp(t, string(out))
	if got := m2.Get("Content-Length"); got != strconv.Itoa(len(m2.Body)) {
		t.Errorf("Content-Length=%s не совпадает с длиной тела %d", got, len(m2.Body))
	}
}

func TestNoInjectNonHTML(t *testing.T) {
	body := "{\"ok\":true}"
	raw := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body
	if _, ok := Inject(parseResp(t, raw)); ok {
		t.Error("в JSON инъекции быть не должно")
	}
}

func TestNoInjectCompressed(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\n\x1f\x8b\x08\x00\x00"
	if _, ok := Inject(parseResp(t, raw)); ok {
		t.Error("в сжатый ответ инъекции быть не должно")
	}
}

func TestNoInjectChunked(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n<html>\r\n0\r\n\r\n"
	if _, ok := Inject(parseResp(t, raw)); ok {
		t.Error("в chunked-ответ инъекции быть не должно (тело хранится сырым)")
	}
}
