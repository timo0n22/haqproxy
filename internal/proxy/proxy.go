// Package proxy — MITM-прокси haqproxy поверх собственного парсера (internal/rawhttp),
// а не поверх net/http или сторонней библиотеки. Такой подход даёт побайтовую
// точность запросов/ответов и в пассивной истории (см. §4 ТЗ): порядок и регистр
// заголовков сохраняются как есть.
//
// Поддерживается HTTP-проксирование (absolute-form) и HTTPS через CONNECT с
// подменой сертификата (leaf от нашего CA). HTTP/2 не MITM-им: в ALPN предлагаем
// только http/1.1, браузер откатывается на 1.1. Это осознанное упрощение MVP
// (этапы 0-2); WebSocket/H2 — вне рамок собственного парсера на данном этапе.
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/loginovartem/haqproxy/internal/ca"
	"github.com/loginovartem/haqproxy/internal/rawhttp"
	"github.com/loginovartem/haqproxy/internal/store"
)

// Proxy — перехватывающий прокси.
type Proxy struct {
	CA          *ca.CA
	Store       *store.Store
	Logger      *log.Logger
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

// New создаёт прокси с разумными таймаутами.
func New(c *ca.CA, s *store.Store, logger *log.Logger) *Proxy {
	return &Proxy{
		CA:          c,
		Store:       s,
		Logger:      logger,
		DialTimeout: 15 * time.Second,
		IOTimeout:   60 * time.Second,
	}
}

// ListenAndServe запускает прокси на addr (например "127.0.0.1:8080").
func (p *Proxy) ListenAndServe(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	p.logf("proxy listening on %s", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)

	// Читаем первое сообщение, чтобы понять: CONNECT (HTTPS-туннель) или
	// обычный HTTP-запрос в absolute-form.
	first, err := rawhttp.ReadMessage(br, true)
	if err != nil {
		return
	}
	parts := first.StartLineParts()
	if len(parts) < 2 {
		return
	}
	method := parts[0]

	if strings.EqualFold(method, "CONNECT") {
		p.handleConnect(client, parts[1])
		return
	}
	// Обычный HTTP: первое сообщение уже прочитано — обрабатываем его, затем
	// продолжаем читать keep-alive на том же соединении.
	p.serveHTTP(client, br, first)
}

// handleConnect отвечает на CONNECT, поднимает TLS с leaf-сертификатом и
// обслуживает расшифрованные запросы.
func (p *Proxy) handleConnect(client net.Conn, target string) {
	host, port := splitHostPort(target, 443)

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	tlsConn := tls.Server(client, &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return p.CA.LeafFor(name)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	sni := tlsConn.ConnectionState().ServerName
	if sni == "" {
		sni = host
	}
	tbr := bufio.NewReader(tlsConn)
	p.serveLoop(tlsConn, tbr, sni, port, "https")
}

// serveHTTP обрабатывает уже прочитанный первый plain-HTTP запрос и продолжает цикл.
func (p *Proxy) serveHTTP(client net.Conn, br *bufio.Reader, first *rawhttp.Message) {
	if !p.processHTTP(client, first, "http") {
		return
	}
	p.serveLoop(client, br, "", 80, "http")
}

// serveLoop читает запросы из conn в цикле (keep-alive) и обрабатывает каждый.
// defaultHost/scheme используются, когда host не удаётся взять из запроса
// (для https — из CONNECT/SNI).
func (p *Proxy) serveLoop(conn net.Conn, br *bufio.Reader, defaultHost string, defaultPort int, scheme string) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(p.IOTimeout))
		msg, err := rawhttp.ReadMessage(br, true)
		if err != nil {
			return
		}
		if scheme == "https" {
			p.forward(conn, msg, defaultHost, defaultPort, scheme)
		} else {
			if !p.processHTTP(conn, msg, scheme) {
				return
			}
		}
	}
}

// processHTTP обрабатывает plain-HTTP запрос в absolute-form: извлекает host/port,
// переписывает request-line в origin-form и форвардит. Возвращает false, если
// соединение следует закрыть.
func (p *Proxy) processHTTP(conn net.Conn, msg *rawhttp.Message, scheme string) bool {
	host, port, rewritten := rewriteToOrigin(msg)
	if host == "" {
		host = msg.Get("Host")
	}
	if host == "" {
		return false
	}
	p.forwardRaw(conn, msg, rewritten, host, port, scheme)
	return true
}

// forward — вариант для https, где запрос уже в origin-form (переписывать не нужно).
func (p *Proxy) forward(conn net.Conn, msg *rawhttp.Message, defaultHost string, defaultPort int, scheme string) {
	host := hostFromHeaderOr(msg, defaultHost)
	port := defaultPort
	if h, prt := splitHostPortMaybe(msg.Get("Host")); h != "" {
		host = h
		if prt > 0 {
			port = prt
		}
	}
	p.forwardRaw(conn, msg, msg.Raw, host, port, scheme)
}

// forwardRaw открывает соединение к upstream, шлёт sendBytes, читает ответ,
// пишет его клиенту и записывает запись истории.
func (p *Proxy) forwardRaw(client net.Conn, reqMsg *rawhttp.Message, sendBytes []byte, host string, port int, scheme string) {
	method, path := methodPath(reqMsg)
	start := time.Now()

	upstream, err := p.dialUpstream(host, port, scheme == "https")
	if err != nil {
		p.record(scheme, host, port, method, path, reqMsg.Raw, nil, nil, nil, err.Error())
		return
	}
	defer upstream.Close()

	_ = upstream.SetDeadline(time.Now().Add(p.IOTimeout))
	if _, err := upstream.Write(sendBytes); err != nil {
		p.record(scheme, host, port, method, path, reqMsg.Raw, nil, nil, nil, "upstream write: "+err.Error())
		return
	}

	ubr := bufio.NewReader(upstream)
	respMsg, rerr := rawhttp.ReadMessage(ubr, false)

	var rawResp []byte
	var status *int
	if respMsg != nil && len(respMsg.Raw) > 0 {
		rawResp = respMsg.Raw
		if code, ok := respMsg.StatusCode(); ok {
			status = &code
		}
		// пересылаем ответ клиенту как есть
		_, _ = client.Write(respMsg.Raw)
	}

	dur := int(time.Since(start).Milliseconds())
	errStr := ""
	if rerr != nil && rerr != io.EOF {
		errStr = "upstream read: " + rerr.Error()
	}
	p.record(scheme, host, port, method, path, reqMsg.Raw, rawResp, status, &dur, errStr)
}

func (p *Proxy) dialUpstream(host string, port int, useTLS bool) (net.Conn, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, p.DialTimeout)
	if err != nil {
		return nil, err
	}
	if useTLS {
		tconn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, // цель может иметь сломанный/самоподписанный серт — не мешаем тесту
			NextProtos:         []string{"http/1.1"},
		})
		if err := tconn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		return tconn, nil
	}
	return conn, nil
}

func (p *Proxy) record(scheme, host string, port int, method, path string, rawReq, rawResp []byte, status, dur *int, errStr string) {
	e := &store.Entry{
		Source:      "proxy",
		Host:        host,
		Port:        port,
		Scheme:      scheme,
		Method:      method,
		Path:        path,
		RespStatus:  status,
		DurationMs:  dur,
		RawRequest:  rawReq,
		RawResponse: rawResp,
	}
	if errStr != "" {
		e.Error = &errStr
	}
	if _, err := p.Store.InsertEntry(e); err != nil {
		p.logf("store insert: %v", err)
	}
}

func (p *Proxy) logf(format string, args ...any) {
	if p.Logger != nil {
		p.Logger.Printf(format, args...)
	}
}

// ---------- helpers ----------

func methodPath(msg *rawhttp.Message) (string, string) {
	parts := msg.StartLineParts()
	method, path := "?", "?"
	if len(parts) >= 1 {
		method = parts[0]
	}
	if len(parts) >= 2 {
		path = parts[1]
	}
	return method, path
}

func hostFromHeaderOr(msg *rawhttp.Message, def string) string {
	if h := msg.Get("Host"); h != "" {
		if host, _ := splitHostPortMaybe(h); host != "" {
			return host
		}
	}
	return def
}

// rewriteToOrigin переписывает request-line из absolute-form
// ("GET http://host:port/path HTTP/1.1") в origin-form ("GET /path HTTP/1.1"),
// возвращая host, port и новые сырые байты запроса. Если запрос уже в
// origin-form — возвращает host="" и исходные байты.
func rewriteToOrigin(msg *rawhttp.Message) (host string, port int, raw []byte) {
	parts := msg.StartLineParts()
	if len(parts) < 3 {
		return "", 80, msg.Raw
	}
	method, target, version := parts[0], parts[1], parts[2]
	lower := strings.ToLower(target)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", 80, msg.Raw
	}

	scheme := "http"
	rest := target[len("http://"):]
	if strings.HasPrefix(lower, "https://") {
		scheme = "https"
		rest = target[len("https://"):]
	}
	// rest = host[:port]/path...
	slash := strings.IndexByte(rest, '/')
	authority := rest
	pathPart := "/"
	if slash >= 0 {
		authority = rest[:slash]
		pathPart = rest[slash:]
	}
	host, port = splitHostPort(authority, defaultPort(scheme))

	newStart := method + " " + pathPart + " " + version + "\r\n"
	// заменяем первую строку в Raw
	if idx := indexCRLF(msg.Raw); idx >= 0 {
		raw = append([]byte(newStart), msg.Raw[idx+2:]...)
	} else {
		raw = msg.Raw
	}
	return host, port, raw
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// splitHostPort разбивает "host:port" (или "host"); при отсутствии порта
// возвращает def.
func splitHostPort(s string, def int) (string, int) {
	h, p := splitHostPortMaybe(s)
	if h == "" {
		return s, def
	}
	if p <= 0 {
		return h, def
	}
	return h, p
}

// splitHostPortMaybe возвращает host и port (0, если порта нет). Корректно
// обрабатывает IPv6 в скобках.
func splitHostPortMaybe(s string) (string, int) {
	if s == "" {
		return "", 0
	}
	if host, portStr, err := net.SplitHostPort(s); err == nil {
		p, _ := strconv.Atoi(portStr)
		return host, p
	}
	return s, 0
}
