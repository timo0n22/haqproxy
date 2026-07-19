// Package replay — "голый" HTTP-клиент для вкладки Replay (бывший repeater.py).
//
// Сознательно не используем net/http: он нормализует порядок и регистр
// заголовков, схлопывает дубли и т.п. — а для security-тестирования (request
// smuggling, обход WAF по регистру заголовка, порядок полей) важно отправить
// ровно то, что написано в редакторе, байт в байт. Поэтому здесь свой сокет
// (net.Dial + tls.Client) + разбор ответа через internal/rawhttp.
package replay

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/loginovartem/haqproxy/internal/rawhttp"
)

// Result — исход одной отправки.
type Result struct {
	RawResponse []byte
	Status      *int
	DurationMs  int
	Error       string
}

// SendRaw отправляет rawRequest ровно как есть на host:port.
// useTLS — оборачивать ли соединение в TLS; verifyTLS — проверять ли сертификат
// (по умолчанию false: тестируем и самоподписанные/сломанные цели).
func SendRaw(host string, port int, useTLS bool, rawRequest []byte, timeout time.Duration, verifyTLS bool) *Result {
	start := time.Now()
	res := &Result{}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		res.Error = err.Error()
		res.DurationMs = int(time.Since(start).Milliseconds())
		return res
	}
	defer conn.Close()

	if useTLS {
		tconn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: !verifyTLS,
			// Только HTTP/1.1: наш ридер не понимает HTTP/2-фреймы.
			NextProtos: []string{"http/1.1"},
		})
		if err := tconn.Handshake(); err != nil {
			res.Error = "tls: " + err.Error()
			res.DurationMs = int(time.Since(start).Milliseconds())
			return res
		}
		conn = tconn
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(rawRequest); err != nil {
		res.Error = "write: " + err.Error()
		res.DurationMs = int(time.Since(start).Milliseconds())
		return res
	}

	br := bufio.NewReader(conn)
	msg, err := rawhttp.ReadMessage(br, false)
	res.DurationMs = int(time.Since(start).Milliseconds())
	if msg != nil && len(msg.Raw) > 0 {
		res.RawResponse = msg.Raw
		if code, ok := msg.StatusCode(); ok {
			res.Status = &code
		}
	}
	if err != nil {
		// частичный ответ мог быть прочитан — сохраняем и его, и ошибку
		res.Error = err.Error()
	}
	return res
}
