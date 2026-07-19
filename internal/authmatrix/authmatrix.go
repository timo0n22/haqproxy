// Package authmatrix — тестер доступа по ролям/сессиям (§7 ТЗ).
//
// Один и тот же запрос прогоняется под разными "личностями" (identity — набор
// подменяемых заголовков, например Cookie/Authorization разных пользователей),
// результаты сводятся в сравнительную таблицу. Прямое попадание в IDOR/broken
// access control: если низкопривилегированная identity получает тот же
// статус и близкую длину тела, что baseline (например Admin) — строка
// подсвечивается как потенциальная находка.
package authmatrix

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/timo0n22/haqproxy/internal/rawhttp"
	"github.com/timo0n22/haqproxy/internal/replay"
	"github.com/timo0n22/haqproxy/internal/store"
)

// Row — результат прогона под одной identity.
type Row struct {
	IdentityID   int64
	IdentityName string
	Status       *int
	BodyLen      int
	BodyHash     string // короткий (первые 12 hex) хэш тела ответа
	DurationMs   int
	Error        string
	IsBaseline   bool
	Suspicious   bool // эвристика IDOR: похоже на baseline, хотя не должно
}

// Run описывает один прогон матрицы.
type Run struct {
	Host string
	Port int
	TLS  bool
	Rows []Row
}

// Execute прогоняет rawRequest под каждой identity (первая в списке — baseline)
// и возвращает заполненный Run. verifyTLS — как в replay (по умолчанию false).
func Execute(host string, port int, tls bool, rawRequest []byte, identities []*store.Identity, timeout time.Duration) *Run {
	run := &Run{Host: host, Port: port, TLS: tls}
	if len(identities) == 0 {
		return run
	}

	var baseline *Row
	for i, idn := range identities {
		modified := ApplyOverrides(rawRequest, idn.Headers)
		res := replay.SendRaw(host, port, tls, modified, timeout, false)

		body := responseBody(res.RawResponse)
		row := Row{
			IdentityID:   idn.ID,
			IdentityName: idn.Name,
			Status:       res.Status,
			BodyLen:      len(body),
			BodyHash:     shortHash(body),
			DurationMs:   res.DurationMs,
			Error:        res.Error,
			IsBaseline:   i == 0,
		}
		run.Rows = append(run.Rows, row)
		if i == 0 {
			baseline = &run.Rows[0]
		}
	}

	// Эвристика: не-baseline строка "подозрительна", если её статус совпадает с
	// baseline и длина тела близка (в пределах 5% или 64 байт). Это значит, что
	// менее привилегированная identity получила примерно тот же ответ, что и
	// baseline — потенциальный broken access control.
	if baseline != nil && baseline.Status != nil {
		for i := 1; i < len(run.Rows); i++ {
			r := &run.Rows[i]
			if r.Status == nil || *r.Status != *baseline.Status {
				continue
			}
			if closeLen(r.BodyLen, baseline.BodyLen) {
				r.Suspicious = true
			}
		}
	}
	return run
}

// ApplyOverrides подменяет (или добавляет) заголовки в сыром запросе. Существующий
// заголовок с тем же именем (без учёта регистра) заменяется по значению с
// сохранением исходного имени в остальных строках; отсутствующий — добавляется
// в конец блока заголовков. Тело и стартовая строка не трогаются.
func ApplyOverrides(rawRequest []byte, overrides []store.HeaderOverride) []byte {
	if len(overrides) == 0 {
		return append([]byte{}, rawRequest...)
	}
	// Разделяем на блок заголовков и тело по первому \r\n\r\n.
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(rawRequest, sep)
	var headPart, rest []byte
	if idx < 0 {
		headPart = rawRequest
		rest = nil
	} else {
		headPart = rawRequest[:idx]
		rest = rawRequest[idx:] // включает ведущий \r\n\r\n
	}

	lines := strings.Split(string(headPart), "\r\n")
	if len(lines) == 0 {
		return append([]byte{}, rawRequest...)
	}
	startLine := lines[0]
	headerLines := lines[1:]

	used := make([]bool, len(overrides))
	var outHeaders []string
	for _, ln := range headerLines {
		name := headerName(ln)
		replaced := false
		for i, ov := range overrides {
			if strings.EqualFold(name, ov.Name) {
				outHeaders = append(outHeaders, ov.Name+": "+ov.Value)
				used[i] = true
				replaced = true
				break
			}
		}
		if !replaced {
			outHeaders = append(outHeaders, ln)
		}
	}
	// добавляем отсутствовавшие
	for i, ov := range overrides {
		if !used[i] {
			outHeaders = append(outHeaders, ov.Name+": "+ov.Value)
		}
	}

	var b bytes.Buffer
	b.WriteString(startLine)
	for _, h := range outHeaders {
		b.WriteString("\r\n")
		b.WriteString(h)
	}
	if rest != nil {
		b.Write(rest)
	} else {
		b.WriteString("\r\n\r\n")
	}
	return b.Bytes()
}

func headerName(line string) string {
	if i := strings.IndexByte(line, ':'); i >= 0 {
		return strings.TrimSpace(line[:i])
	}
	return ""
}

func responseBody(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	m, _ := rawhttp.ReadMessage(bufio.NewReader(bytes.NewReader(raw)), false)
	if m == nil {
		return nil
	}
	return m.Body
}

func shortHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])[:12]
}

func closeLen(a, b int) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	if d <= 64 {
		return true
	}
	tol := b / 20 // 5%
	return d <= tol
}
