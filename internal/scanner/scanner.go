// Package scanner — пассивный scanner-lite (§8 ТЗ). Фиксированный набор правил
// v1 (не универсальный DSL — осознанно просто, под частые находки), прогоняется
// по каждому проксированному ответу. Результаты — Finding'и, которые вызывающий
// код сохраняет в store.
package scanner

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"

	"github.com/loginovartem/haqproxy/internal/rawhttp"
)

// Finding — одна находка (без entry_id, его проставляет вызывающий).
type Finding struct {
	Rule     string
	Severity string // info | low | medium | high
	Detail   string
}

// Scan прогоняет все правила по паре сырых запрос/ответ и возвращает находки.
func Scan(rawRequest, rawResponse []byte) []Finding {
	var findings []Finding
	if len(rawResponse) == 0 {
		return findings
	}

	req, _ := rawhttp.ReadMessage(bufio.NewReader(bytes.NewReader(rawRequest)), true)
	resp, _ := rawhttp.ReadMessage(bufio.NewReader(bytes.NewReader(rawResponse)), false)
	if resp == nil {
		return findings
	}

	findings = appendIf(findings, checkSecurityHeaders(resp))
	findings = appendIf(findings, checkVerboseErrors(resp))
	findings = appendIf(findings, checkSensitivePaths(resp))
	if req != nil {
		findings = appendIf(findings, checkReflectedParam(req, resp))
		findings = append(findings, checkJWT(req)...)
	}
	return findings
}

func appendIf(list []Finding, f *Finding) []Finding {
	if f != nil {
		list = append(list, *f)
	}
	return list
}

// --- Правило 1: отсутствие security-заголовков ---

func checkSecurityHeaders(resp *rawhttp.Message) *Finding {
	// Проверяем только для HTML-ответов: на статике/API часть заголовков не нужна.
	ct := strings.ToLower(resp.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil
	}
	want := []struct{ header, label string }{
		{"Content-Security-Policy", "CSP"},
		{"X-Frame-Options", "X-Frame-Options"},
		{"Strict-Transport-Security", "HSTS"},
		{"X-Content-Type-Options", "X-Content-Type-Options"},
	}
	var missing []string
	for _, wnt := range want {
		if resp.Get(wnt.header) == "" {
			missing = append(missing, wnt.label)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &Finding{
		Rule:     "missing-security-headers",
		Severity: "low",
		Detail:   "нет: " + strings.Join(missing, ", "),
	}
}

// --- Правило 2: отражение значения параметра в теле ответа ---

func checkReflectedParam(req, resp *rawhttp.Message) *Finding {
	body := resp.Body
	if len(body) == 0 {
		return nil
	}
	params := collectParams(req)
	for name, val := range params {
		if len(val) < 4 {
			continue // слишком короткие значения дают ложные срабатывания
		}
		if bytes.Contains(body, []byte(val)) {
			return &Finding{
				Rule:     "reflected-parameter",
				Severity: "medium",
				Detail:   "значение параметра " + name + " отражено в теле без экранирования (проверьте на XSS)",
			}
		}
	}
	return nil
}

func collectParams(req *rawhttp.Message) map[string]string {
	out := map[string]string{}
	parts := req.StartLineParts()
	if len(parts) >= 2 {
		if u, err := url.Parse(parts[1]); err == nil {
			for k, vs := range u.Query() {
				if len(vs) > 0 {
					out[k] = vs[0]
				}
			}
		}
	}
	// form-urlencoded тело
	ct := strings.ToLower(req.Get("Content-Type"))
	if strings.Contains(ct, "application/x-www-form-urlencoded") && len(req.Body) > 0 {
		if vals, err := url.ParseQuery(string(req.Body)); err == nil {
			for k, vs := range vals {
				if len(vs) > 0 {
					out[k] = vs[0]
				}
			}
		}
	}
	return out
}

// --- Правило 3: verbose-ошибки / стектрейсы в теле ---

var errorPatterns = regexp.MustCompile(`(?i)(Traceback \(most recent call last\)|at java\.|You have an error in your SQL syntax|Exception in thread|org\.springframework|System\.NullReferenceException|PHP (Warning|Fatal error)|ORA-\d{5}|psql: |stack trace:)`)

func checkVerboseErrors(resp *rawhttp.Message) *Finding {
	if len(resp.Body) == 0 {
		return nil
	}
	if m := errorPatterns.FindString(string(resp.Body)); m != "" {
		return &Finding{
			Rule:     "verbose-error",
			Severity: "medium",
			Detail:   "признаки стектрейса/verbose-ошибки в ответе: " + trim(m, 60),
		}
	}
	return nil
}

// --- Правило 4: слабые/none JWT в заголовках ---

func checkJWT(req *rawhttp.Message) []Finding {
	var out []Finding
	seen := map[string]bool{}
	candidates := []string{req.Get("Authorization"), req.Get("Cookie")}
	jwtRe := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	for _, hv := range candidates {
		for _, tok := range jwtRe.FindAllString(hv, -1) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			if f := inspectJWT(tok); f != nil {
				out = append(out, *f)
			}
		}
	}
	return out
}

func inspectJWT(tok string) *Finding {
	segs := strings.Split(tok, ".")
	if len(segs) < 2 {
		return nil
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return nil
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdrJSON, &hdr) != nil {
		return nil
	}
	switch strings.ToLower(hdr.Alg) {
	case "none":
		return &Finding{Rule: "jwt-alg-none", Severity: "high", Detail: `JWT с "alg":"none" — подпись не проверяется`}
	case "hs256":
		return &Finding{Rule: "jwt-hs256", Severity: "info", Detail: `JWT на HS256 — проверить на подбор слабого секрета`}
	}
	return nil
}

// --- Правило 5: упоминания чувствительных путей ---

var sensitiveRe = regexp.MustCompile(`(?i)(\.git/|/\.env\b|\.bak\b|\.sql\b|/\.svn/|id_rsa\b|\.htpasswd\b)`)

func checkSensitivePaths(resp *rawhttp.Message) *Finding {
	if len(resp.Body) == 0 {
		return nil
	}
	if m := sensitiveRe.FindString(string(resp.Body)); m != "" {
		return &Finding{
			Rule:     "sensitive-path-reference",
			Severity: "low",
			Detail:   "ссылка на потенциально чувствительный путь: " + m,
		}
	}
	return nil
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
