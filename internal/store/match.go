package store

import "strings"

// likeFromPattern превращает scope-паттерн ("*.example.com") в SQL LIKE-шаблон
// ("%.example.com"). Символ '*' → '%'.
func likeFromPattern(p string) string {
	return strings.ReplaceAll(p, "*", "%")
}

// matchHostPattern сопоставляет host с scope-паттерном на стороне Go (для InScope
// в горячем пути прокси, без обращения к SQL LIKE). Поддерживает один или
// несколько '*' как wildcard любой длины. Сравнение регистронезависимое.
func matchHostPattern(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if !strings.Contains(pattern, "*") {
		return pattern == host
	}
	parts := strings.Split(pattern, "*")
	// Первый сегмент должен быть префиксом.
	if parts[0] != "" && !strings.HasPrefix(host, parts[0]) {
		return false
	}
	pos := len(parts[0])
	for _, seg := range parts[1 : len(parts)-1] {
		idx := strings.Index(host[pos:], seg)
		if idx < 0 {
			return false
		}
		pos += idx + len(seg)
	}
	// Последний сегмент должен быть суффиксом.
	last := parts[len(parts)-1]
	if last != "" && !strings.HasSuffix(host[pos:], last) {
		return false
	}
	return true
}

func join(parts []string, sep string) string { return strings.Join(parts, sep) }
