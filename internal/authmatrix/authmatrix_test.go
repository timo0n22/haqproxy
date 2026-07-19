package authmatrix

import (
	"strings"
	"testing"

	"github.com/timo0n22/haqproxy/internal/store"
)

func TestApplyOverridesReplaceExisting(t *testing.T) {
	raw := []byte("GET /x HTTP/1.1\r\nHost: t\r\nCookie: old=1\r\n\r\n")
	out := ApplyOverrides(raw, []store.HeaderOverride{{Name: "Cookie", Value: "session=admin"}})
	s := string(out)
	if strings.Contains(s, "old=1") {
		t.Errorf("старое значение Cookie не заменено: %q", s)
	}
	if !strings.Contains(s, "Cookie: session=admin") {
		t.Errorf("новое значение Cookie отсутствует: %q", s)
	}
	// стартовая строка и Host не тронуты
	if !strings.HasPrefix(s, "GET /x HTTP/1.1\r\nHost: t\r\n") {
		t.Errorf("стартовая строка/Host изменены: %q", s)
	}
}

func TestApplyOverridesCaseInsensitive(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nhost: t\r\nAUTHORIZATION: Bearer old\r\n\r\n")
	out := ApplyOverrides(raw, []store.HeaderOverride{{Name: "Authorization", Value: "Bearer new"}})
	s := string(out)
	if strings.Contains(s, "Bearer old") || !strings.Contains(s, "Authorization: Bearer new") {
		t.Errorf("регистронезависимая замена не сработала: %q", s)
	}
	if strings.Count(s, "uthorization") != 1 {
		t.Errorf("заголовок задублирован: %q", s)
	}
}

func TestApplyOverridesAddMissing(t *testing.T) {
	raw := []byte("GET / HTTP/1.1\r\nHost: t\r\n\r\n")
	out := ApplyOverrides(raw, []store.HeaderOverride{{Name: "Cookie", Value: "s=1"}})
	s := string(out)
	if !strings.Contains(s, "Cookie: s=1") {
		t.Errorf("отсутствующий заголовок не добавлен: %q", s)
	}
	if !strings.HasSuffix(s, "\r\n\r\n") {
		t.Errorf("завершающий CRLF потерян: %q", s)
	}
}

func TestApplyOverridesPreservesBody(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 5\r\n\r\nhello")
	out := ApplyOverrides(raw, []store.HeaderOverride{{Name: "Cookie", Value: "s=1"}})
	if !strings.HasSuffix(string(out), "\r\n\r\nhello") {
		t.Errorf("тело не сохранено: %q", string(out))
	}
}

func TestCloseLen(t *testing.T) {
	if !closeLen(1000, 1030) {
		t.Error("1000 vs 1030 должны считаться близкими (в пределах 5%)")
	}
	if closeLen(1000, 2000) {
		t.Error("1000 vs 2000 не близки")
	}
	if !closeLen(10, 40) {
		t.Error("малые значения в пределах 64 байт близки")
	}
}
