package web

import (
	"net/http"
	"os"
	"time"
)

// handleQuit завершает процесс. Работает и в GUI (окно закрывается вместе с
// процессом), и в headless. Отвечаем до выхода, чтобы клиент успел получить ответ.
func (s *Server) handleQuit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(`<div class="hint">Завершение…</div>`))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}()
}
