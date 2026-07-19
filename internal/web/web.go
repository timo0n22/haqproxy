// Package web — HTTP-хендлеры + html/template (htmx) для UI haqproxy (§11 ТЗ).
// Сервер рендерит HTML-фрагменты, htmx подменяет их по месту — почти без своего JS.
package web

import (
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/timo0n22/haqproxy/internal/collaboratorclient"
	"github.com/timo0n22/haqproxy/internal/httpql"
	"github.com/timo0n22/haqproxy/internal/replay"
	"github.com/timo0n22/haqproxy/internal/store"
	webassets "github.com/timo0n22/haqproxy/web"
)

// Ключи настроек в store (вкладка Settings).
const (
	SettingCollabDomain  = "collab_domain"
	SettingCollabAPI     = "collab_api"
	SettingCollabSecret  = "collab_secret"
	SettingUITheme       = "ui_theme"
	SettingUIWindowAlpha = "ui_window_alpha"
)

// DefaultTheme — тема по умолчанию, если не выбрана.
const DefaultTheme = "tokyo-night"

// Server — веб-бэкенд UI.
type Server struct {
	store   *store.Store
	caPEM   []byte
	tmpl    *template.Template
	tabs    *tabManager
	logger  *log.Logger
	timeout time.Duration

	collabDomain string
	collab       *collaboratorclient.Client

	automateMu sync.Mutex
	automate   *automateState
}

// SetCollaborator задаёт параметры Collaborator: базовый домен для payload'ов
// и клиента для опроса VPS.
func (s *Server) SetCollaborator(domain, apiBase, secret string) {
	s.collabDomain = domain
	s.collab = collaboratorclient.New(apiBase, secret)
}

// New создаёт веб-сервер. caPEM — PEM корневого CA для отдачи на установку.
func New(s *store.Store, caPEM []byte, logger *log.Logger) (*Server, error) {
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{
		store:   s,
		caPEM:   caPEM,
		tmpl:    tmpl,
		tabs:    newTabManager(),
		logger:  logger,
		timeout: 20 * time.Second,
	}, nil
}

func parseTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"status":      statusStr,
		"statusClass": statusClass,
		"dur":         durStr,
		"bytesStr":    bytesStr,
		"deref":       deref,
	}
	return template.New("").Funcs(funcs).ParseFS(webassets.FS, "templates/*.html")
}

// Handler возвращает http.Handler со всеми маршрутами.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// статика из встроенной FS
	staticFS, _ := fs.Sub(webassets.FS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /ca-cert", s.handleCACert)
	mux.HandleFunc("POST /api/quit", s.handleQuit)

	// History
	mux.HandleFunc("GET /view/history", s.handleHistoryView)
	mux.HandleFunc("GET /view/history/rows", s.handleHistoryRows)
	mux.HandleFunc("GET /view/entry/{id}", s.handleEntryDetail)
	mux.HandleFunc("POST /api/entry/{id}/meta", s.handleEntryMeta)

	// Replay
	mux.HandleFunc("GET /view/replay", s.handleReplayView)
	mux.HandleFunc("POST /api/replay/new", s.handleReplayNew)
	mux.HandleFunc("GET /view/replay/tab/{id}", s.handleReplayTab)
	mux.HandleFunc("GET /view/replay/from/{id}", s.handleReplayFrom)
	mux.HandleFunc("POST /api/replay/close/{id}", s.handleReplayClose)
	mux.HandleFunc("POST /api/replay/send/{id}", s.handleReplaySend)

	// AuthMatrix
	mux.HandleFunc("GET /view/matrix", s.handleMatrixView)
	mux.HandleFunc("POST /api/identities", s.handleIdentityAdd)
	mux.HandleFunc("DELETE /api/identities/{id}", s.handleIdentityDelete)
	mux.HandleFunc("POST /api/matrix/run", s.handleMatrixRun)

	// Findings (scanner-lite)
	mux.HandleFunc("GET /view/findings", s.handleFindingsView)
	mux.HandleFunc("GET /view/findings/rows", s.handleFindingsRows)
	mux.HandleFunc("GET /view/findings/count", s.handleFindingsCount)

	// Collaborator (OOB)
	mux.HandleFunc("GET /view/collaborator", s.handleCollabView)
	mux.HandleFunc("POST /api/oob/generate", s.handleOOBGenerate)
	mux.HandleFunc("GET /view/collaborator/interactions", s.handleCollabInteractions)

	// DOM Logger
	mux.HandleFunc("GET /view/domlogger", s.handleDomView)
	mux.HandleFunc("GET /view/domlogger/rows", s.handleDomRows)
	mux.HandleFunc("GET /view/domlogger/count", s.handleDomCount)

	// Automate (Intruder-подобный прогон по payload'ам)
	mux.HandleFunc("GET /view/automate", s.handleAutomateView)
	mux.HandleFunc("GET /view/automate/from/{id}", s.handleAutomateFrom)
	mux.HandleFunc("POST /api/automate/run", s.handleAutomateRun)
	mux.HandleFunc("POST /api/automate/clear", s.handleAutomateClear)

	// Очистка накопленных данных
	mux.HandleFunc("POST /api/history/clear", s.handleHistoryClear)
	mux.HandleFunc("POST /api/findings/clear", s.handleFindingsClear)
	mux.HandleFunc("POST /api/domlogger/clear", s.handleDomClear)
	mux.HandleFunc("POST /api/matrix/clear", s.handleMatrixClear)
	mux.HandleFunc("POST /api/oob/clear", s.handleOOBClear)

	// Settings
	mux.HandleFunc("GET /view/settings", s.handleSettingsView)
	mux.HandleFunc("POST /api/settings/collaborator", s.handleSettingsCollaborator)
	mux.HandleFunc("POST /api/settings/ui", s.handleSettingsUI)

	// Scope
	mux.HandleFunc("GET /view/scope", s.handleScopeView)
	mux.HandleFunc("POST /api/scope", s.handleScopeAdd)
	mux.HandleFunc("DELETE /api/scope/{id}", s.handleScopeDelete)
	mux.HandleFunc("POST /api/scope/{id}/toggle", s.handleScopeToggle)

	return mux
}

// ---------- Index / CA ----------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	entries, err := s.store.ListEntries(store.QueryFilter{Limit: 200})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "layout.html", map[string]any{"Entries": entries, "Theme": s.currentTheme()})
}

func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="haqproxy-ca.pem"`)
	w.Write(s.caPEM)
}

// ---------- History ----------

func (s *Server) handleHistoryView(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListEntries(store.QueryFilter{Limit: 200})
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "history_view", map[string]any{"Entries": entries})
}

func (s *Server) handleHistoryRows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	compiled, err := httpql.Compile(q)
	if err != nil {
		s.renderRowsError(w, err.Error())
		return
	}
	f := store.QueryFilter{
		Source:    r.URL.Query().Get("source"),
		ScopeOnly: r.URL.Query().Get("scope_only") == "1",
		WhereSQL:  compiled.SQL,
		WhereArgs: compiled.Args,
		Limit:     300,
	}
	entries, err := s.store.ListEntries(f)
	if err != nil {
		s.renderRowsError(w, err.Error())
		return
	}
	s.render(w, "history_rows", map[string]any{"Entries": entries})
}

func (s *Server) renderRowsError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	template.HTMLEscape(w, []byte(`<tr><td colspan="7" class="empty err">HTTPQL: `))
	template.HTMLEscape(w, []byte(msg))
	w.Write([]byte(`</td></tr>`))
}

func (s *Server) handleEntryDetail(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	entry, err := s.store.GetEntry(id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.render(w, "entry_detail", map[string]any{"Entry": entry})
}

func (s *Server) handleEntryMeta(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	r.ParseForm()
	var note, tag *string
	if v := r.FormValue("note"); v != "" {
		note = &v
	}
	if v := r.FormValue("tag"); v != "" {
		tag = &v
	}
	if err := s.store.UpdateEntryMeta(id, note, tag); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Replay ----------

func (s *Server) replayData() map[string]any {
	tabs, active, activeID := s.tabs.snapshot()
	return map[string]any{"Tabs": tabs, "Active": active, "ActiveID": activeID}
}

func (s *Server) handleReplayView(w http.ResponseWriter, r *http.Request) {
	s.render(w, "replay_view", s.replayData())
}

func (s *Server) handleReplayNew(w http.ResponseWriter, r *http.Request) {
	n := len(s.mustTabsNames()) + 1
	s.tabs.newTab("Tab " + strconv.Itoa(n))
	s.render(w, "replay_view", s.replayData())
}

func (s *Server) mustTabsNames() []*ReplayTab {
	t, _, _ := s.tabs.snapshot()
	return t
}

func (s *Server) handleReplayTab(w http.ResponseWriter, r *http.Request) {
	s.tabs.setActive(int(parseID(r.PathValue("id"))))
	s.render(w, "replay_view", s.replayData())
}

func (s *Server) handleReplayClose(w http.ResponseWriter, r *http.Request) {
	s.tabs.close(int(parseID(r.PathValue("id"))))
	s.render(w, "replay_view", s.replayData())
}

func (s *Server) handleReplayFrom(w http.ResponseWriter, r *http.Request) {
	id := parseID(r.PathValue("id"))
	entry, err := s.store.GetEntry(id)
	if err != nil {
		s.fail(w, err)
		return
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	tls := entry.Scheme == "https"
	name := "#" + strconv.FormatInt(entry.ID, 10) + " " + entry.Host
	s.tabs.newTabFrom(name, entry.Host, entry.Port, tls, string(entry.RawRequest))
	s.render(w, "replay_view", s.replayData())
}

func (s *Server) handleReplaySend(w http.ResponseWriter, r *http.Request) {
	tab := s.tabs.get(int(parseID(r.PathValue("id"))))
	if tab == nil {
		http.Error(w, "no tab", http.StatusNotFound)
		return
	}
	r.ParseForm()
	tab.Host = strings.TrimSpace(r.FormValue("host"))
	tab.TLS = r.FormValue("tls") == "1"
	if p, err := strconv.Atoi(r.FormValue("port")); err == nil && p > 0 {
		tab.Port = p
	} else if tab.Port == 0 {
		if tab.TLS {
			tab.Port = 443
		} else {
			tab.Port = 80
		}
	}
	// Нормализуем переводы строк из textarea (браузер шлёт \n) в \r\n, как того
	// требует HTTP на уровне байтов.
	raw := normalizeCRLF(r.FormValue("raw_request"))
	tab.RawRequest = r.FormValue("raw_request")

	res := replay.SendRaw(tab.Host, tab.Port, tab.TLS, []byte(raw), s.timeout, false)
	tab.LastResponse = bytesStr(res.RawResponse)
	tab.LastStatus = res.Status
	tab.LastDurationMs = res.DurationMs
	tab.LastError = res.Error

	// Пишем в историю как source='replay', привязка к базовой записи не нужна для v1.
	var status *int = res.Status
	dur := res.DurationMs
	method, path := "?", "?"
	if parts := strings.SplitN(raw, "\r\n", 2); len(parts) > 0 {
		if fields := strings.SplitN(parts[0], " ", 3); len(fields) >= 2 {
			method, path = fields[0], fields[1]
		}
	}
	scheme := "http"
	if tab.TLS {
		scheme = "https"
	}
	entry := &store.Entry{
		Source:      "replay",
		Host:        tab.Host,
		Port:        tab.Port,
		Scheme:      scheme,
		Method:      method,
		Path:        path,
		RespStatus:  status,
		DurationMs:  &dur,
		RawRequest:  []byte(raw),
		RawResponse: res.RawResponse,
	}
	if res.Error != "" {
		entry.Error = &res.Error
	}
	if _, err := s.store.InsertEntry(entry); err != nil {
		s.logf("replay store insert: %v", err)
	}

	s.render(w, "replay_response", map[string]any{"Active": tab})
}

// ---------- Scope ----------

func (s *Server) handleScopeView(w http.ResponseWriter, r *http.Request) {
	scope, err := s.store.ListScope()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "scope_view", map[string]any{"Scope": scope})
}

func (s *Server) handleScopeAdd(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	pattern := strings.TrimSpace(r.FormValue("pattern"))
	if pattern != "" {
		if err := s.store.AddScope(pattern); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.renderScopeList(w)
}

func (s *Server) handleScopeDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RemoveScope(parseID(r.PathValue("id"))); err != nil {
		s.fail(w, err)
		return
	}
	s.renderScopeList(w)
}

func (s *Server) handleScopeToggle(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	enabled := r.FormValue("enabled") == "1"
	if err := s.store.SetScopeEnabled(parseID(r.PathValue("id")), enabled); err != nil {
		s.fail(w, err)
		return
	}
	s.renderScopeList(w)
}

func (s *Server) renderScopeList(w http.ResponseWriter) {
	scope, err := s.store.ListScope()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "scope_list", map[string]any{"Scope": scope})
}

// ---------- helpers ----------

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.logf("template %s: %v", name, err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.logf("handler error: %v", err)
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func (s *Server) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

func parseID(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// ---------- template funcs ----------

func statusStr(code *int) string {
	if code == nil {
		return "—"
	}
	return strconv.Itoa(*code)
}

func statusClass(code *int) string {
	if code == nil {
		return ""
	}
	return "status-" + strconv.Itoa(*code/100)
}

func durStr(ms *int) string {
	if ms == nil {
		return ""
	}
	return strconv.Itoa(*ms)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// bytesStr превращает сырые байты в строку для отображения, заменяя
// невалидный UTF-8 на U+FFFD (иначе html/template может обрезать вывод).
func bytesStr(b []byte) string {
	if b == nil {
		return ""
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}
