package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/loginovartem/haqproxy/internal/authmatrix"
	"github.com/loginovartem/haqproxy/internal/store"
)

func (s *Server) handleMatrixView(w http.ResponseWriter, r *http.Request) {
	identities, err := s.store.ListIdentities()
	if err != nil {
		s.fail(w, err)
		return
	}
	data := map[string]any{
		"Identities": identities,
		"BasePort":   443,
		"BaseTLS":    true,
	}
	// Опциональный базовый запрос из истории (?base=id).
	if baseStr := r.URL.Query().Get("base"); baseStr != "" {
		if entry, _ := s.store.GetEntry(parseID(baseStr)); entry != nil {
			data["BaseID"] = entry.ID
			data["BaseHost"] = entry.Host
			data["BasePort"] = entry.Port
			data["BaseTLS"] = entry.Scheme == "https"
			data["BaseRaw"] = string(entry.RawRequest)
		}
	}
	s.render(w, "matrix_view", data)
}

func (s *Server) handleIdentityAdd(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	headers := parseHeaderLines(r.FormValue("headers"))
	if name != "" {
		if _, err := s.store.AddIdentity(name, headers); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.renderIdentityList(w)
}

func (s *Server) handleIdentityDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteIdentity(parseID(r.PathValue("id"))); err != nil {
		s.fail(w, err)
		return
	}
	s.renderIdentityList(w)
}

func (s *Server) renderIdentityList(w http.ResponseWriter) {
	identities, err := s.store.ListIdentities()
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "identity_list", map[string]any{"Identities": identities})
}

func (s *Server) handleMatrixRun(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	host := strings.TrimSpace(r.FormValue("host"))
	tls := r.FormValue("tls") == "1"
	port, _ := strconv.Atoi(r.FormValue("port"))
	if port <= 0 {
		if tls {
			port = 443
		} else {
			port = 80
		}
	}
	raw := normalizeCRLF(r.FormValue("raw_request"))

	// identity_id приходят в порядке DOM (порядок списка identity); первая
	// отмеченная — baseline.
	var identities []*store.Identity
	for _, idStr := range r.Form["identity_id"] {
		if idn, _ := s.store.GetIdentity(parseID(idStr)); idn != nil {
			identities = append(identities, idn)
		}
	}
	if host == "" || len(identities) == 0 {
		s.render(w, "matrix_results", map[string]any{"Rows": nil})
		return
	}

	run := authmatrix.Execute(host, port, tls, []byte(raw), identities, s.timeout)

	// Персистим прогон и результаты (§3 ТЗ).
	var baseEntryID *int64
	if v := r.FormValue("base_entry_id"); v != "" {
		id := parseID(v)
		baseEntryID = &id
	}
	if runID, err := s.store.CreateMatrixRun(baseEntryID); err == nil {
		for _, row := range run.Rows {
			_ = s.store.SaveMatrixResult(runID, row.IdentityID, row.Status, row.BodyLen, row.BodyHash, row.DurationMs)
		}
	}

	s.render(w, "matrix_results", map[string]any{"Rows": run.Rows})
}

// parseHeaderLines разбирает текст (по строке на заголовок "Name: value") в
// список подмен.
func parseHeaderLines(text string) []store.HeaderOverride {
	var out []store.HeaderOverride
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimRight(ln, "\r")
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		idx := strings.IndexByte(ln, ':')
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(ln[:idx])
		value := strings.TrimSpace(ln[idx+1:])
		if name != "" {
			out = append(out, store.HeaderOverride{Name: name, Value: value})
		}
	}
	return out
}
