package web

import (
	"net/http"
	"strconv"
)

func (s *Server) handleFindingsView(w http.ResponseWriter, r *http.Request) {
	findings, err := s.store.ListFindings(300)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "findings_view", map[string]any{"Findings": findings})
}

func (s *Server) handleFindingsRows(w http.ResponseWriter, r *http.Request) {
	findings, err := s.store.ListFindings(300)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "findings_rows", map[string]any{"Findings": findings})
}

func (s *Server) handleFindingsCount(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountFindings()
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(strconv.Itoa(n)))
}
