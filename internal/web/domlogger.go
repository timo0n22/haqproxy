package web

import (
	"net/http"
	"strconv"
)

func (s *Server) handleDomView(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListDomEvents(300)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "domlogger_view", map[string]any{"Events": events})
}

func (s *Server) handleDomRows(w http.ResponseWriter, r *http.Request) {
	events, err := s.store.ListDomEvents(300)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "domlogger_rows", map[string]any{"Events": events})
}

func (s *Server) handleDomCount(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.CountDomEvents()
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(strconv.Itoa(n)))
}
