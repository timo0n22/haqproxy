package web

import "net/http"

func (s *Server) handleHistoryClear(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearHistory(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "history_rows", map[string]any{"Entries": nil})
}

func (s *Server) handleFindingsClear(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearFindings(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "findings_rows", map[string]any{"Findings": nil})
}

func (s *Server) handleDomClear(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearDomEvents(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "domlogger_rows", map[string]any{"Events": nil})
}

func (s *Server) handleMatrixClear(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearMatrix(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "matrix_results", map[string]any{"Rows": nil})
}

func (s *Server) handleOOBClear(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearOOBTokens(); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "oob_tokens", s.collabData())
}
