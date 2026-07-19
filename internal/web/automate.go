package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/timo0n22/haqproxy/internal/automate"
)

// automateState — состояние вкладки Automate в памяти процесса (последний прогон
// и параметры базового запроса). Не персистится — чтобы ничего не копить в БД.
type automateState struct {
	Host    string
	Port    int
	TLS     bool
	RawReq  string
	Marker  string
	Results []automate.Result
}

func (s *Server) automateData() map[string]any {
	s.automateMu.Lock()
	defer s.automateMu.Unlock()
	st := s.automate
	if st == nil {
		st = &automateState{Port: 443, TLS: true, Marker: "FUZZ",
			RawReq: "GET /FUZZ HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"}
	}
	return map[string]any{
		"Host": st.Host, "Port": st.Port, "TLS": st.TLS,
		"RawReq": st.RawReq, "Marker": st.Marker, "Results": st.Results,
	}
}

func (s *Server) handleAutomateView(w http.ResponseWriter, r *http.Request) {
	s.render(w, "automate_view", s.automateData())
}

func (s *Server) handleAutomateFrom(w http.ResponseWriter, r *http.Request) {
	entry, err := s.store.GetEntry(parseID(r.PathValue("id")))
	if err != nil {
		s.fail(w, err)
		return
	}
	if entry == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.automateMu.Lock()
	s.automate = &automateState{
		Host: entry.Host, Port: entry.Port, TLS: entry.Scheme == "https",
		RawReq: string(entry.RawRequest), Marker: "FUZZ",
	}
	s.automateMu.Unlock()
	s.render(w, "automate_view", s.automateData())
}

func (s *Server) handleAutomateRun(w http.ResponseWriter, r *http.Request) {
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
	marker := strings.TrimSpace(r.FormValue("marker"))
	if marker == "" {
		marker = "FUZZ"
	}
	raw := normalizeCRLF(r.FormValue("raw_request"))
	payloads := splitPayloads(r.FormValue("payloads"))

	if host == "" || len(payloads) == 0 {
		s.render(w, "automate_results", map[string]any{"Results": nil, "Marker": marker})
		return
	}

	results := automate.Run(host, port, tls, raw, marker, payloads, s.timeout)

	s.automateMu.Lock()
	s.automate = &automateState{Host: host, Port: port, TLS: tls, RawReq: r.FormValue("raw_request"), Marker: marker, Results: results}
	s.automateMu.Unlock()

	s.render(w, "automate_results", map[string]any{"Results": results, "Marker": marker})
}

func (s *Server) handleAutomateClear(w http.ResponseWriter, r *http.Request) {
	s.automateMu.Lock()
	if s.automate != nil {
		s.automate.Results = nil
	}
	s.automateMu.Unlock()
	s.render(w, "automate_results", map[string]any{"Results": nil})
}

func splitPayloads(text string) []string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimRight(ln, "\r")
		if strings.TrimSpace(ln) == "" {
			continue
		}
		out = append(out, ln)
	}
	return out
}
