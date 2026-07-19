package collaborator

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// Config — настройки серверной части Collaborator.
type Config struct {
	Zone   string // базовая зона, например "oob.example.com" (payload = <token>.oob.example.com)
	IP     string // IP, который отдаём A-записью (обычно IP самого VPS)
	Secret string // общий секрет для API (Bearer)
	DNS    string // адрес DNS-листенера, например ":53"
	HTTP   string // адрес HTTP-листенера, например ":80"
	API    string // адрес API-листенера, например ":8081"
}

// Server связывает store и слушатели.
type Server struct {
	cfg    Config
	store  *Store
	logger *log.Logger
	zone   string // нормализованная зона в нижнем регистре без точек по краям
}

// NewServer создаёт сервер.
func NewServer(cfg Config, store *Store, logger *log.Logger) *Server {
	return &Server{
		cfg:    cfg,
		store:  store,
		logger: logger,
		zone:   strings.ToLower(strings.Trim(cfg.Zone, ".")),
	}
}

// ---------- DNS ----------

// ServeDNS реализует dns.Handler: логирует КАЖДЫЙ запрос и отвечает A-записью
// на IP VPS (чтобы последующий HTTP от той же цели тоже пришёл к нам).
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	ip := clientIP(w.RemoteAddr())
	for _, q := range r.Question {
		name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		token := s.extractToken(name)
		if err := s.store.Add("dns", token, ip, name+" "+dns.TypeToString[q.Qtype]); err != nil {
			s.logf("dns store: %v", err)
		}
		s.logf("DNS %s %s from %s", dns.TypeToString[q.Qtype], name, ip)

		if q.Qtype == dns.TypeA && s.cfg.IP != "" {
			rr, err := dns.NewRR(q.Name + " 60 IN A " + s.cfg.IP)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	_ = w.WriteMsg(m)
}

// StartDNS запускает UDP и TCP DNS-листенеры (блокирует до ошибки).
func (s *Server) StartDNS() error {
	errc := make(chan error, 2)
	for _, proto := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: s.cfg.DNS, Net: proto, Handler: s}
		go func() { errc <- srv.ListenAndServe() }()
	}
	return <-errc
}

// ---------- HTTP (логгер OOB-хитов) ----------

// StartHTTP запускает HTTP-логгер: любой входящий запрос логируется, ответ 200.
func (s *Server) StartHTTP() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleOOB)
	return http.ListenAndServe(s.cfg.HTTP, mux)
}

func (s *Server) handleOOB(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	token := s.extractToken(strings.ToLower(host))
	ip := clientIP(nil, r.RemoteAddr)
	raw := r.Method + " " + r.URL.String() + " Host:" + r.Host + " UA:" + r.UserAgent()
	if err := s.store.Add("http", token, ip, raw); err != nil {
		s.logf("http store: %v", err)
	}
	s.logf("HTTP %s %s%s from %s", r.Method, r.Host, r.URL.Path, ip)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ---------- API для клиента ----------

// StartAPI запускает API с проверкой Bearer-секрета.
func (s *Server) StartAPI() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/interactions", s.handleInteractions)
	return http.ListenAndServe(s.cfg.API, mux)
}

func (s *Server) handleInteractions(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var since float64
	if v := r.URL.Query().Get("since"); v != "" {
		since, _ = strconv.ParseFloat(v, 64)
	}
	items, err := s.store.Since(since, 1000)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

func (s *Server) authorized(r *http.Request) bool {
	if s.cfg.Secret == "" {
		return false // без секрета API закрыт
	}
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+s.cfg.Secret
}

// ---------- helpers ----------

// extractToken возвращает метку слева от базовой зоны. Для "abc.oob.example.com"
// с зоной "oob.example.com" вернёт "abc". Если зона не совпала — крайнюю левую метку.
func (s *Server) extractToken(name string) string {
	name = strings.TrimSuffix(name, ".")
	if s.zone != "" && strings.HasSuffix(name, "."+s.zone) {
		prefix := strings.TrimSuffix(name, "."+s.zone)
		labels := strings.Split(prefix, ".")
		if len(labels) > 0 {
			return labels[len(labels)-1] // метка непосредственно слева от зоны
		}
	}
	labels := strings.Split(name, ".")
	if len(labels) > 0 {
		return labels[0]
	}
	return ""
}

func (s *Server) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// clientIP извлекает IP из net.Addr или из строки addr (второй аргумент опционален).
func clientIP(addr net.Addr, raw ...string) string {
	if addr != nil {
		if host, _, err := net.SplitHostPort(addr.String()); err == nil {
			return host
		}
		return addr.String()
	}
	if len(raw) > 0 {
		if host, _, err := net.SplitHostPort(raw[0]); err == nil {
			return host
		}
		return raw[0]
	}
	return ""
}
