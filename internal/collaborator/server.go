package collaborator

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	NS1    string // имя первого nameserver (по умолчанию ns1.<zone>)
	NS2    string // имя второго nameserver (по умолчанию ns2.<zone>)
}

// Server связывает store и слушатели.
type Server struct {
	cfg    Config
	store  *Store
	logger *log.Logger
	zone   string // нормализованная зона в нижнем регистре без точек по краям
	ns1    string
	ns2    string
	serial uint32
}

// NewServer создаёт сервер.
func NewServer(cfg Config, store *Store, logger *log.Logger) *Server {
	zone := strings.ToLower(strings.Trim(cfg.Zone, "."))
	ns1 := strings.ToLower(strings.Trim(cfg.NS1, "."))
	if ns1 == "" {
		ns1 = "ns1." + zone
	}
	ns2 := strings.ToLower(strings.Trim(cfg.NS2, "."))
	if ns2 == "" {
		ns2 = "ns2." + zone
	}
	return &Server{
		cfg:    cfg,
		store:  store,
		logger: logger,
		zone:   zone,
		ns1:    ns1,
		ns2:    ns2,
		serial: uint32(time.Now().Unix()),
	}
}

// ---------- DNS ----------

// ServeDNS реализует dns.Handler: логирует КАЖДЫЙ запрос (это и есть основной
// OOB-сигнал) и отвечает как авторитативный сервер зоны.
//
// Ключевое для пути «кастомные NS всего домена → VPS» (§10.3, вариант B): чтобы
// регистратор принял делегацию и зона считалась живой, сервер отвечает не только
// A-записью на IP VPS (wildcard-catch-all для любого поддомена), но и SOA/NS для
// апекса — их проверяют pre-delegation проверки регистраторов и резолверы.
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
		s.answerQuestion(m, q)
	}
	_ = w.WriteMsg(m)
}

// answerQuestion формирует ответ на один вопрос.
func (s *Server) answerQuestion(m *dns.Msg, q dns.Question) {
	apex := dns.Fqdn(s.zone)
	switch q.Qtype {
	case dns.TypeA:
		// Wildcard catch-all: любой поддомен резолвится в IP VPS, чтобы
		// последующий HTTP от цели тоже пришёл к нам.
		if ip := net.ParseIP(s.cfg.IP).To4(); ip != nil {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			})
		} else {
			m.Ns = append(m.Ns, s.soa())
		}
	case dns.TypeNS:
		if strings.EqualFold(q.Name, apex) {
			m.Answer = append(m.Answer,
				&dns.NS{Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: dns.Fqdn(s.ns1)},
				&dns.NS{Hdr: dns.RR_Header{Name: apex, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600}, Ns: dns.Fqdn(s.ns2)},
			)
		} else {
			m.Ns = append(m.Ns, s.soa())
		}
	case dns.TypeSOA:
		m.Answer = append(m.Answer, s.soa())
	default:
		// NODATA для прочих типов (AAAA и т.п.): кладём SOA в authority —
		// это форсирует откат цели на A-запись (→ HTTP-хит к нам по IPv4).
		m.Ns = append(m.Ns, s.soa())
	}
}

// soa возвращает SOA-запись зоны.
func (s *Server) soa() *dns.SOA {
	apex := dns.Fqdn(s.zone)
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      dns.Fqdn(s.ns1),
		Mbox:    "hostmaster." + apex,
		Serial:  s.serial,
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  3600,
	}
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
