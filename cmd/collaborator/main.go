// Command collaborator — OOB-слушатель для VPS (§10.2 ТЗ): авторитативный DNS +
// HTTP-логгер + API с Bearer-авторизацией, своя SQLite.
//
// Инфраструктурный шаг (НЕ код, §10.3): нужна NS-делегация зоны на этот VPS,
// а не просто wildcard A-запись — иначе DNS-резолвы (самый надёжный OOB-сигнал,
// проходящий через egress-firewall) не будут видны. Проще всего — отдельный
// дешёвый домен с кастомными NS на этот VPS.
//
// Секрет НЕ хардкодится: берётся из флага -secret или переменной окружения
// HAQPROXY_COLLAB_SECRET.
package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/timo0n22/haqproxy/internal/collaborator"
)

func main() {
	var (
		zone     = flag.String("zone", "oob.example.com", "базовая зона (payload = <token>.<zone>)")
		ip       = flag.String("ip", "", "IP для A-ответа (обычно IP этого VPS)")
		secret   = flag.String("secret", os.Getenv("HAQPROXY_COLLAB_SECRET"), "общий секрет для API (Bearer)")
		dnsAddr  = flag.String("dns", ":53", "адрес DNS-листенера")
		httpAddr = flag.String("http", ":80", "адрес HTTP-логгера")
		apiAddr  = flag.String("api", ":8081", "адрес API")
		ns1      = flag.String("ns1", "", "имя первого nameserver (по умолчанию ns1.<zone>)")
		ns2      = flag.String("ns2", "", "имя второго nameserver (по умолчанию ns2.<zone>)")
		dataDir  = flag.String("data", ".", "каталог для БД interactions")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "collab ", log.LstdFlags)

	if *secret == "" {
		logger.Fatal("не задан -secret (или HAQPROXY_COLLAB_SECRET) — API был бы открыт")
	}
	if *ip == "" {
		logger.Fatal("не задан -ip: без IP авторитативный сервер не сможет отвечать A-записями")
	}

	store, err := collaborator.OpenStore(filepath.Join(*dataDir, "collaborator.db"))
	if err != nil {
		logger.Fatalf("store: %v", err)
	}
	defer store.Close()

	srv := collaborator.NewServer(collaborator.Config{
		Zone: *zone, IP: *ip, Secret: *secret,
		DNS: *dnsAddr, HTTP: *httpAddr, API: *apiAddr,
		NS1: *ns1, NS2: *ns2,
	}, store, logger)

	logger.Printf("zone=%s ip=%s dns=%s http=%s api=%s", *zone, *ip, *dnsAddr, *httpAddr, *apiAddr)

	go func() {
		if err := srv.StartHTTP(); err != nil {
			logger.Fatalf("http: %v", err)
		}
	}()
	go func() {
		if err := srv.StartAPI(); err != nil {
			logger.Fatalf("api: %v", err)
		}
	}()
	if err := srv.StartDNS(); err != nil {
		logger.Fatalf("dns: %v", err)
	}
}
