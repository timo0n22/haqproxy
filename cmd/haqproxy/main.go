// Command haqproxy — headless-бинарник: MITM-прокси + вся история + веб-UI на
// HTTP-порту. Веб открывать в браузере НАПРЯМУЮ (не через сам прокси). Нативная
// GUI-обёртка того же UI — в cmd/haqproxy-gui.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/timo0n22/haqproxy/internal/app"
)

func main() {
	var (
		proxyAddr = flag.String("proxy", "127.0.0.1:8080", "адрес MITM-прокси")
		webAddr   = flag.String("web", "127.0.0.1:5050", "адрес веб-UI")
		dataDir   = flag.String("data", defaultDataDir(), "каталог данных (БД, CA)")
		domlogger = flag.Bool("domlogger", true, "инжектить DOM-sink-трекер в HTML-ответы хостов в scope")

		collabDomain = flag.String("collab-domain", "", "базовый домен Collaborator для payload'ов (напр. oob.example.com)")
		collabAPI    = flag.String("collab-api", "", "адрес API VPS-Collaborator (напр. http://vps-ip:8081)")
		collabSecret = flag.String("collab-secret", os.Getenv("HAQPROXY_COLLAB_SECRET"), "общий секрет API VPS-Collaborator")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)

	backend, err := app.Setup(app.Options{
		ProxyAddr:    *proxyAddr,
		DataDir:      *dataDir,
		DOMLogger:    *domlogger,
		CollabDomain: *collabDomain,
		CollabAPI:    *collabAPI,
		CollabSecret: *collabSecret,
	}, logger)
	if err != nil {
		logger.Fatalf("setup: %v", err)
	}
	defer backend.Close()

	logger.Printf("web UI:   http://%s  (установите CA из http://%s/ca-cert)", *webAddr, *webAddr)

	if err := http.ListenAndServe(*webAddr, backend.Handler); err != nil {
		logger.Fatalf("web serve: %v", err)
	}
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".haqproxy"
	}
	return filepath.Join(home, ".haqproxy")
}
