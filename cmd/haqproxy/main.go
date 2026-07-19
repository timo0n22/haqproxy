// Command haqproxy — единый бинарник для рабочей машины: MITM-прокси + вся
// история + веб-UI (htmx). Веб открывать в браузере НАПРЯМУЮ (не через сам
// прокси), чтобы не проксировать самого себя.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/loginovartem/haqproxy/internal/ca"
	"github.com/loginovartem/haqproxy/internal/proxy"
	"github.com/loginovartem/haqproxy/internal/scanner"
	"github.com/loginovartem/haqproxy/internal/store"
	"github.com/loginovartem/haqproxy/internal/web"
)

func main() {
	var (
		proxyAddr = flag.String("proxy", "127.0.0.1:8080", "адрес MITM-прокси")
		webAddr   = flag.String("web", "127.0.0.1:5050", "адрес веб-UI")
		dataDir   = flag.String("data", defaultDataDir(), "каталог данных (БД, CA)")
	)
	flag.Parse()

	logger := log.New(os.Stdout, "", log.LstdFlags)

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		logger.Fatalf("data dir: %v", err)
	}

	st, err := store.Open(filepath.Join(*dataDir, "haqproxy.db"))
	if err != nil {
		logger.Fatalf("store: %v", err)
	}
	defer st.Close()

	rootCA, err := ca.LoadOrCreate(filepath.Join(*dataDir, "ca"))
	if err != nil {
		logger.Fatalf("ca: %v", err)
	}

	websrv, err := web.New(st, rootCA.CertPEM(), logger)
	if err != nil {
		logger.Fatalf("web: %v", err)
	}

	p := proxy.New(rootCA, st, logger)

	// Пассивный scanner-lite: прогоняем правила по каждому проксированному
	// ответу в отдельной горутине, чтобы не задерживать проксирование.
	p.AfterRecord = func(entryID int64, rawReq, rawResp []byte) {
		go func() {
			for _, f := range scanner.Scan(rawReq, rawResp) {
				if err := st.AddFinding(entryID, f.Rule, f.Severity, f.Detail); err != nil {
					logger.Printf("finding insert: %v", err)
				}
			}
		}()
	}

	// Прокси в отдельной горутине.
	go func() {
		if err := p.ListenAndServe(*proxyAddr); err != nil {
			logger.Fatalf("proxy: %v", err)
		}
	}()

	logger.Printf("data dir: %s", *dataDir)
	logger.Printf("web UI:   http://%s", *webAddr)
	logger.Printf("proxy:    http://%s  (установите CA из http://%s/ca-cert)", *proxyAddr, *webAddr)

	if err := http.ListenAndServe(*webAddr, websrv.Handler()); err != nil {
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
