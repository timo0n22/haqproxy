// Package app собирает backend haqproxy (store + CA + MITM-прокси + web-UI) в
// единое целое, чтобы и headless-бинарник (cmd/haqproxy), и GUI-обёртка
// (cmd/haqproxy-gui) переиспользовали одну и ту же обвязку.
package app

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/timo0n22/haqproxy/internal/ca"
	"github.com/timo0n22/haqproxy/internal/proxy"
	"github.com/timo0n22/haqproxy/internal/scanner"
	"github.com/timo0n22/haqproxy/internal/store"
	"github.com/timo0n22/haqproxy/internal/web"
)

// Options — параметры запуска backend.
type Options struct {
	ProxyAddr    string
	DataDir      string
	DOMLogger    bool
	CollabDomain string
	CollabAPI    string
	CollabSecret string
}

// Backend — собранный и запущенный backend: HTTP-хендлер UI и владение ресурсами.
type Backend struct {
	Handler http.Handler
	store   *store.Store
}

// Close освобождает ресурсы backend.
func (b *Backend) Close() error { return b.store.Close() }

// Setup открывает БД и CA, поднимает MITM-прокси в отдельной горутине и
// возвращает готовый HTTP-хендлер веб-UI. Сам веб-сервер вызывающий код
// запускает как ему удобно (headless — http.ListenAndServe; GUI — http.Serve на
// локальном listener'е с последующим открытием нативного окна).
func Setup(opts Options, logger *log.Logger) (*Backend, error) {
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		return nil, err
	}

	st, err := store.Open(filepath.Join(opts.DataDir, "haqproxy.db"))
	if err != nil {
		return nil, err
	}

	rootCA, err := ca.LoadOrCreate(filepath.Join(opts.DataDir, "ca"))
	if err != nil {
		st.Close()
		return nil, err
	}

	websrv, err := web.New(st, rootCA.CertPEM(), logger)
	if err != nil {
		st.Close()
		return nil, err
	}
	websrv.SetCollaborator(opts.CollabDomain, opts.CollabAPI, opts.CollabSecret)

	p := proxy.New(rootCA, st, logger)
	p.DOMLogger = opts.DOMLogger

	// Пассивный scanner-lite по каждому проксированному ответу (в отдельной
	// горутине, чтобы не задерживать проксирование).
	p.AfterRecord = func(entryID int64, rawReq, rawResp []byte) {
		go func() {
			for _, f := range scanner.Scan(rawReq, rawResp) {
				if err := st.AddFinding(entryID, f.Rule, f.Severity, f.Detail); err != nil {
					logger.Printf("finding insert: %v", err)
				}
			}
		}()
	}

	go func() {
		if err := p.ListenAndServe(opts.ProxyAddr); err != nil {
			logger.Fatalf("proxy: %v", err)
		}
	}()

	logger.Printf("data dir: %s", opts.DataDir)
	logger.Printf("proxy:    http://%s", opts.ProxyAddr)

	return &Backend{Handler: websrv.Handler(), store: st}, nil
}
