// Command haqproxy-gui — нативная десктоп-обёртка haqproxy: тот же backend
// (MITM-прокси + история + web-UI), но UI открывается в нативном окне ОС
// (WKWebView на macOS), а не во вкладке браузера. Весь htmx-интерфейс
// переиспользуется как есть — сервер поднимается на локальном эфемерном порту,
// а окно навигируется на него.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	webview "github.com/webview/webview_go"

	"github.com/timo0n22/haqproxy/internal/app"
)

func main() {
	// Cocoa требует, чтобы UI жил на главном потоке; фиксируем main-горутину на
	// исходном (main) потоке до любого планирования горутин.
	runtime.LockOSThread()

	var (
		proxyAddr = flag.String("proxy", "127.0.0.1:8080", "адрес MITM-прокси")
		dataDir   = flag.String("data", defaultDataDir(), "каталог данных (БД, CA)")
		domlogger = flag.Bool("domlogger", true, "инжектить DOM-sink-трекер в HTML-ответы хостов в scope")

		collabDomain = flag.String("collab-domain", "", "базовый домен Collaborator для payload'ов")
		collabAPI    = flag.String("collab-api", "", "адрес API VPS-Collaborator")
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

	// UI-сервер на локальном эфемерном порту (только loopback).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	go func() {
		if err := http.Serve(ln, backend.Handler); err != nil {
			logger.Printf("web serve: %v", err)
		}
	}()

	url := "http://" + ln.Addr().String() + "/"
	logger.Printf("UI window -> %s", url)

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("haqproxy")
	w.SetSize(1280, 860, webview.HintNone)

	// Живое управление прозрачностью окна из вкладки Settings.
	if err := w.Bind("haq_setAlpha", func(alpha float64) {
		if alpha < 0.4 {
			alpha = 0.4
		}
		setWindowAlpha(w.Window(), alpha)
	}); err != nil {
		logger.Printf("bind: %v", err)
	}

	// Применяем сохранённую прозрачность при старте.
	if backend.UIAlpha > 0 && backend.UIAlpha < 1.0 {
		setWindowAlpha(w.Window(), backend.UIAlpha)
	}

	// Закрытие окна (крестик) завершает процесс, а не оставляет его в фоне.
	quitOnClose(w.Window())

	w.Navigate(url)
	w.Run()

	// На случай, если Run вернулся, но что-то держит процесс — выходим явно.
	backend.Close()
	os.Exit(0)
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".haqproxy"
	}
	return filepath.Join(home, ".haqproxy")
}
