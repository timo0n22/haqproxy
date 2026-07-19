// Package automate — аналог Intruder / Caido Automate: базовый запрос с маркером
// прогоняется по списку payload'ов (маркер заменяется на каждый payload),
// результаты сводятся в таблицу для поиска аномалий (другой статус/длина).
package automate

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/timo0n22/haqproxy/internal/replay"
)

// MaxPayloads — предохранитель от запредельных прогонов.
const MaxPayloads = 5000

// Result — исход одного запроса.
type Result struct {
	Index      int
	Payload    string
	Status     *int
	Length     int // длина сырого ответа в байтах
	DurationMs int
	Error      string
	Suspicious bool // статус отличается от самого частого (baseline)
}

// Run прогоняет rawTemplate по payloads, заменяя каждое вхождение marker на
// payload. Запросы шлёт с ограниченной конкуренцией, порядок результатов
// сохраняется. rawTemplate уже должен быть с CRLF-переводами строк.
func Run(host string, port int, tls bool, rawTemplate, marker string, payloads []string, timeout time.Duration) []Result {
	if marker == "" {
		marker = "FUZZ"
	}
	if len(payloads) > MaxPayloads {
		payloads = payloads[:MaxPayloads]
	}
	results := make([]Result, len(payloads))

	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, p := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			req := strings.ReplaceAll(rawTemplate, marker, p)
			res := replay.SendRaw(host, port, tls, []byte(req), timeout, false)
			r := Result{Index: i, Payload: p, DurationMs: res.DurationMs, Error: res.Error}
			if res.Status != nil {
				r.Status = res.Status
			}
			r.Length = len(res.RawResponse)
			results[i] = r
		}(i, p)
	}
	wg.Wait()

	markAnomalies(results)
	return results
}

// markAnomalies подсвечивает строки, чей статус отличается от самого частого
// (грубая эвристика «стоит посмотреть»).
func markAnomalies(rs []Result) {
	freq := map[int]int{}
	for _, r := range rs {
		if r.Status != nil {
			freq[*r.Status]++
		}
	}
	if len(freq) < 2 {
		return // все одинаковые — подсвечивать нечего
	}
	// самый частый статус — baseline
	type kv struct {
		code, n int
	}
	var pairs []kv
	for c, n := range freq {
		pairs = append(pairs, kv{c, n})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].n > pairs[j].n })
	baseline := pairs[0].code
	for i := range rs {
		if rs[i].Status != nil && *rs[i].Status != baseline {
			rs[i].Suspicious = true
		}
	}
}
