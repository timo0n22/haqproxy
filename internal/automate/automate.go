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

// MaxPayloads — предохранитель от запредельных прогонов (в т.ч. для комбинаций
// в режиме матрицы FUZZ1 × FUZZ2).
const MaxPayloads = 5000

// Position — одна позиция подстановки: маркер и его список payload'ов.
type Position struct {
	Marker   string
	Payloads []string
}

// Result — исход одного запроса. Payloads — значения по позициям (одно для
// одиночного режима, два для матрицы).
type Result struct {
	Index      int
	Payloads   []string
	Status     *int
	Length     int // длина сырого ответа в байтах
	DurationMs int
	Error      string
	Suspicious bool // статус отличается от самого частого (baseline)
}

// Run прогоняет rawTemplate по позициям: для одной позиции — по списку payload'ов,
// для двух — по всем комбинациям (декартово произведение, режим «матрица»).
// Каждый маркер заменяется на соответствующее значение. rawTemplate уже должен
// быть с CRLF-переводами строк.
func Run(host string, port int, tls bool, rawTemplate string, positions []Position, timeout time.Duration) []Result {
	var active []Position
	for _, p := range positions {
		if p.Marker != "" && len(p.Payloads) > 0 {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return nil
	}

	combos := combinations(active, MaxPayloads)
	results := make([]Result, len(combos))

	const workers = 8
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, combo := range combos {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, combo []string) {
			defer wg.Done()
			defer func() { <-sem }()
			req := rawTemplate
			for j, pos := range active {
				req = strings.ReplaceAll(req, pos.Marker, combo[j])
			}
			res := replay.SendRaw(host, port, tls, []byte(req), timeout, false)
			r := Result{Index: i, Payloads: combo, DurationMs: res.DurationMs, Error: res.Error}
			if res.Status != nil {
				r.Status = res.Status
			}
			r.Length = len(res.RawResponse)
			results[i] = r
		}(i, combo)
	}
	wg.Wait()

	markAnomalies(results)
	return results
}

// combinations строит декартово произведение payload'ов по позициям, ограничивая
// общее число max (грубо — прерываясь при достижении лимита).
func combinations(positions []Position, max int) [][]string {
	combos := [][]string{{}}
	for _, pos := range positions {
		var next [][]string
		for _, prefix := range combos {
			for _, p := range pos.Payloads {
				c := make([]string, len(prefix)+1)
				copy(c, prefix)
				c[len(prefix)] = p
				next = append(next, c)
				if len(next) >= max {
					break
				}
			}
			if len(next) >= max {
				break
			}
		}
		combos = next
	}
	return combos
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
