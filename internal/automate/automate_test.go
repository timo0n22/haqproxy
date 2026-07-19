package automate

import "testing"

func ptr(i int) *int { return &i }

func TestCombinationsMatrix(t *testing.T) {
	pos := []Position{
		{Marker: "FUZZ1", Payloads: []string{"a", "b"}},
		{Marker: "FUZZ2", Payloads: []string{"1", "2", "3"}},
	}
	got := combinations(pos, MaxPayloads)
	if len(got) != 6 {
		t.Fatalf("ожидалось 6 комбинаций (2×3), получено %d", len(got))
	}
	for _, c := range got {
		if len(c) != 2 {
			t.Errorf("каждая комбинация должна иметь 2 значения, got %v", c)
		}
	}
	// первая комбинация — a,1; последняя — b,3
	if got[0][0] != "a" || got[0][1] != "1" || got[5][0] != "b" || got[5][1] != "3" {
		t.Errorf("неверный порядок комбинаций: %v", got)
	}
}

func TestCombinationsSingle(t *testing.T) {
	got := combinations([]Position{{Marker: "FUZZ1", Payloads: []string{"x", "y", "z"}}}, MaxPayloads)
	if len(got) != 3 {
		t.Fatalf("ожидалось 3, получено %d", len(got))
	}
}

func TestCombinationsCap(t *testing.T) {
	big := make([]string, 200)
	for i := range big {
		big[i] = "p"
	}
	got := combinations([]Position{{Marker: "A", Payloads: big}, {Marker: "B", Payloads: big}}, MaxPayloads)
	if len(got) > MaxPayloads {
		t.Errorf("превышен лимит MaxPayloads: %d", len(got))
	}
}

func TestMarkAnomalies(t *testing.T) {
	rs := []Result{
		{Status: ptr(404)},
		{Status: ptr(404)},
		{Status: ptr(200)}, // отличается от самого частого (404) — аномалия
		{Status: ptr(404)},
		{Status: ptr(301)}, // тоже аномалия
	}
	markAnomalies(rs)
	if rs[0].Suspicious || rs[1].Suspicious || rs[3].Suspicious {
		t.Error("baseline-строки (404) не должны быть подсвечены")
	}
	if !rs[2].Suspicious || !rs[4].Suspicious {
		t.Error("строки с иным статусом должны быть подсвечены")
	}
}

func TestMarkAnomaliesAllSame(t *testing.T) {
	rs := []Result{{Status: ptr(200)}, {Status: ptr(200)}, {Status: ptr(200)}}
	markAnomalies(rs)
	for i, r := range rs {
		if r.Suspicious {
			t.Errorf("строка %d не должна быть аномалией — все статусы одинаковы", i)
		}
	}
}

func TestMarkAnomaliesNilStatus(t *testing.T) {
	// ошибки (nil-статус) не должны паниковать и не считаются baseline
	rs := []Result{{Status: nil}, {Status: ptr(200)}, {Status: ptr(200)}}
	markAnomalies(rs)
	if rs[1].Suspicious || rs[2].Suspicious {
		t.Error("самый частый статус не должен подсвечиваться")
	}
}
