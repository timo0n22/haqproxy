package automate

import "testing"

func ptr(i int) *int { return &i }

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
