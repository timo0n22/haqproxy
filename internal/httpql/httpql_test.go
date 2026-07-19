package httpql

import "testing"

func TestCompileValid(t *testing.T) {
	cases := []struct {
		q       string
		wantSQL string
		wantN   int // число аргументов
	}{
		{"", "", 0},
		{`method.eq:"POST"`, "method = ?", 1},
		{`host.cont:"api"`, "host LIKE ?", 1},
		{`status.gte:400`, "resp_status >= ?", 1},
		{`method.eq:"POST" and status.gte:400`, "method = ? AND resp_status >= ?", 2},
		{`host.cont:"api" or source.eq:"replay"`, "host LIKE ? OR source = ?", 2},
		{`body.cont:"secret"`, "(raw_request LIKE ? OR raw_response LIKE ?)", 2},
	}
	for _, c := range cases {
		got, err := Compile(c.q)
		if err != nil {
			t.Fatalf("Compile(%q) error: %v", c.q, err)
		}
		if got.SQL != c.wantSQL {
			t.Errorf("Compile(%q).SQL = %q, want %q", c.q, got.SQL, c.wantSQL)
		}
		if len(got.Args) != c.wantN {
			t.Errorf("Compile(%q) args = %d, want %d", c.q, len(got.Args), c.wantN)
		}
	}
}

func TestCompileMethodUppercased(t *testing.T) {
	got, err := Compile(`method.eq:"post"`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Args[0] != "POST" {
		t.Errorf("method value = %v, want POST", got.Args[0])
	}
}

func TestCompileStatusIsInt(t *testing.T) {
	got, err := Compile(`status.eq:404`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Args[0] != 404 {
		t.Errorf("status arg = %v (%T), want int 404", got.Args[0], got.Args[0])
	}
}

func TestCompileErrors(t *testing.T) {
	bad := []string{
		`method.zz:1`,                 // неизвестный оператор
		`nope.eq:"x"`,                 // неизвестное поле
		`host.gt:5`,                   // gt только для status
		`method.eq:"a" and`,           // обрыв на and
		`and method.eq:"a"`,           // начинается с and
		`method.eq:"a" method.eq:"b"`, // нет коннектора
	}
	for _, q := range bad {
		if _, err := Compile(q); err == nil {
			t.Errorf("Compile(%q) ожидалась ошибка, получено nil", q)
		}
	}
}

// Значения никогда не должны попадать в SQL-строку напрямую — только через ?.
func TestCompileNoInjection(t *testing.T) {
	got, err := Compile(`host.cont:"'; DROP TABLE entries;--"`)
	if err != nil {
		t.Fatal(err)
	}
	if got.SQL != "host LIKE ?" {
		t.Errorf("SQL = %q, значение просочилось в запрос", got.SQL)
	}
	if got.Args[0] != "%'; DROP TABLE entries;--%" {
		t.Errorf("значение должно быть аргументом-плейсхолдером, got %v", got.Args[0])
	}
}
