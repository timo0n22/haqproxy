package store

// Finding — результат пассивного scanner-lite (§8 ТЗ).
type Finding struct {
	ID       int64  `json:"id"`
	EntryID  int64  `json:"entry_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"` // info | low | medium | high
	Detail   string `json:"detail"`
	// Денормализованные поля из entries для отображения списка.
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"`
}

// AddFinding сохраняет находку.
func (s *Store) AddFinding(entryID int64, rule, severity, detail string) error {
	_, err := s.db.Exec(
		"INSERT INTO findings (entry_id, rule_name, severity, detail) VALUES (?,?,?,?)",
		entryID, rule, severity, detail)
	return err
}

// CountFindings возвращает общее число находок.
func (s *Store) CountFindings() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&n)
	return n, err
}

// ListFindings возвращает находки (новейшие сверху) с данными связанной записи.
func (s *Store) ListFindings(limit int) ([]*Finding, error) {
	if limit <= 0 {
		limit = 300
	}
	rows, err := s.db.Query(`
		SELECT f.id, f.entry_id, f.rule_name, f.severity, f.detail,
		       e.host, e.path, e.method
		FROM findings f
		LEFT JOIN entries e ON e.id = f.entry_id
		ORDER BY f.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		var f Finding
		var host, path, method *string
		if err := rows.Scan(&f.ID, &f.EntryID, &f.RuleName, &f.Severity, &f.Detail,
			&host, &path, &method); err != nil {
			return nil, err
		}
		f.Host = deref(host)
		f.Path = deref(path)
		f.Method = deref(method)
		out = append(out, &f)
	}
	return out, rows.Err()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
