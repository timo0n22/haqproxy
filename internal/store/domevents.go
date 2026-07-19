package store

import "time"

// DomEvent — зафиксированный вызов опасного DOM-синка (§9 ТЗ).
type DomEvent struct {
	ID        int64   `json:"id"`
	Timestamp float64 `json:"timestamp"`
	Host      string  `json:"host"`
	Sink      string  `json:"sink"`
	Value     string  `json:"value"`
	Stack     string  `json:"stack"`
}

// AddDomEvent сохраняет DOM-событие.
func (s *Store) AddDomEvent(host, sink, value, stack string) error {
	_, err := s.db.Exec(
		"INSERT INTO dom_events (timestamp, host, sink, value, stack) VALUES (?,?,?,?,?)",
		float64(time.Now().UnixNano())/1e9, host, sink, value, stack)
	return err
}

// CountDomEvents возвращает число DOM-событий.
func (s *Store) CountDomEvents() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM dom_events").Scan(&n)
	return n, err
}

// ListDomEvents возвращает DOM-события (новейшие сверху).
func (s *Store) ListDomEvents(limit int) ([]*DomEvent, error) {
	if limit <= 0 {
		limit = 300
	}
	rows, err := s.db.Query(
		"SELECT id, timestamp, host, sink, value, stack FROM dom_events ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DomEvent
	for rows.Next() {
		var e DomEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Host, &e.Sink, &e.Value, &e.Stack); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
