// Package collaborator — серверная часть OOB-слушателя для VPS (§10.2 ТЗ):
// авторитативный DNS-листенер, HTTP-логгер и API с Bearer-авторизацией. Своя,
// никак не связанная с основной, SQLite.
package collaborator

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                 -- 'dns' | 'http'
    token TEXT,                         -- best-effort метка (label слева от базовой зоны)
    source_ip TEXT,
    timestamp REAL NOT NULL,
    raw_query_or_request TEXT           -- полное имя запроса (DNS) или сырой запрос (HTTP)
);
CREATE INDEX IF NOT EXISTS idx_interactions_ts ON interactions(timestamp);
`

// Store — хранилище interactions на VPS.
type Store struct {
	db *sql.DB
}

// Interaction — одна зафиксированная OOB-активность.
type Interaction struct {
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	Token     string  `json:"token"`
	SourceIP  string  `json:"source_ip"`
	Timestamp float64 `json:"timestamp"`
	Raw       string  `json:"raw"`
}

// OpenStore открывает (или создаёт) БД interactions.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// Close закрывает БД.
func (s *Store) Close() error { return s.db.Close() }

// Add сохраняет interaction.
func (s *Store) Add(kind, token, sourceIP, raw string) error {
	_, err := s.db.Exec(
		"INSERT INTO interactions (kind, token, source_ip, timestamp, raw_query_or_request) VALUES (?,?,?,?,?)",
		kind, token, sourceIP, float64(time.Now().UnixNano())/1e9, raw)
	return err
}

// Since возвращает interactions с timestamp строго больше since (новейшие внизу
// по id), ограничивая limit.
func (s *Store) Since(since float64, limit int) ([]*Interaction, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.db.Query(
		`SELECT id, kind, token, source_ip, timestamp, raw_query_or_request
		 FROM interactions WHERE timestamp > ? ORDER BY id ASC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Interaction
	for rows.Next() {
		var it Interaction
		var token, ip, raw *string
		if err := rows.Scan(&it.ID, &it.Kind, &token, &ip, &it.Timestamp, &raw); err != nil {
			return nil, err
		}
		it.Token = strDeref(token)
		it.SourceIP = strDeref(ip)
		it.Raw = strDeref(raw)
		out = append(out, &it)
	}
	return out, rows.Err()
}

func strDeref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
