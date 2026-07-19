// Package store — слой хранения haqproxy поверх SQLite (modernc.org/sqlite, без CGO).
//
// Один SQLite-файл на весь инструмент. Под таблицей `entries` живёт и трафик
// из проксирования (source='proxy'), и запросы из Replay (source='replay').
//
// Сырые запрос/ответ храним ЦЕЛИКОМ как байты. В Go, в отличие от Python, нет
// нужды в latin-1-трюке: raw_request/raw_response — это BLOB, храним []byte как
// есть, побайтово lossless (включая бинарные тела и точный порядок/регистр
// заголовков). Индексируемые колонки (host, method, status и т.д.) — извлечённые
// для быстрой фильтрации метаданные; источник правды — raw_request/raw_response.
package store

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // driver name в database/sql — "sqlite", не "sqlite3"
)

const schema = `
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,               -- 'proxy' | 'replay'
    parent_id INTEGER,                  -- если replay создан "из" записи истории
    timestamp REAL NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    scheme TEXT NOT NULL,               -- 'http' | 'https'
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    resp_status INTEGER,
    duration_ms INTEGER,
    raw_request BLOB NOT NULL,          -- сырые байты запроса
    raw_response BLOB,                  -- сырые байты ответа, NULL если не было ответа/ошибка
    error TEXT,                         -- текст ошибки, если запрос не удался
    note TEXT,                          -- свободная заметка пользователя
    tag TEXT                            -- короткий тег/лейбл, например "IDOR?"
);

CREATE INDEX IF NOT EXISTS idx_entries_host ON entries(host);
CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source);
CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);

CREATE TABLE IF NOT EXISTS scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL UNIQUE,       -- например "*.example.com" или "example.com"
    enabled INTEGER NOT NULL DEFAULT 1
);

-- Заготовки под следующие этапы (§3 ТЗ); создаём заранее, стоит дёшево.
CREATE TABLE IF NOT EXISTS identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    header_overrides TEXT NOT NULL      -- JSON-список пар заголовков для подстановки
);

CREATE TABLE IF NOT EXISTS matrix_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    base_entry_id INTEGER,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS matrix_results (
    run_id INTEGER NOT NULL,
    identity_id INTEGER NOT NULL,
    status INTEGER,
    body_len INTEGER,
    body_hash TEXT,
    duration_ms INTEGER
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS oob_tokens (
    token TEXT PRIMARY KEY,
    note TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS dom_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    host TEXT NOT NULL,
    sink TEXT NOT NULL,      -- имя опасного DOM-синка (innerHTML, eval, ...)
    value TEXT,              -- усечённое значение
    stack TEXT               -- stack trace на момент вызова
);
`

// Store — обёртка над *sql.DB. Потокобезопасен (database/sql имеет пул соединений);
// WAL-режим позволяет писателю-прокси и читателю-веб не блокировать друг друга.
type Store struct {
	db *sql.DB
}

// Open открывает (или создаёт) БД по пути path и применяет схему.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// modernc.org/sqlite: единственное соединение для записи упрощает WAL и
	// исключает "database is locked" при конкурентных вставках из прокси.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA busy_timeout=30000"); err != nil {
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

// Entry — одна запись истории (proxy или replay).
type Entry struct {
	ID          int64   `json:"id"`
	Source      string  `json:"source"`
	ParentID    *int64  `json:"parent_id"`
	Timestamp   float64 `json:"timestamp"`
	Host        string  `json:"host"`
	Port        int     `json:"port"`
	Scheme      string  `json:"scheme"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	RespStatus  *int    `json:"resp_status"`
	DurationMs  *int    `json:"duration_ms"`
	RawRequest  []byte  `json:"-"`
	RawResponse []byte  `json:"-"`
	Error       *string `json:"error"`
	Note        *string `json:"note"`
	Tag         *string `json:"tag"`
}

// InsertEntry вставляет запись и возвращает её id.
func (s *Store) InsertEntry(e *Entry) (int64, error) {
	if e.Timestamp == 0 {
		e.Timestamp = float64(time.Now().UnixNano()) / 1e9
	}
	res, err := s.db.Exec(
		`INSERT INTO entries
		   (source, parent_id, timestamp, host, port, scheme, method, path,
		    resp_status, duration_ms, raw_request, raw_response, error, note, tag)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.Source, e.ParentID, e.Timestamp, e.Host, e.Port, e.Scheme, e.Method, e.Path,
		e.RespStatus, e.DurationMs, e.RawRequest, e.RawResponse, e.Error, e.Note, e.Tag,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// QueryFilter — набор фильтров для списка истории. Пустые поля игнорируются.
// WhereSQL/WhereArgs — опциональный дополнительный фрагмент WHERE (из HTTPQL),
// уже параметризованный; подставляется через AND.
type QueryFilter struct {
	Source    string
	ScopeOnly bool
	WhereSQL  string
	WhereArgs []any
	Limit     int
}

// ListEntries возвращает записи (без сырых тел — для таблицы истории),
// новейшие сверху.
func (s *Store) ListEntries(f QueryFilter) ([]*Entry, error) {
	var clauses []string
	var args []any

	if f.Source != "" {
		clauses = append(clauses, "source = ?")
		args = append(args, f.Source)
	}
	if f.WhereSQL != "" {
		clauses = append(clauses, "("+f.WhereSQL+")")
		args = append(args, f.WhereArgs...)
	}
	if f.ScopeOnly {
		patterns, err := s.enabledScopePatterns()
		if err != nil {
			return nil, err
		}
		if len(patterns) == 0 {
			// scope пуст, а фильтр запрошен — ничего не показываем, чтобы не
			// создавать ложное ощущение "всё в scope".
			clauses = append(clauses, "1=0")
		} else {
			var sc []string
			for _, p := range patterns {
				sc = append(sc, "host LIKE ?")
				args = append(args, likeFromPattern(p))
			}
			clauses = append(clauses, "("+join(sc, " OR ")+")")
		}
	}

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + join(clauses, " AND ")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q := fmt.Sprintf(`SELECT id, source, parent_id, timestamp, host, port, scheme, method,
	         path, resp_status, duration_ms, error, note, tag
	  FROM entries %s ORDER BY id DESC LIMIT ?`, where)
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Source, &e.ParentID, &e.Timestamp, &e.Host,
			&e.Port, &e.Scheme, &e.Method, &e.Path, &e.RespStatus, &e.DurationMs,
			&e.Error, &e.Note, &e.Tag); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// GetEntry возвращает полную запись, включая сырые тела.
func (s *Store) GetEntry(id int64) (*Entry, error) {
	var e Entry
	err := s.db.QueryRow(
		`SELECT id, source, parent_id, timestamp, host, port, scheme, method, path,
		        resp_status, duration_ms, raw_request, raw_response, error, note, tag
		 FROM entries WHERE id = ?`, id,
	).Scan(&e.ID, &e.Source, &e.ParentID, &e.Timestamp, &e.Host, &e.Port, &e.Scheme,
		&e.Method, &e.Path, &e.RespStatus, &e.DurationMs, &e.RawRequest, &e.RawResponse,
		&e.Error, &e.Note, &e.Tag)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// UpdateEntryMeta обновляет заметку/тег (COALESCE — nil-поля не трогаются).
func (s *Store) UpdateEntryMeta(id int64, note, tag *string) error {
	_, err := s.db.Exec(
		"UPDATE entries SET note = COALESCE(?, note), tag = COALESCE(?, tag) WHERE id = ?",
		note, tag, id)
	return err
}

// ---------- Scope ----------

// ScopeRow — строка списка scope.
type ScopeRow struct {
	ID      int64  `json:"id"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
}

// ListScope возвращает все scope-паттерны по порядку добавления.
func (s *Store) ListScope() ([]*ScopeRow, error) {
	rows, err := s.db.Query("SELECT id, pattern, enabled FROM scope ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ScopeRow
	for rows.Next() {
		var r ScopeRow
		var en int
		if err := rows.Scan(&r.ID, &r.Pattern, &en); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, &r)
	}
	return out, rows.Err()
}

// AddScope добавляет паттерн (idempotent — дубли игнорируются).
func (s *Store) AddScope(pattern string) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO scope (pattern, enabled) VALUES (?, 1)", pattern)
	return err
}

// RemoveScope удаляет паттерн по id.
func (s *Store) RemoveScope(id int64) error {
	_, err := s.db.Exec("DELETE FROM scope WHERE id = ?", id)
	return err
}

// SetScopeEnabled включает/выключает паттерн.
func (s *Store) SetScopeEnabled(id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec("UPDATE scope SET enabled = ? WHERE id = ?", v, id)
	return err
}

// InScope сообщает, попадает ли host под хотя бы один включённый scope-паттерн.
// Если scope пуст — возвращает true (весь трафик считается интересным).
func (s *Store) InScope(host string) (bool, error) {
	patterns, err := s.enabledScopePatterns()
	if err != nil {
		return false, err
	}
	if len(patterns) == 0 {
		return true, nil
	}
	for _, p := range patterns {
		if matchHostPattern(p, host) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) enabledScopePatterns() ([]string, error) {
	rows, err := s.db.Query("SELECT pattern FROM scope WHERE enabled = 1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
