package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// HeaderOverride — одна подменяемая пара заголовка для identity.
type HeaderOverride struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Identity — именованный набор заголовков для подмены ("Admin", "User B",
// "Unauthenticated"), §7 ТЗ.
type Identity struct {
	ID      int64            `json:"id"`
	Name    string           `json:"name"`
	Headers []HeaderOverride `json:"headers"`
}

// ListIdentities возвращает все identity по порядку добавления.
func (s *Store) ListIdentities() ([]*Identity, error) {
	rows, err := s.db.Query("SELECT id, name, header_overrides FROM identities ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Identity
	for rows.Next() {
		var id Identity
		var raw string
		if err := rows.Scan(&id.ID, &id.Name, &raw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &id.Headers)
		out = append(out, &id)
	}
	return out, rows.Err()
}

// GetIdentity возвращает одну identity по id (nil, если нет).
func (s *Store) GetIdentity(id int64) (*Identity, error) {
	var idn Identity
	var raw string
	err := s.db.QueryRow("SELECT id, name, header_overrides FROM identities WHERE id = ?", id).
		Scan(&idn.ID, &idn.Name, &raw)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(raw), &idn.Headers)
	return &idn, nil
}

// AddIdentity создаёт identity, возвращает id.
func (s *Store) AddIdentity(name string, headers []HeaderOverride) (int64, error) {
	blob, _ := json.Marshal(headers)
	res, err := s.db.Exec("INSERT INTO identities (name, header_overrides) VALUES (?, ?)", name, string(blob))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteIdentity удаляет identity по id.
func (s *Store) DeleteIdentity(id int64) error {
	_, err := s.db.Exec("DELETE FROM identities WHERE id = ?", id)
	return err
}

// CreateMatrixRun сохраняет запуск матрицы, возвращает run_id.
func (s *Store) CreateMatrixRun(baseEntryID *int64) (int64, error) {
	res, err := s.db.Exec("INSERT INTO matrix_runs (base_entry_id, created_at) VALUES (?, ?)",
		baseEntryID, float64(time.Now().UnixNano())/1e9)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SaveMatrixResult сохраняет одну строку результата матрицы.
func (s *Store) SaveMatrixResult(runID, identityID int64, status *int, bodyLen int, bodyHash string, durationMs int) error {
	_, err := s.db.Exec(
		"INSERT INTO matrix_results (run_id, identity_id, status, body_len, body_hash, duration_ms) VALUES (?,?,?,?,?,?)",
		runID, identityID, status, bodyLen, bodyHash, durationMs)
	return err
}
