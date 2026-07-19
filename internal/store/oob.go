package store

import "time"

// OOBToken — сгенерированный на клиенте payload для Collaborator (§3 ТЗ).
// VPS о токенах заранее не знает — просто логирует любой хит; корреляция
// происходит на клиенте по совпадению токена с именем interaction.
type OOBToken struct {
	Token     string  `json:"token"`
	Note      string  `json:"note"`
	CreatedAt float64 `json:"created_at"`
}

// AddOOBToken сохраняет сгенерированный токен с заметкой.
func (s *Store) AddOOBToken(token, note string) error {
	_, err := s.db.Exec("INSERT OR REPLACE INTO oob_tokens (token, note, created_at) VALUES (?,?,?)",
		token, note, float64(time.Now().UnixNano())/1e9)
	return err
}

// ListOOBTokens возвращает токены (новейшие сверху).
func (s *Store) ListOOBTokens() ([]*OOBToken, error) {
	rows, err := s.db.Query("SELECT token, note, created_at FROM oob_tokens ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*OOBToken
	for rows.Next() {
		var t OOBToken
		if err := rows.Scan(&t.Token, &t.Note, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}
