package store

// Настройки приложения — key/value, редактируются во вкладке Settings и
// переживают перезапуск (в отличие от флагов). Ключи см. в package web
// (collab_domain, collab_api, collab_secret, ui_theme, ui_window_alpha).

// GetSetting возвращает значение настройки или "" (второй результат — найдена ли).
func (s *Store) GetSetting(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// SetSetting сохраняет значение настройки (upsert).
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(
		"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	return err
}

// AllSettings возвращает все настройки как map.
func (s *Store) AllSettings() (map[string]string, error) {
	rows, err := s.db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
