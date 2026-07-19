package store

// Очистка накопленных данных (кнопки «Очистить» в окнах). Конфиг (scope,
// identities, settings) не трогаем — только накопленные записи.

// ClearHistory удаляет всю историю запросов и производные от неё passive-находки
// (findings ссылаются на entries и без них бессмысленны).
func (s *Store) ClearHistory() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM findings"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM entries"); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearFindings удаляет только находки scanner-lite.
func (s *Store) ClearFindings() error {
	_, err := s.db.Exec("DELETE FROM findings")
	return err
}

// ClearDomEvents удаляет DOM-события.
func (s *Store) ClearDomEvents() error {
	_, err := s.db.Exec("DELETE FROM dom_events")
	return err
}

// ClearMatrix удаляет прогоны AuthMatrix (identities сохраняются).
func (s *Store) ClearMatrix() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM matrix_results"); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM matrix_runs"); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearOOBTokens удаляет локально сгенерированные OOB-токены (interactions живут
// на VPS и отсюда не чистятся).
func (s *Store) ClearOOBTokens() error {
	_, err := s.db.Exec("DELETE FROM oob_tokens")
	return err
}
