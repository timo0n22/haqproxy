package web

import (
	"sync"
)

// ReplayTab — состояние одной вкладки Replay. Держим на сервере, в памяти
// процесса (haqproxy — однопользовательский локальный инструмент), как допускает
// §11 ТЗ.
type ReplayTab struct {
	ID             int
	Name           string
	Host           string
	Port           int
	TLS            bool
	RawRequest     string
	LastResponse   string
	LastStatus     *int
	LastDurationMs int
	LastError      string
}

// tabManager — потокобезопасный набор вкладок Replay с указателем на активную.
type tabManager struct {
	mu       sync.Mutex
	tabs     []*ReplayTab
	activeID int
	nextID   int
}

func newTabManager() *tabManager {
	return &tabManager{nextID: 1}
}

func (m *tabManager) snapshot() ([]*ReplayTab, *ReplayTab, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tabsCopy := make([]*ReplayTab, len(m.tabs))
	copy(tabsCopy, m.tabs)
	return tabsCopy, m.findLocked(m.activeID), m.activeID
}

func (m *tabManager) newTab(name string) *ReplayTab {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addLocked(name, "", 443, true, "GET / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n")
}

func (m *tabManager) addLocked(name, host string, port int, tls bool, raw string) *ReplayTab {
	t := &ReplayTab{ID: m.nextID, Name: name, Host: host, Port: port, TLS: tls, RawRequest: raw}
	m.nextID++
	m.tabs = append(m.tabs, t)
	m.activeID = t.ID
	return t
}

func (m *tabManager) newTabFrom(name, host string, port int, tls bool, raw string) *ReplayTab {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addLocked(name, host, port, tls, raw)
}

func (m *tabManager) get(id int) *ReplayTab {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.findLocked(id)
}

func (m *tabManager) setActive(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.findLocked(id) != nil {
		m.activeID = id
	}
}

func (m *tabManager) close(id int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, t := range m.tabs {
		if t.ID == id {
			m.tabs = append(m.tabs[:i], m.tabs[i+1:]...)
			break
		}
	}
	if m.activeID == id {
		m.activeID = 0
		if len(m.tabs) > 0 {
			m.activeID = m.tabs[len(m.tabs)-1].ID
		}
	}
}

func (m *tabManager) findLocked(id int) *ReplayTab {
	for _, t := range m.tabs {
		if t.ID == id {
			return t
		}
	}
	return nil
}
