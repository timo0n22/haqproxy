// Package collaboratorclient — клиентская часть Collaborator в составе
// cmd/haqproxy (§10.1 ТЗ): генерация OOB-токенов и опрос VPS.
package collaboratorclient

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Interaction — запись OOB-активности, как её отдаёт API VPS.
type Interaction struct {
	ID        int64   `json:"id"`
	Kind      string  `json:"kind"`
	Token     string  `json:"token"`
	SourceIP  string  `json:"source_ip"`
	Timestamp float64 `json:"timestamp"`
	Raw       string  `json:"raw"`
}

// GenerateToken возвращает случайный токен из 12 hex-символов.
func GenerateToken() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand practically не падает; на всякий случай — временная метка
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// Client опрашивает API VPS.
type Client struct {
	APIBase string // например "http://vps-ip:8081"
	Secret  string
	http    *http.Client
}

// New создаёт клиента.
func New(apiBase, secret string) *Client {
	return &Client{APIBase: apiBase, Secret: secret, http: &http.Client{Timeout: 10 * time.Second}}
}

// Configured сообщает, задан ли адрес API и секрет.
func (c *Client) Configured() bool {
	return c.APIBase != "" && c.Secret != ""
}

// FetchInteractions запрашивает interactions с timestamp > since.
func (c *Client) FetchInteractions(since float64) ([]*Interaction, error) {
	if !c.Configured() {
		return nil, fmt.Errorf("collaborator API не настроен")
	}
	url := fmt.Sprintf("%s/api/interactions?since=%s", c.APIBase, strconv.FormatFloat(since, 'f', -1, 64))
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Secret)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPS вернул %d", resp.StatusCode)
	}
	var out []*Interaction
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
