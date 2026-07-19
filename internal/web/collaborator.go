package web

import (
	"net/http"
	"strings"

	"github.com/timo0n22/haqproxy/internal/collaboratorclient"
)

// tokenView — токен + готовый payload для отображения.
type tokenView struct {
	Token   string
	Note    string
	Payload string
}

func (s *Server) collabData() map[string]any {
	tokens, _ := s.store.ListOOBTokens()
	var views []tokenView
	for _, t := range tokens {
		views = append(views, tokenView{
			Token:   t.Token,
			Note:    t.Note,
			Payload: s.payloadFor(t.Token),
		})
	}
	domain := s.collabDomain
	if domain == "" {
		domain = "<не настроен: флаг -collab-domain>"
	}
	configured := s.collab != nil && s.collab.Configured()
	return map[string]any{
		"Tokens":     views,
		"Domain":     domain,
		"Configured": configured,
	}
}

func (s *Server) payloadFor(token string) string {
	if s.collabDomain == "" {
		return token + ".oob.<ваш-домен>"
	}
	return token + "." + strings.Trim(s.collabDomain, ".")
}

func (s *Server) handleCollabView(w http.ResponseWriter, r *http.Request) {
	s.render(w, "collaborator_view", s.collabData())
}

func (s *Server) handleOOBGenerate(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	note := strings.TrimSpace(r.FormValue("note"))
	token := collaboratorclient.GenerateToken()
	if err := s.store.AddOOBToken(token, note); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, "oob_tokens", s.collabData())
}

func (s *Server) handleCollabInteractions(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{}
	if s.collab == nil || !s.collab.Configured() {
		data["NotConfigured"] = true
		s.render(w, "collab_interactions", data)
		return
	}
	items, err := s.collab.FetchInteractions(0)
	if err != nil {
		data["Error"] = err.Error()
		s.render(w, "collab_interactions", data)
		return
	}
	// Корреляция с нашими токенами: сопоставляем известные токены с полем token
	// или сырым содержимым interaction, чтобы показать заметку.
	tokens, _ := s.store.ListOOBTokens()
	noteByToken := map[string]string{}
	for _, t := range tokens {
		noteByToken[t.Token] = t.Note
	}
	type row struct {
		*collaboratorclient.Interaction
		Note  string
		Known bool
	}
	var rows []row
	for _, it := range items {
		note, known := noteByToken[it.Token]
		if !known {
			// иногда токен — не ровно label; ищем известный токен как подстроку
			for tk, nt := range noteByToken {
				if tk != "" && (strings.Contains(it.Token, tk) || strings.Contains(it.Raw, tk)) {
					note, known = nt, true
					break
				}
			}
		}
		rows = append(rows, row{Interaction: it, Note: note, Known: known})
	}
	data["Rows"] = rows
	s.render(w, "collab_interactions", data)
}
