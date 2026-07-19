package web

import (
	"net/http"
	"strconv"
	"strings"
)

// currentTheme возвращает выбранную тему или дефолтную.
func (s *Server) currentTheme() string {
	if v, ok, _ := s.store.GetSetting(SettingUITheme); ok && v != "" {
		return v
	}
	return DefaultTheme
}

func (s *Server) currentAlpha() float64 {
	if v, ok, _ := s.store.GetSetting(SettingUIWindowAlpha); ok && v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0.4 && f <= 1.0 {
			return f
		}
	}
	return 1.0
}

func (s *Server) handleSettingsView(w http.ResponseWriter, r *http.Request) {
	get := func(k string) string { v, _, _ := s.store.GetSetting(k); return v }
	alpha := s.currentAlpha()
	data := map[string]any{
		"CollabDomain": get(SettingCollabDomain),
		"CollabAPI":    get(SettingCollabAPI),
		"CollabSecret": get(SettingCollabSecret),
		"Theme":        s.currentTheme(),
		"Alpha":        alpha,
		"AlphaPct":     int(alpha*100 + 0.5),
	}
	s.render(w, "settings_view", data)
}

func (s *Server) handleSettingsCollaborator(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	domain := strings.TrimSpace(r.FormValue("collab_domain"))
	api := strings.TrimSpace(r.FormValue("collab_api"))
	secret := strings.TrimSpace(r.FormValue("collab_secret"))

	for k, v := range map[string]string{
		SettingCollabDomain: domain,
		SettingCollabAPI:    api,
		SettingCollabSecret: secret,
	} {
		if err := s.store.SetSetting(k, v); err != nil {
			s.fail(w, err)
			return
		}
	}
	// Применяем сразу — без перезапуска.
	s.SetCollaborator(domain, api, secret)
	s.render(w, "collab_saved", nil)
}

func (s *Server) handleSettingsUI(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if theme := r.FormValue("theme"); theme != "" && validTheme(theme) {
		if err := s.store.SetSetting(SettingUITheme, theme); err != nil {
			s.fail(w, err)
			return
		}
	}
	if alpha := r.FormValue("alpha"); alpha != "" {
		if f, err := strconv.ParseFloat(alpha, 64); err == nil && f >= 0.4 && f <= 1.0 {
			if err := s.store.SetSetting(SettingUIWindowAlpha, strconv.FormatFloat(f, 'f', 2, 64)); err != nil {
				s.fail(w, err)
				return
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

var themeSet = map[string]bool{
	"tokyo-night": true, "tokyo-night-light": true,
	"gruvbox": true, "gruvbox-light": true,
	"rosepine": true, "rosepine-light": true,
	"catppuccin": true, "catppuccin-light": true,
}

func validTheme(t string) bool { return themeSet[t] }
