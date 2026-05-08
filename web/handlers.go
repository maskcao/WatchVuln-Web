package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/zema1/watchvuln/ent"
	"github.com/zema1/watchvuln/ent/vulninformation"
)

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	data := &PageData{
		Title: "登录 - WatchVuln 控制台",
		Next:  r.URL.Query().Get("next"),
	}
	s.render(w, "login.html", data)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	next := r.FormValue("next")

	if username == s.config.Console.Username && password == s.config.Console.Password {
		session := s.sessions.Create(username)
		http.SetCookie(w, &http.Cookie{
			Name:     "watchvuln_session",
			Value:    session.ID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  session.ExpiresAt,
		})
		s.addLog("info", "用户 "+username+" 登录成功")
		if next != "" && !strings.HasPrefix(next, "/login") {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	data := &PageData{
		Title: "登录 - WatchVuln 控制台",
		Error: "用户名或密码错误",
		Next:  next,
	}
	s.render(w, "login.html", data)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("watchvuln_session")
	if err == nil {
		s.sessions.Delete(cookie.Value)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleDashboardPage(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	ctx := r.Context()

	// Single query for all stats using aggregation
	totalCount, _ := s.app.DB().VulnInformation.Query().Count(ctx)
	pushedCount, _ := s.app.DB().VulnInformation.Query().Where(vulninformation.Pushed(true)).Count(ctx)
	unpushedCount := totalCount - pushedCount

	todayStart := time.Now().Truncate(24 * time.Hour)
	todayCount, _ := s.app.DB().VulnInformation.Query().
		Where(vulninformation.CreateTimeGTE(todayStart)).
		Count(ctx)

	// Get sources
	sources := make([]string, 0)
	for _, g := range s.app.Grabbers() {
		sources = append(sources, g.ProviderInfo().Name)
	}

	// Get recent vulns for initial page load
	vulns, _ := s.app.DB().VulnInformation.Query().
		Order(ent.Desc(vulninformation.FieldCreateTime)).
		Limit(20).
		All(ctx)

	data := &PageData{
		Title:     "漏洞监控控制台 - WatchVuln",
		ActiveNav: "dashboard",
		Username:  sess.Username,
		Data: map[string]interface{}{
			"Vulns":         vulns,
			"TotalCount":    totalCount,
			"PushedCount":   pushedCount,
			"UnpushedCount": unpushedCount,
			"TodayCount":    todayCount,
			"Sources":       sources,
			"Interval":      s.config.IntervalParsed.String(),
			"Time":          time.Now().Format("2006-01-02 15:04:05"),
		},
	}
	s.render(w, "dashboard.html", data)
}

func (s *Server) handleSettingsPage(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	allSources := []struct {
		Name        string
		DisplayName string
		Enabled     bool
	}{
		{"avd", "阿里云漏洞库 (AVD)", contains(s.config.Sources, "avd")},
		{"chaitin", "长亭漏洞库", contains(s.config.Sources, "chaitin")},
		{"nox", "奇安信威胁情报中心", contains(s.config.Sources, "nox") || contains(s.config.Sources, "ti")},
		{"oscs", "OSCS 开源安全情报", contains(s.config.Sources, "oscs")},
		{"threatbook", "微步在线", contains(s.config.Sources, "threatbook")},
		{"seebug", "Seebug (知道创宇)", contains(s.config.Sources, "seebug")},
		{"struts2", "Apache Struts2 公告", contains(s.config.Sources, "struts2")},
		{"kev", "CISA KEV", contains(s.config.Sources, "kev")},
		{"venustech", "启明星辰", contains(s.config.Sources, "venustech")},
	}

	providerStatus := make([]map[string]interface{}, 0)
	for _, g := range s.app.Grabbers() {
		info := g.ProviderInfo()
		providerStatus = append(providerStatus, map[string]interface{}{
			"Name":        info.Name,
			"DisplayName": info.DisplayName,
			"Link":        info.Link,
		})
	}

	pushConfigs := make(map[string]map[string]string)
	for _, pc := range s.config.Pusher {
		pushType := pc["type"]
		pushConfigs[pushType] = pc
	}

	tab := r.URL.Query().Get("tab")
	if tab == "" {
		tab = "sources"
	}

	data := &PageData{
		Title:     "设置 - WatchVuln 控制台",
		ActiveNav: "settings",
		Username:  sess.Username,
		Data: map[string]interface{}{
			"Tab":              tab,
			"AllSources":      allSources,
			"Interval":         s.config.IntervalParsed.String(),
			"EnableCVEFilter":  *s.config.EnableCVEFilter,
			"NoFilter":         s.config.NoFilter,
			"NoGithubSearch":   *s.config.NoGithubSearch,
			"NoSleep":          *s.config.NoSleep,
			"SleepRanges":      s.config.SleepRanges,
			"DiffMode":         *s.config.DiffMode,
			"ProviderStatus":   providerStatus,
			"PushConfigs":      pushConfigs,
			"PusherConfig":     s.config.Pusher,
			"DBConn":           s.config.DBConn,
			"Proxy":            s.config.Proxy,
			"SkipTLSVerify":    s.config.SkipTLSVerify,
			"Success":          r.URL.Query().Get("success"),
			"WhiteKeywords":    s.config.WhiteKeywords,
			"BlackKeywords":    s.config.BlackKeywords,
		},
	}
	s.render(w, "settings.html", data)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *Server) handleLogsPage(w http.ResponseWriter, r *http.Request) {
	sess := getSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	data := &PageData{
		Title:     "系统日志 - WatchVuln 控制台",
		ActiveNav: "logs",
		Username:  sess.Username,
	}
	s.render(w, "logs.html", data)
}
