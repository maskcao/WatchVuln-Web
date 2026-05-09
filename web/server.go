package web

import (
	"embed"
	"html/template"
	"net/http"
	"sync"
	"time"

	"github.com/kataras/golog"
	"github.com/zema1/watchvuln/ctrl"
)

//go:embed templates/* static/*
var embeddedFiles embed.FS

type Server struct {
	app      *ctrl.WatchVulnApp
	config   *ctrl.WatchVulnAppConfig
	sessions *SessionStore
	logBuf   *LogBuffer
	server   *http.Server

	mu         sync.RWMutex
	baseTmpl   *template.Template
	pageTmpls  map[string]*template.Template
	collecting bool
}

func NewServer(app *ctrl.WatchVulnApp, config *ctrl.WatchVulnAppConfig) (*Server, error) {
	logBuf := NewLogBuffer(500)

	baseTmpl, err := template.ParseFS(embeddedFiles, "templates/layout.html")
	if err != nil {
		return nil, err
	}

	// Build per-page template sets so each page can define its own "content" block
	pageNames := []string{"login.html", "dashboard.html", "settings.html", "logs.html", "404.html"}
	pageTmpls := make(map[string]*template.Template)
	for _, name := range pageNames {
		tmpl, err := baseTmpl.Clone()
		if err != nil {
			return nil, err
		}
		tmpl, err = tmpl.ParseFS(embeddedFiles, "templates/"+name)
		if err != nil {
			return nil, err
		}
		pageTmpls[name] = tmpl
	}

	s := &Server{
		app:       app,
		config:    config,
		sessions:  NewSessionStore(),
		logBuf:    logBuf,
		baseTmpl:  baseTmpl,
		pageTmpls: pageTmpls,
	}

	mux := http.NewServeMux()

	// Static assets
	mux.Handle("/static/", http.FileServer(http.FS(embeddedFiles)))

	// Public routes
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			s.handleLogin(w, r)
		} else {
			s.handleLoginPage(w, r)
		}
	})
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/api/rss", s.handleAPIRSS)

	// Protected routes
	mux.HandleFunc("/", s.requireAuth(s.handleDashboardPage))
	mux.HandleFunc("/dashboard", s.requireAuth(s.handleDashboardPage))
	mux.HandleFunc("/settings", s.requireAuth(s.handleSettingsPage))
	mux.HandleFunc("/logs", s.requireAuth(s.handleLogsPage))

	// API routes
	mux.HandleFunc("/api/vulns", s.requireAuth(s.handleAPIVulns))
	mux.HandleFunc("/api/stats", s.requireAuth(s.handleAPIStats))
	mux.HandleFunc("/api/trigger-collect", s.requireAuth(s.handleAPITriggerCollect))
	mux.HandleFunc("/api/test-push", s.requireAuth(s.handleAPITestPush))
	mux.HandleFunc("/api/push", s.requireAuth(s.handleAPIPushVuln))
	mux.HandleFunc("/api/logs", s.requireAuth(s.handleAPILogs))
	mux.HandleFunc("/api/export", s.requireAuth(s.handleAPIExport))
	mux.HandleFunc("/api/sources", s.requireAuth(s.handleAPISources))
	mux.HandleFunc("/api/settings", s.requireAuth(s.handleAPISettings))
	mux.HandleFunc("/api/change-password", s.requireAuth(s.handleAPIChangePassword))
	mux.HandleFunc("/api/collect-status", s.requireAuth(s.handleAPICollectStatus))

	s.server = &http.Server{
		Addr:         config.Console.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s, nil
}

func (s *Server) ListenAndServe() error {
	golog.Infof("web console listening on %s", s.config.Console.Listen)
	return s.server.ListenAndServe()
}

func (s *Server) addLog(level, msg string) {
	s.logBuf.Write([]byte(msg))
}

func (s *Server) render(w http.ResponseWriter, name string, data interface{}) {
	if tmpl, ok := s.pageTmpls[name]; ok {
		if err := tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
			golog.Errorf("template error: %s", err)
		}
	} else {
		golog.Errorf("template not found: %s", name)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

type PageData struct {
	Title     string
	ActiveNav string
	Username  string
	Error     string
	Success   string
	Next      string
	Data      interface{}
}
