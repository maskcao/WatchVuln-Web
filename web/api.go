package web

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zema1/watchvuln/ctrl"
	"github.com/zema1/watchvuln/ent"
	"github.com/zema1/watchvuln/ent/predicate"
	"github.com/zema1/watchvuln/ent/vulninformation"
)

// ---------- JSON response helpers ----------

type APIResponse struct {
	Success  bool        `json:"success"`
	Data     interface{} `json:"data,omitempty"`
	Error    string      `json:"error,omitempty"`
	Total    int         `json:"total,omitempty"`
	Page     int         `json:"page,omitempty"`
	PageSize int         `json:"page_size,omitempty"`
}

func writeJSON(w http.ResponseWriter, resp APIResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(resp)
}

// ---------- /api/vulns ----------

func (s *Server) handleAPIVulns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize < 1 || pageSize > 500 {
		pageSize = 20
	}

	var preds []predicate.VulnInformation

	if sev := q.Get("severity"); sev != "" {
		preds = append(preds, vulninformation.Severity(sev))
	}
	if cve := q.Get("cve"); cve != "" {
		preds = append(preds, vulninformation.CveContainsFold(cve))
	}
	if src := q.Get("source"); src != "" {
		preds = append(preds, vulninformation.FromContainsFold(src))
	}
	if pushed := q.Get("pushed"); pushed == "true" {
		preds = append(preds, vulninformation.Pushed(true))
	} else if pushed == "false" {
		preds = append(preds, vulninformation.Pushed(false))
	}
	if search := q.Get("search"); search != "" {
		preds = append(preds, vulninformation.Or(
			vulninformation.TitleContainsFold(search),
			vulninformation.CveContainsFold(search),
		))
	}
	if df := q.Get("date_from"); df != "" {
		if t, err := time.Parse("2006-01-02", df); err == nil {
			preds = append(preds, vulninformation.CreateTimeGTE(t))
		}
	}
	if dt := q.Get("date_to"); dt != "" {
		if t, err := time.Parse("2006-01-02", dt); err == nil {
			preds = append(preds, vulninformation.CreateTimeLTE(t.Add(24*time.Hour)))
		}
	}

	query := s.app.DB().VulnInformation.Query()
	if len(preds) > 0 {
		query = query.Where(preds...)
	}

	// Handle sorting
	sortField := q.Get("sort")
	sortAsc := q.Get("order") != "desc"
	switch sortField {
	case "cve":
		if sortAsc {
			query = query.Order(ent.Asc(vulninformation.FieldCve))
		} else {
			query = query.Order(ent.Desc(vulninformation.FieldCve))
		}
	case "disclosure":
		if sortAsc {
			query = query.Order(ent.Asc(vulninformation.FieldDisclosure))
		} else {
			query = query.Order(ent.Desc(vulninformation.FieldDisclosure))
		}
	case "create_time":
		if sortAsc {
			query = query.Order(ent.Asc(vulninformation.FieldCreateTime))
		} else {
			query = query.Order(ent.Desc(vulninformation.FieldCreateTime))
		}
	default:
		query = query.Order(ent.Desc(vulninformation.FieldCreateTime))
	}

	total, err := query.Count(ctx)
	if err != nil {
		writeJSON(w, APIResponse{Success: false, Error: err.Error()})
		return
	}

	vulns, err := query.
		Order(ent.Desc(vulninformation.FieldCreateTime)).
		Limit(pageSize).
		Offset((page - 1) * pageSize).
		All(ctx)
	if err != nil {
		writeJSON(w, APIResponse{Success: false, Error: err.Error()})
		return
	}

	if vulns == nil {
		vulns = make([]*ent.VulnInformation, 0)
	}

	type vulnResult struct {
		ID           int       `json:"id"`
		Key          string    `json:"key"`
		Title        string    `json:"title"`
		Description  string    `json:"description"`
		Severity     string    `json:"severity"`
		CVE          string    `json:"cve"`
		Disclosure   string    `json:"disclosure"`
		Solutions    string    `json:"solutions"`
		References   []string  `json:"references"`
		Tags         []string  `json:"tags"`
		GithubSearch []string  `json:"github_search"`
		From         string    `json:"from"`
		Pushed       bool      `json:"pushed"`
		CreateTime   time.Time `json:"create_time"`
		UpdateTime   time.Time `json:"update_time"`
	}

	results := make([]vulnResult, 0, len(vulns))
	for _, v := range vulns {
		results = append(results, vulnResult{
			ID:           v.ID,
			Key:          v.Key,
			Title:        v.Title,
			Description:  v.Description,
			Severity:     v.Severity,
			CVE:          v.Cve,
			Disclosure:   v.Disclosure,
			Solutions:    v.Solutions,
			References:   v.References,
			Tags:         v.Tags,
			GithubSearch: v.GithubSearch,
			From:         v.From,
			Pushed:       v.Pushed,
			CreateTime:   v.CreateTime,
			UpdateTime:   v.UpdateTime,
		})
	}

	writeJSON(w, APIResponse{
		Success:  true,
		Data:     results,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// ---------- /api/stats ----------

func (s *Server) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db := s.app.DB()

	totalVulns, _ := db.VulnInformation.Query().Count(ctx)
	pushedCount, _ := db.VulnInformation.Query().Where(vulninformation.Pushed(true)).Count(ctx)
	unpushedCount, _ := db.VulnInformation.Query().Where(vulninformation.Pushed(false)).Count(ctx)

	severityDist := make(map[string]int)
	for _, sev := range []string{"低危", "中危", "高危", "严重"} {
		c, _ := db.VulnInformation.Query().Where(vulninformation.Severity(sev)).Count(ctx)
		severityDist[sev] = c
	}

	sourceDist := make(map[string]int)
	for _, g := range s.app.Grabbers() {
		c, _ := db.VulnInformation.Query().Where(vulninformation.FromContainsFold(g.ProviderInfo().Name)).Count(ctx)
		sourceDist[g.ProviderInfo().Name] = c
	}

	latest, err := db.VulnInformation.Query().Order(ent.Desc(vulninformation.FieldCreateTime)).First(ctx)
	latestTime := ""
	if err == nil && latest != nil {
		latestTime = latest.CreateTime.Format("2006-01-02 15:04:05")
	}

	writeJSON(w, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"total_vulns":          totalVulns,
			"pushed_count":         pushedCount,
			"unpushed_count":       unpushedCount,
			"severity_distribution": severityDist,
			"source_distribution":   sourceDist,
			"latest_vuln_time":     latestTime,
		},
	})
}

// ---------- /api/trigger-collect ----------

func (s *Server) handleAPITriggerCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, APIResponse{Success: false, Error: "method not allowed"})
		return
	}

	s.mu.Lock()
	if s.collecting {
		s.mu.Unlock()
		writeJSON(w, APIResponse{Success: false, Error: "采集任务正在进行中，请稍后再试"})
		return
	}
	s.collecting = true
	s.mu.Unlock()

	s.addLog("info", "手动触发漏洞采集...")
	go func() {
		defer func() {
			s.mu.Lock()
			s.collecting = false
			s.mu.Unlock()
		}()
		count, err := s.app.TriggerCollect(context.Background())
		if err != nil {
			s.addLog("error", "采集失败: "+err.Error())
		} else {
			s.addLog("info", fmt.Sprintf("采集完成，发现 %d 个新漏洞", count))
		}
	}()

	writeJSON(w, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "采集已启动，请稍后刷新查看结果"},
	})
}

// ---------- /api/collect-status ----------

func (s *Server) handleAPICollectStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	collecting := s.collecting
	s.mu.RUnlock()

	writeJSON(w, APIResponse{
		Success: true,
		Data:    map[string]interface{}{"collecting": collecting},
	})
}

// ---------- /api/test-push ----------

func (s *Server) handleAPITestPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, APIResponse{Success: false, Error: "method not allowed"})
		return
	}

	s.addLog("info", "发送测试推送消息...")
	err := s.app.TestPush()
	if err != nil {
		s.addLog("error", "测试推送失败: "+err.Error())
		writeJSON(w, APIResponse{Success: false, Error: err.Error()})
		return
	}

	s.addLog("info", "测试推送发送成功")
	writeJSON(w, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "测试推送已发送"},
	})
}

// ---------- /api/push/:id ----------

func (s *Server) handleAPIPushVuln(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, APIResponse{Success: false, Error: "method not allowed"})
		return
	}

	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		writeJSON(w, APIResponse{Success: false, Error: "missing vuln id"})
		return
	}
	id, err := strconv.Atoi(idStr)
	if err != nil {
		writeJSON(w, APIResponse{Success: false, Error: "invalid vuln id"})
		return
	}

	s.addLog("info", fmt.Sprintf("手动推送漏洞 ID: %d", id))
	if err := s.app.PushVulnByID(r.Context(), id); err != nil {
		s.addLog("error", fmt.Sprintf("推送漏洞失败: %v", err))
		writeJSON(w, APIResponse{Success: false, Error: err.Error()})
		return
	}

	s.addLog("info", fmt.Sprintf("漏洞 ID %d 推送成功", id))
	writeJSON(w, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "推送成功"},
	})
}

// ---------- /api/logs ----------

func (s *Server) handleAPILogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 500 {
		limit = 100
	}

	entries := s.logBuf.Entries()
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}

	// Reverse to show newest first
	result := make([]LogEntry, len(entries))
	for i, e := range entries {
		result[len(entries)-1-i] = e
	}

	writeJSON(w, APIResponse{Success: true, Data: result, Total: len(result)})
}

// ---------- /api/export ----------

func (s *Server) handleAPIExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	// Build query with same filters as vulns API
	q := s.app.DB().VulnInformation.Query()
	if sev := r.URL.Query().Get("severity"); sev != "" {
		q.Where(vulninformation.Severity(sev))
	}
	if cve := r.URL.Query().Get("cve"); cve != "" {
		q.Where(vulninformation.CveContainsFold(cve))
	}

	vulns, err := q.Order(ent.Desc(vulninformation.FieldCreateTime)).All(ctx)
	if err != nil {
		writeJSON(w, APIResponse{Success: false, Error: err.Error()})
		return
	}

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=watchvuln_export.csv")
		writer := csv.NewWriter(w)
		writer.Write([]string{"ID", "Title", "CVE", "Severity", "Disclosure", "Source", "Pushed", "Tags", "Description"})
		for _, v := range vulns {
			writer.Write([]string{
				strconv.Itoa(v.ID),
				v.Title,
				v.Cve,
				v.Severity,
				v.Disclosure,
				v.From,
				strconv.FormatBool(v.Pushed),
				strings.Join(v.Tags, "; "),
				v.Description,
			})
		}
		writer.Flush()
	default:
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=watchvuln_export.json")
		json.NewEncoder(w).Encode(vulns)
	}
}

// ---------- /api/sources ----------

func (s *Server) handleAPISources(w http.ResponseWriter, r *http.Request) {
	type sourceInfo struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Link        string `json:"link"`
	}

	sources := make([]sourceInfo, 0)
	for _, g := range s.app.Grabbers() {
		info := g.ProviderInfo()
		sources = append(sources, sourceInfo{
			Name:        info.Name,
			DisplayName: info.DisplayName,
			Link:        info.Link,
		})
	}

	writeJSON(w, APIResponse{Success: true, Data: sources})
}

// ---------- /api/settings ----------

func (s *Server) handleAPISettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, APIResponse{Success: false, Error: "method not allowed"})
		return
	}

	var settings struct {
		Sources         string            `json:"sources"`
		Interval        string            `json:"interval"`
		EnableCVEFilter bool              `json:"enable_cve_filter"`
		NoFilter        bool              `json:"no_filter"`
		NoGithubSearch  bool              `json:"no_github_search"`
		NoSleep         bool              `json:"no_sleep"`
		SleepRanges     []ctrl.SleepRange `json:"sleep_ranges"`
		WhiteKeywords   []string          `json:"white_keywords"`
		BlackKeywords   []string          `json:"black_keywords"`
		Pusher          []map[string]string `json:"pusher"`
	}

	if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
		writeJSON(w, APIResponse{Success: false, Error: "invalid JSON: " + err.Error()})
		return
	}

	if settings.Sources != "" {
		s.config.Sources = strings.Split(settings.Sources, ",")
		if err := s.app.UpdateSources(); err != nil {
			s.addLog("error", fmt.Sprintf("更新数据源失败: %v", err))
		} else {
			s.addLog("info", fmt.Sprintf("数据源已更新: %v", s.config.Sources))
		}
	}
	if settings.Interval != "" {
		if d, err := time.ParseDuration(settings.Interval); err == nil {
			s.config.Interval = settings.Interval
			s.config.IntervalParsed = d
		}
	}
	if settings.EnableCVEFilter {
		t := true
		s.config.EnableCVEFilter = &t
	}
	s.config.NoFilter = settings.NoFilter
	ng := settings.NoGithubSearch
	s.config.NoGithubSearch = &ng
	ns := settings.NoSleep
	s.config.NoSleep = &ns
	if settings.SleepRanges != nil {
		s.config.SleepRanges = settings.SleepRanges
		s.addLog("info", fmt.Sprintf("休眠时间段已更新: %v", settings.SleepRanges))
	}
	if settings.WhiteKeywords != nil {
		s.config.WhiteKeywords = settings.WhiteKeywords
		s.addLog("info", fmt.Sprintf("白名单关键词已更新: %v", settings.WhiteKeywords))
	}
	if settings.BlackKeywords != nil {
		s.config.BlackKeywords = settings.BlackKeywords
		s.addLog("info", fmt.Sprintf("黑名单关键词已更新: %v", settings.BlackKeywords))
	}
	if settings.Pusher != nil {
		s.config.Pusher = settings.Pusher
		if err := s.app.UpdatePusher(settings.Pusher); err != nil {
			s.addLog("error", fmt.Sprintf("更新推送配置失败: %v", err))
		} else {
			s.addLog("info", fmt.Sprintf("推送配置已更新，共 %d 个渠道", len(settings.Pusher)))
		}
	}

	// Save config to file for persistence across restarts
	if err := s.config.Save(); err != nil {
		s.addLog("error", fmt.Sprintf("保存配置失败: %v", err))
	} else {
		s.addLog("info", "配置已保存到文件")
	}

	s.addLog("info", "配置已更新")

	writeJSON(w, APIResponse{
		Success: true,
		Data: map[string]string{
			"message": "配置已更新并保存。",
		},
	})
}

// ---------- /api/change-password ----------

func (s *Server) handleAPIChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, APIResponse{Success: false, Error: "method not allowed"})
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, APIResponse{Success: false, Error: "invalid JSON: " + err.Error()})
		return
	}

	if req.OldPassword != s.config.Console.Password {
		writeJSON(w, APIResponse{Success: false, Error: "原密码错误"})
		return
	}

	if req.NewPassword == "" || len(req.NewPassword) < 6 {
		writeJSON(w, APIResponse{Success: false, Error: "新密码不能少于6个字符"})
		return
	}

	s.config.Console.Password = req.NewPassword
	s.addLog("info", "管理员密码已修改")

	writeJSON(w, APIResponse{
		Success: true,
		Data:    map[string]string{"message": "密码修改成功"},
	})
}

// ---------- /api/rss ----------

func (s *Server) handleAPIRSS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	vulns, err := s.app.DB().VulnInformation.Query().
		Order(ent.Desc(vulninformation.FieldCreateTime)).
		Limit(50).
		All(ctx)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	type rssItem struct {
		XMLName     xml.Name `xml:"item"`
		Title       string   `xml:"title"`
		Link        string   `xml:"link"`
		Description string   `xml:"description"`
		PubDate     string   `xml:"pubDate"`
		Guid        string   `xml:"guid"`
	}

	type rssChannel struct {
		XMLName     xml.Name  `xml:"channel"`
		Title       string    `xml:"title"`
		Link        string    `xml:"link"`
		Description string    `xml:"description"`
		Items       []rssItem `xml:"item"`
	}

	type rssFeed struct {
		XMLName xml.Name   `xml:"rss"`
		Version string     `xml:"version,attr"`
		Channel rssChannel `xml:"channel"`
	}

	items := make([]rssItem, 0, len(vulns))
	for _, v := range vulns {
		desc := fmt.Sprintf("[%s] %s", v.Severity, v.Title)
		if v.Cve != "" {
			desc = fmt.Sprintf("%s (%s)", desc, v.Cve)
		}
		if len(v.Description) > 500 {
			desc += "\n\n" + v.Description[:500] + "..."
		} else if v.Description != "" {
			desc += "\n\n" + v.Description
		}

		items = append(items, rssItem{
			Title:       fmt.Sprintf("[%s][%s] %s", v.Severity, filepath.Base(v.From), v.Title),
			Link:        v.From,
			Description: desc,
			PubDate:     v.CreateTime.Format(time.RFC1123Z),
			Guid:        v.Key,
		})
	}

	feed := rssFeed{
		Version: "2.0",
		Channel: rssChannel{
			Title:       "WatchVuln - 漏洞监控",
			Link:        "https://github.com/zema1/watchvuln",
			Description: "WatchVuln 高价值漏洞监控推送",
			Items:       items,
		},
	}

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	enc.Encode(feed)
}
