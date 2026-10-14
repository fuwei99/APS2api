package api

import (
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bsfdsagfadg/vertex/internal/config"
)

const (
	adminCookieName = "admin_token"
	adminSessionTTL = 24 * time.Hour
)

var (
	//nolint:gochecknoglobals // Admin sessions state
	adminSessionsMu sync.Mutex
	//nolint:gochecknoglobals // Admin sessions state
	adminSessions = map[string]time.Time{}
)

// ---- 登录失败锁定（按客户端 IP，不按账号）----
//
// 为什么不按账号：本程序只有一个管理员账号，"按账号锁定"等于一把全局锁，
// 任何人故意错 3 次就能把机主本人一起锁在门外（已实测踩到这个坑）。
// 按 IP 锁定只惩罚发起爆破的那个来源，其他 IP 正常登录不受影响。
//
// 同一个 IP 连续失败 adminMaxFailures 次即锁定该 IP；解锁后再失败会拉长锁定时长
// （递增、封顶 adminLockMax）。登录成功、或距上次失败超过 adminFailureResetAfter
// 都没有新失败，则该 IP 的计数清零。
const (
	adminMaxFailures       = 3
	adminLockBase          = 5 * time.Minute
	adminLockMax           = 60 * time.Minute
	adminFailureResetAfter = time.Hour
	adminLockSweepSize     = 512 // 条目超过这个数才做一次过期清理
)

type adminIPLock struct {
	failures    int
	lockLevel   int
	lockedUntil time.Time
	lastFailure time.Time
}

var (
	//nolint:gochecknoglobals // Admin login lock state
	adminLockMu sync.Mutex
	//nolint:gochecknoglobals // Admin login lock state
	adminLocks = map[string]*adminIPLock{}
)

// clientIP 取真实客户端 IP。
//
// 本服务跑在 cloudflared 隧道后面，隧道连接器从 127.0.0.1 发起请求，
// 所以 r.RemoteAddr 永远是 127.0.0.1——直接拿它当 IP 会让"按 IP 锁定"退化成全局锁。
// 真实客户端 IP 由 Cloudflare 注入在 CF-Connecting-IP 头里。
//
// 安全约束：只有当请求确实来自本机（隧道连接器）时才信任这些转发头，
// 否则公网直连者可以自己伪造 CF-Connecting-IP，靠换 IP 绕过锁定。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
			return v
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				xff = xff[:i]
			}
			if v := strings.TrimSpace(xff); v != "" {
				return v
			}
		}
	}
	return host
}

// adminLockRemainingFor 返回该 IP 剩余的锁定时长；未锁定返回 0。
func adminLockRemainingFor(ip string) time.Duration {
	adminLockMu.Lock()
	defer adminLockMu.Unlock()
	entry, ok := adminLocks[ip]
	if !ok {
		return 0
	}
	if entry.lockedUntil.After(time.Now()) {
		return time.Until(entry.lockedUntil)
	}
	return 0
}

// recordAdminLoginFailureFor 记一次该 IP 的登录失败。
// 返回 >0 表示本次失败触发了锁定，值为锁定时长。
func recordAdminLoginFailureFor(ip string) time.Duration {
	adminLockMu.Lock()
	defer adminLockMu.Unlock()

	now := time.Now()
	sweepAdminLocksLocked(now)

	entry, ok := adminLocks[ip]
	if !ok {
		entry = &adminIPLock{} //nolint:exhaustruct // 新条目从零开始
		adminLocks[ip] = entry
	}
	if !entry.lastFailure.IsZero() && now.Sub(entry.lastFailure) > adminFailureResetAfter {
		entry.failures = 0
		entry.lockLevel = 0
	}
	entry.failures++
	entry.lastFailure = now

	if entry.failures < adminMaxFailures {
		return 0
	}

	lockFor := adminLockBase
	for i := 0; i < entry.lockLevel; i++ {
		lockFor *= 3
		if lockFor >= adminLockMax {
			lockFor = adminLockMax
			break
		}
	}
	if entry.lockLevel < 10 {
		entry.lockLevel++
	}
	entry.lockedUntil = now.Add(lockFor)
	entry.failures = 0 // 计数归零：解锁后再错满 3 次才会再次锁定（且锁得更久）
	return lockFor
}

// recordAdminLoginSuccessFor 该 IP 登录成功，清空它的失败计数与锁定级别。
func recordAdminLoginSuccessFor(ip string) {
	adminLockMu.Lock()
	delete(adminLocks, ip)
	adminLockMu.Unlock()
}

// sweepAdminLocksLocked 清理长期无活动的条目，避免 map 无限增长。调用方需持锁。
func sweepAdminLocksLocked(now time.Time) {
	if len(adminLocks) <= adminLockSweepSize {
		return
	}
	for ip, entry := range adminLocks {
		if !entry.lockedUntil.After(now) && now.Sub(entry.lastFailure) > adminFailureResetAfter {
			delete(adminLocks, ip)
		}
	}
}

// writeAdminLocked 统一返回 429，并告知还需等待多久。
func writeAdminLocked(w http.ResponseWriter, left time.Duration) {
	secs := int(left.Seconds())
	if secs < 1 {
		secs = 1
	}
	mins := (secs + 59) / 60
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, adminErr(fmt.Sprintf(
		"该 IP 密码错误次数过多，登录已锁定，请约 %d 分钟后重试 (too many failed attempts from this IP, locked for ~%d min)",
		mins, mins,
	)))
}

func issueAdminToken() string {
	b := make([]byte, 32)
	_, _ = cryptorand.Read(b)
	tok := hex.EncodeToString(b)
	adminSessionsMu.Lock()
	adminSessions[tok] = time.Now().Add(adminSessionTTL)
	adminSessionsMu.Unlock()
	return tok
}

func checkAdminToken(tok string) bool {
	if tok == "" {
		return false
	}
	adminSessionsMu.Lock()
	defer adminSessionsMu.Unlock()
	exp, ok := adminSessions[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(adminSessions, tok)
		return false
	}
	return true
}

func dropAdminToken(tok string) {
	if tok == "" {
		return
	}
	adminSessionsMu.Lock()
	delete(adminSessions, tok)
	adminSessionsMu.Unlock()
}

func cleanupAdminSessions() int {
	now := time.Now()
	adminSessionsMu.Lock()
	defer adminSessionsMu.Unlock()
	n := 0
	for tok, exp := range adminSessions {
		if now.After(exp) {
			delete(adminSessions, tok)
			n++
		}
	}
	return n
}

func adminTokenFromRequest(r *http.Request) string {
	if c, err := r.Cookie(adminCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
}

func requireAdmin(r *http.Request) bool {
	return checkAdminToken(adminTokenFromRequest(r))
}

func StartAdminSessionCleanup(interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			if n := cleanupAdminSessions(); n > 0 {
				log.Printf("[Admin] 已清理 %d 个过期会话 token", n)
			}
		}
	}()
}

func EnsureAdminPassword() {
	if strings.TrimSpace(config.Load().AdminPassword) != "" {
		return
	}
	b := make([]byte, 9)
	if _, err := cryptorand.Read(b); err != nil {
		log.Printf("[Admin] 生成管理员密码失败：%v", err)
		return
	}
	pw := base64.RawURLEncoding.EncodeToString(b)
	if err := config.WriteSettings(map[string]any{"admin_password": pw}); err != nil {
		log.Printf("[Admin] 写入管理员密码到 config.json 失败：%v", err)
		return
	}
	bar := strings.Repeat("=", 60)
	fmt.Fprintf(os.Stderr, "\n%s\n", bar)
	fmt.Fprintln(os.Stderr, "[Admin] 首次启动，已自动生成管理员密码：")
	fmt.Fprintf(os.Stderr, "[Admin]     密码: %s\n", pw)
	fmt.Fprintln(os.Stderr, "[Admin]     访问: http://<host>:<port>/admin")
	fmt.Fprintln(os.Stderr, "[Admin]     密码已写入 config/config.json，登录后可在面板修改")
	fmt.Fprintf(os.Stderr, "%s\n\n", bar)
	log.Printf("%s", bar)
	log.Printf("[Admin] 首次启动，已自动生成管理员密码：")
	log.Printf("[Admin]     密码: %s", pw)
	log.Printf("[Admin]     访问: http://<host>:<port>/admin")
	log.Printf("[Admin]     密码已写入 config/config.json，登录后可在面板修改")
	log.Printf("%s", bar)
}

func (adm *AdminHandler) adminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		adm.adminMethodNotAllowed(w)
		return
	}
	ip := clientIP(r)
	// 该 IP 处于锁定期就直接拒绝，连密码都不比对——否则锁定形同虚设。
	if left := adminLockRemainingFor(ip); left > 0 {
		log.Printf("[Security] 后台登录处于锁定期，拒绝请求。剩余 %s。来源 IP: %s",
			left.Round(time.Second), ip)
		writeAdminLocked(w, left)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !adm.decodeAdminBody(w, r, &body) {
		return
	}
	expected := strings.TrimSpace(config.Load().AdminPassword)
	if expected == "" {
		writeJSON(w, http.StatusInternalServerError, adminErr("管理员密码未初始化 (admin password not set)"))
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.Password)), []byte(expected)) != 1 {
		lockFor := recordAdminLoginFailureFor(ip)
		log.Printf("[Security] 警告：后台登录失败，密码错误。来源 IP: %s", ip)
		if lockFor > 0 {
			log.Printf("[Security] 该 IP 连续失败达 %d 次，已锁定 %s。来源 IP: %s",
				adminMaxFailures, lockFor, ip)
			writeAdminLocked(w, lockFor)
			return
		}
		writeJSON(w, http.StatusUnauthorized, adminErr("密码错误 (invalid password)"))
		return
	}
	recordAdminLoginSuccessFor(ip)
	log.Printf("[Admin] 管理后台登录成功。来源 IP: %s", ip)
	cleanupAdminSessions()
	tok := issueAdminToken()
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge:   int(adminSessionTTL / time.Second),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (adm *AdminHandler) adminLogout(w http.ResponseWriter, r *http.Request) {
	dropAdminToken(adminTokenFromRequest(r))
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (adm *AdminHandler) adminCheckAuth(w http.ResponseWriter, r *http.Request) {
	authenticated := requireAdmin(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":     authenticated,
		"background_image":  adm.cfg.BackgroundImage(),
		"font_size":         adm.cfg.FontSize(),
		"font_color_type":   adm.cfg.FontColorType(),
		"font_color":        adm.cfg.FontColor(),
		"custom_bg_presets": adm.cfg.CustomBgPresets(),
	})
}

func (adm *AdminHandler) adminChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !adm.decodeAdminBody(w, r, &body) {
		return
	}
	expected := strings.TrimSpace(config.Load().AdminPassword)
	if expected == "" {
		writeJSON(w, http.StatusInternalServerError, adminErr("未设置管理员密码"))
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(body.OldPassword)), []byte(expected)) != 1 {
		writeJSON(w, http.StatusBadRequest, adminErr("原密码错误"))
		return
	}
	newPw := strings.TrimSpace(body.NewPassword)
	if len(newPw) < 6 {
		writeJSON(w, http.StatusBadRequest, adminErr("新密码不能少于 6 个字符"))
		return
	}
	if err := config.WriteSettings(map[string]any{"admin_password": newPw}); err != nil {
		writeJSON(w, http.StatusInternalServerError, adminErr("写入新密码失败"))
		return
	}
	adminSessionsMu.Lock()
	adminSessions = map[string]time.Time{}
	adminSessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		MaxAge:   -1,
	})
	log.Printf("[Security] 后台管理员密码已修改，所有在线会话已重置。来源 IP: %s", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
