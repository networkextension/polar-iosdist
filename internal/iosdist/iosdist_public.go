package iosdist

// Public-facing iOS distribution share page.
//
// Three endpoints, all unauthenticated and keyed by the random
// public_slug on the app row:
//
//   GET  /iosdist/share/:slug                 → server-rendered landing page
//   POST /iosdist/share/:slug/install         → mints a fresh OTA token + manifest URL
//   POST /iosdist/share/:slug/test-request    → "申请测试" form: log to DB, optionally
//                                                forward to ASC ascCreateTester
//
// The slug acts as a capability — anyone with the URL can see the app
// and submit invite requests, but cannot enumerate other apps. Visibility
// is gated by is_public; turning that off makes the slug return 404
// without invalidating the slug itself, so the operator can re-enable
// without breaking flyers / printed QR codes.

import (
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ---- locale resolution + i18n strings ---------------------------------
//
// Locale picked in this priority:
//   1) ?lang= query param (operator-friendly aliases: "english" / "zh_CN")
//   2) Accept-Language header (first supported language listed)
//   3) Default "zh-CN" (the page chrome's historical language)
//
// Supported set is small + curated — adding a new locale = adding it
// here + filling messages map. No automatic translation.

const iosdistDefaultLocale = "zh-CN"

var iosdistSupportedLocales = []string{"zh-CN", "en", "ja", "ko"}

// iosdistLocaleAliases normalizes the common ways a query param might
// arrive ("english", "zh_CN", "Chinese", "中文", "ja-JP", ...) into our
// canonical BCP-47 codes.
var iosdistLocaleAliases = map[string]string{
	"zh":       "zh-CN",
	"zh-cn":    "zh-CN",
	"zh_cn":    "zh-CN",
	"zh-hans":  "zh-CN",
	"zh_hans":  "zh-CN",
	"chinese":  "zh-CN",
	"中文":       "zh-CN",
	"en":       "en",
	"en-us":    "en",
	"en_us":    "en",
	"en-gb":    "en",
	"en_gb":    "en",
	"english":  "en",
	"ja":       "ja",
	"ja-jp":    "ja",
	"ja_jp":    "ja",
	"japanese": "ja",
	"ko":       "ko",
	"ko-kr":    "ko",
	"ko_kr":    "ko",
	"korean":   "ko",
}

// iosdistLocaleFor returns the resolved locale for this request. Always
// returns a value present in iosdistSupportedLocales.
func iosdistLocaleFor(c *gin.Context) string {
	if q := strings.TrimSpace(c.Query("lang")); q != "" {
		if mapped := iosdistMapLocale(q); mapped != "" {
			return mapped
		}
	}
	// Accept-Language: comma-separated list like "zh-CN,zh;q=0.9,en;q=0.8".
	// We do a lazy parse — take the first comma-separated entry whose
	// alias matches a supported locale.
	for _, raw := range strings.Split(c.GetHeader("Accept-Language"), ",") {
		// Strip the q-value if any: "zh;q=0.9" → "zh".
		part := strings.TrimSpace(raw)
		if i := strings.IndexByte(part, ';'); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		if mapped := iosdistMapLocale(part); mapped != "" {
			return mapped
		}
	}
	return iosdistDefaultLocale
}

func iosdistMapLocale(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if mapped, ok := iosdistLocaleAliases[s]; ok {
		return mapped
	}
	// Try a region-stripped fallback ("zh-tw" → "zh") so unmapped
	// regional variants still degrade to a known language.
	if i := strings.IndexAny(s, "-_"); i > 0 {
		if mapped, ok := iosdistLocaleAliases[s[:i]]; ok {
			return mapped
		}
	}
	return ""
}

// pickI18N returns the localized value for `locale` if present, else
// the fallback. Use for description / promo / app name overrides.
func pickI18N(m map[string]string, locale, fallback string) string {
	if m != nil {
		if v, ok := m[locale]; ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return fallback
}

// iosdistMessages is the chrome-text dictionary. Add a key here when
// you add a new UI string anywhere in the public pages so all four
// locales render the same shape.
var iosdistMessages = map[string]map[string]string{
	"zh-CN": {
		"plaza_title":            "App 广场",
		"plaza_subtitle":         "浏览所有公开发布的 iOS 应用，点卡片查看详情与安装方式",
		"plaza_count":            "共 %d 个应用",
		"plaza_empty":            "暂无公开应用",
		"plaza_view_detail":      "查看详情 →",
		"plaza_prev":             "← 上一页",
		"plaza_next":             "下一页 →",
		"share_no_version":       "暂无可用版本",
		"share_install_btn":      "安装",
		"share_testflight_btn":   "通过 TestFlight 安装",
		"share_appstore_btn":     "在 App Store 查看",
		"share_no_install":       "暂无可用安装方式",
		"share_marketing_link":   "官方网站",
		"share_support_link":     "技术支持",
		"share_request_title":    "申请加入测试",
		"share_request_desc":     "填写邮箱即可申请。提交后我们会通过 App Store Connect 向你发送官方 TestFlight 邀请邮件，按邮件指引在 TestFlight App 内接受邀请即可。",
		"share_email_ph":         "your@email.com",
		"share_first_ph":         "名 (可选)",
		"share_last_ph":          "姓 (可选)",
		"share_submit":           "提交申请",
		"share_submitting":       "提交中...",
		"share_submit_failed":    "提交失败：",
		"share_invite_sent":      "✓ 邀请已发送，请查收邮箱。",
		"share_invite_logged":    "已记录你的申请，开发者通过后会尽快邀请你。",
		"share_install_fail":     "无法生成安装链接，请稍后重试。",
		"share_install_loading":  "请求中...",
		"share_whatsnew_label":   "新版本",
		"share_whatsnew_asc":     "ASC",
		"share_whatsnew_build":   "本次构建",
		"share_dev_mode_note":    "iOS 16.4 及以上需在「设置 → 隐私与安全性 → 开发者模式」中开启开发者模式后，方可启动通过 OTA 安装的应用。请在 iPhone 自带 Safari 中打开本页面。",
		"share_footer_prefix":    "由 iOS 分发平台提供 · ",
		"share_footer_plaza":     "App 广场",
		"share_footer_share":     "分享链接",
		"lang_picker_label":      "语言：",
	},
	"en": {
		"plaza_title":            "App Plaza",
		"plaza_subtitle":         "Browse every publicly published iOS app. Tap a card for details and install options.",
		"plaza_count":            "%d apps",
		"plaza_empty":            "No public apps yet",
		"plaza_view_detail":      "View details →",
		"plaza_prev":             "← Prev",
		"plaza_next":             "Next →",
		"share_no_version":       "No version available",
		"share_install_btn":      "Install",
		"share_testflight_btn":   "Install via TestFlight",
		"share_appstore_btn":     "View on the App Store",
		"share_no_install":       "No install option available",
		"share_marketing_link":   "Website",
		"share_support_link":     "Support",
		"share_request_title":    "Request beta access",
		"share_request_desc":     "Enter your email. We'll forward the request to App Store Connect, which emails you the official TestFlight invitation. Accept it in the TestFlight app to install.",
		"share_email_ph":         "your@email.com",
		"share_first_ph":         "First name (optional)",
		"share_last_ph":          "Last name (optional)",
		"share_submit":           "Submit",
		"share_submitting":       "Submitting…",
		"share_submit_failed":    "Submit failed: ",
		"share_invite_sent":      "✓ Invitation sent — check your inbox.",
		"share_invite_logged":    "Request logged. The developer will invite you shortly.",
		"share_install_fail":     "Failed to generate install link, please retry.",
		"share_install_loading":  "Requesting…",
		"share_whatsnew_label":   "What's new",
		"share_whatsnew_asc":     "ASC",
		"share_whatsnew_build":   "this build",
		"share_dev_mode_note":    "iOS 16.4+ requires Developer Mode (Settings → Privacy & Security → Developer Mode) before OTA-installed apps will launch. Open this page in Safari on the iPhone itself.",
		"share_footer_prefix":    "Powered by the iOS distribution platform · ",
		"share_footer_plaza":     "App Plaza",
		"share_footer_share":     "Share link",
		"lang_picker_label":      "Language: ",
	},
	"ja": {
		"plaza_title":            "App プラザ",
		"plaza_subtitle":         "公開されている iOS アプリ一覧。カードをタップして詳細とインストール方法を確認できます。",
		"plaza_count":            "%d 件のアプリ",
		"plaza_empty":            "公開アプリはまだありません",
		"plaza_view_detail":      "詳細を見る →",
		"plaza_prev":             "← 前へ",
		"plaza_next":             "次へ →",
		"share_no_version":       "利用可能なバージョンがありません",
		"share_install_btn":      "インストール",
		"share_testflight_btn":   "TestFlight でインストール",
		"share_appstore_btn":     "App Store で見る",
		"share_no_install":       "利用可能なインストール方法はありません",
		"share_marketing_link":   "ウェブサイト",
		"share_support_link":     "サポート",
		"share_request_title":    "ベータ参加を申請",
		"share_request_desc":     "メールアドレスを入力してください。App Store Connect から TestFlight の公式招待メールが届きます。TestFlight アプリで招待を承認するとインストールできます。",
		"share_email_ph":         "your@email.com",
		"share_first_ph":         "名（任意）",
		"share_last_ph":          "姓（任意）",
		"share_submit":           "送信",
		"share_submitting":       "送信中…",
		"share_submit_failed":    "送信に失敗しました：",
		"share_invite_sent":      "✓ 招待を送信しました。メールをご確認ください。",
		"share_invite_logged":    "申請を受け付けました。開発者が承認次第ご連絡します。",
		"share_install_fail":     "インストールリンクの生成に失敗しました。再度お試しください。",
		"share_install_loading":  "リクエスト中…",
		"share_whatsnew_label":   "新バージョン",
		"share_whatsnew_asc":     "ASC",
		"share_whatsnew_build":   "このビルド",
		"share_dev_mode_note":    "iOS 16.4 以降ではデベロッパモード（設定 → プライバシーとセキュリティ → デベロッパモード）を有効にしないと OTA インストールしたアプリが起動できません。iPhone の Safari でこのページを開いてください。",
		"share_footer_prefix":    "iOS 配布プラットフォームによる · ",
		"share_footer_plaza":     "App プラザ",
		"share_footer_share":     "共有リンク",
		"lang_picker_label":      "言語：",
	},
	"ko": {
		"plaza_title":            "App 광장",
		"plaza_subtitle":         "공개된 iOS 앱 모음. 카드를 눌러 상세 정보와 설치 방법을 확인하세요.",
		"plaza_count":            "총 %d개의 앱",
		"plaza_empty":            "아직 공개된 앱이 없습니다",
		"plaza_view_detail":      "자세히 보기 →",
		"plaza_prev":             "← 이전",
		"plaza_next":             "다음 →",
		"share_no_version":       "사용 가능한 버전이 없습니다",
		"share_install_btn":      "설치",
		"share_testflight_btn":   "TestFlight 로 설치",
		"share_appstore_btn":     "App Store 에서 보기",
		"share_no_install":       "사용 가능한 설치 옵션이 없습니다",
		"share_marketing_link":   "웹사이트",
		"share_support_link":     "지원",
		"share_request_title":    "베타 참가 신청",
		"share_request_desc":     "이메일을 입력해 주세요. App Store Connect 에서 공식 TestFlight 초대 메일을 보내드립니다. TestFlight 앱에서 수락하면 설치할 수 있습니다.",
		"share_email_ph":         "your@email.com",
		"share_first_ph":         "이름 (선택)",
		"share_last_ph":          "성 (선택)",
		"share_submit":           "제출",
		"share_submitting":       "제출 중…",
		"share_submit_failed":    "제출 실패: ",
		"share_invite_sent":      "✓ 초대가 전송되었습니다. 이메일을 확인하세요.",
		"share_invite_logged":    "신청이 기록되었습니다. 개발자가 곧 초대하겠습니다.",
		"share_install_fail":     "설치 링크 생성에 실패했습니다. 다시 시도해 주세요.",
		"share_install_loading":  "요청 중…",
		"share_whatsnew_label":   "새 버전",
		"share_whatsnew_asc":     "ASC",
		"share_whatsnew_build":   "이번 빌드",
		"share_dev_mode_note":    "iOS 16.4+ 에서는 개발자 모드(설정 → 개인정보 보호 및 보안 → 개발자 모드)를 켜야 OTA 로 설치된 앱이 실행됩니다. 이 페이지는 iPhone Safari 에서 여세요.",
		"share_footer_prefix":    "iOS 배포 플랫폼 제공 · ",
		"share_footer_plaza":     "App 광장",
		"share_footer_share":     "공유 링크",
		"lang_picker_label":      "언어: ",
	},
}

// t returns the localized string for `key`. Falls back to the zh-CN
// dictionary if locale is missing the key (defensive — additions to
// the zh-CN dict should land first; other locales catch up).
func t(locale, key string) string {
	if dict, ok := iosdistMessages[locale]; ok {
		if v, ok := dict[key]; ok {
			return v
		}
	}
	if v, ok := iosdistMessages[iosdistDefaultLocale][key]; ok {
		return v
	}
	return key
}

// langPickerHTML renders a small inline "EN / 中文 / 日本語 / 한국어"
// chooser. Each link sets ?lang= preserving the rest of the query
// string. Active locale gets an underline.
func langPickerHTML(c *gin.Context, currentLocale string) string {
	labels := map[string]string{
		"zh-CN": "中文",
		"en":    "English",
		"ja":    "日本語",
		"ko":    "한국어",
	}
	// Preserve any other query params (page=, etc.) when switching lang.
	base := c.Request.URL.Path
	otherQuery := c.Request.URL.Query()
	otherQuery.Del("lang")
	suffix := ""
	if len(otherQuery) > 0 {
		suffix = "&" + otherQuery.Encode()
	}
	var b strings.Builder
	b.WriteString(`<div class="lang-picker"><span class="lang-label">`)
	b.WriteString(html.EscapeString(t(currentLocale, "lang_picker_label")))
	b.WriteString(`</span>`)
	for i, code := range iosdistSupportedLocales {
		if i > 0 {
			b.WriteString(`<span class="lang-sep"> · </span>`)
		}
		active := ""
		if code == currentLocale {
			active = " active"
		}
		fmt.Fprintf(&b, `<a class="lang-link%s" href="%s?lang=%s%s">%s</a>`,
			active, html.EscapeString(base), code, html.EscapeString(suffix), html.EscapeString(labels[code]))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// ---- public plaza (discovery) -------------------------------------------

const iosdistPlazaPageSize = 24

func (p *Plugin) handleIOSPublicPlaza(c *gin.Context) {
	page := 1
	if v := c.Query("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	offset := (page - 1) * iosdistPlazaPageSize
	apps, err := p.listPublicIOSApps(iosdistPlazaPageSize, offset)
	if err != nil {
		c.String(http.StatusInternalServerError, "server error")
		return
	}
	total, _ := p.countPublicIOSApps()
	pageHTML := p.renderIOSPlazaPage(c, apps, page, total)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, pageHTML)
}

func (p *Plugin) renderIOSPlazaPage(c *gin.Context, apps []IOSApp, page, total int) string {
	base := p.installPublicBaseURL(c)
	locale := iosdistLocaleFor(c)
	// Preserve ?lang= across pagination links so the language sticks.
	langSuffix := ""
	if c.Query("lang") != "" {
		langSuffix = "&lang=" + c.Query("lang")
	}

	cardsHTML := strings.Builder{}
	if len(apps) == 0 {
		cardsHTML.WriteString(`<div class="empty">` + html.EscapeString(t(locale, "plaza_empty")) + `</div>`)
	} else {
		for _, a := range apps {
			// Pick localized name + description first; fall back to the
			// plain single-language fields when the operator hasn't
			// added a translation for this locale yet.
			displayName := pickI18N(a.NameI18N, locale, a.Name)
			displayDesc := pickI18N(a.DescriptionI18N, locale, a.Description)
			iconHTML := `<div class="card-icon-fb">📱</div>`
			if a.IconURL != "" {
				iconHTML = fmt.Sprintf(`<img class="card-icon" src="%s" alt="%s" />`, html.EscapeString(a.IconURL), html.EscapeString(displayName))
			}
			desc := strings.TrimSpace(displayDesc)
			if len([]rune(desc)) > 80 {
				r := []rune(desc)
				desc = string(r[:80]) + "…"
			}
			descHTML := ""
			if desc != "" {
				descHTML = `<div class="card-desc">` + html.EscapeString(desc) + `</div>`
			}
			// Card link inherits ?lang= so clicking through to the
			// detail page lands in the same locale.
			cardHref := "/iosdist/share/" + html.EscapeString(a.PublicSlug)
			if c.Query("lang") != "" {
				cardHref += "?lang=" + c.Query("lang")
			}
			cardsHTML.WriteString(fmt.Sprintf(`
<a class="card" href="%s">
  <div class="card-head">
    %s
    <div class="card-text">
      <div class="card-title">%s</div>
      <div class="card-bundle">%s</div>
    </div>
  </div>
  %s
  <div class="card-footer">%s</div>
</a>`,
				cardHref,
				iconHTML,
				html.EscapeString(displayName),
				html.EscapeString(a.BundleID),
				descHTML,
				html.EscapeString(t(locale, "plaza_view_detail")),
			))
		}
	}

	// Pagination links — only render when needed.
	pagerHTML := ""
	totalPages := (total + iosdistPlazaPageSize - 1) / iosdistPlazaPageSize
	if totalPages > 1 {
		var prev, next string
		if page > 1 {
			prev = fmt.Sprintf(`<a class="pager-btn" href="?page=%d%s">%s</a>`, page-1, langSuffix, html.EscapeString(t(locale, "plaza_prev")))
		} else {
			prev = `<span class="pager-btn pager-btn-disabled">` + html.EscapeString(t(locale, "plaza_prev")) + `</span>`
		}
		if page < totalPages {
			next = fmt.Sprintf(`<a class="pager-btn" href="?page=%d%s">%s</a>`, page+1, langSuffix, html.EscapeString(t(locale, "plaza_next")))
		} else {
			next = `<span class="pager-btn pager-btn-disabled">` + html.EscapeString(t(locale, "plaza_next")) + `</span>`
		}
		pagerHTML = fmt.Sprintf(`<div class="pager">%s<span class="pager-info">%d / %d</span>%s</div>`, prev, page, totalPages, next)
	}

	_ = base
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>%s</title>
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:0;background:#f2f2f7;color:#1c1c1e;-webkit-font-smoothing:antialiased}
.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 60px}
.head{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:20px}
h1{margin:0;font-size:30px;font-weight:700;letter-spacing:-0.02em}
.subtitle{color:#8e8e93;font-size:14px}
.lang-picker{margin-bottom:16px;font-size:13px;color:#8e8e93}
.lang-label{margin-right:6px}
.lang-link{color:#007aff;text-decoration:none}
.lang-link.active{color:#1c1c1e;font-weight:600;text-decoration:underline}
.lang-sep{color:#c7c7cc}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px}
.card{display:flex;flex-direction:column;justify-content:space-between;background:#fff;border-radius:18px;padding:18px;box-shadow:0 1px 3px rgba(0,0,0,.04);text-decoration:none;color:inherit;transition:transform .18s,box-shadow .18s;min-height:160px}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(0,0,0,.08)}
.card-head{display:flex;gap:14px;align-items:flex-start}
.card-icon,.card-icon-fb{width:60px;height:60px;border-radius:14px;flex-shrink:0;background:linear-gradient(135deg,#e9e9ef,#cfd0d6);display:flex;align-items:center;justify-content:center;font-size:26px;color:#888;object-fit:cover}
.card-text{flex:1;min-width:0}
.card-title{font-weight:600;font-size:17px;line-height:1.2;margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card-bundle{font-size:11px;color:#8e8e93;font-family:ui-monospace,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card-desc{margin-top:12px;color:#3c3c43;font-size:13px;line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.card-footer{margin-top:14px;color:#007aff;font-size:13px;font-weight:500}
.empty{grid-column:1/-1;padding:80px 20px;text-align:center;color:#8e8e93;font-size:15px}
.pager{display:flex;align-items:center;justify-content:center;gap:14px;margin-top:36px}
.pager-btn{padding:10px 16px;border-radius:10px;background:#fff;color:#007aff;text-decoration:none;font-size:14px;font-weight:500;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.pager-btn-disabled{color:#c7c7cc;background:transparent;box-shadow:none}
.pager-info{color:#8e8e93;font-size:13px}
@media(prefers-color-scheme:dark){
  body{background:#000;color:#f2f2f7}
  .card,.pager-btn{background:#1c1c1e;box-shadow:none}
  .card-bundle,.subtitle,.card-desc{color:#aeaeb2}
  .pager-btn{color:#0a84ff}
  .pager-btn-disabled{background:transparent;color:#48484a}
  .empty{color:#aeaeb2}
  .lang-link.active{color:#f2f2f7}
}
</style>
</head><body>
<div class="wrap">
  %s
  <div class="head">
    <div>
      <h1>%s</h1>
      <div class="subtitle">%s</div>
    </div>
    <div class="subtitle">%s</div>
  </div>
  <div class="grid">%s</div>
  %s
</div>
</body></html>`,
		html.EscapeString(locale),
		html.EscapeString(t(locale, "plaza_title")),
		langPickerHTML(c, locale),
		html.EscapeString(t(locale, "plaza_title")),
		html.EscapeString(t(locale, "plaza_subtitle")),
		html.EscapeString(fmt.Sprintf(t(locale, "plaza_count"), total)),
		cardsHTML.String(),
		pagerHTML,
	)
}

// ---- public landing page ------------------------------------------------

func (p *Plugin) handleIOSPublicShareHTML(c *gin.Context) {
	app, latest, ok := p.lookupPublicAppForRequest(c)
	if !ok {
		return
	}
	pageHTML := p.renderIOSSharePage(c, app, latest)
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.String(http.StatusOK, pageHTML)
}

// lookupPublicAppForRequest validates the slug and visibility, fetches
// the latest version, and writes a 404 / 410 response when the request
// can't proceed. Returns ok=false if the caller should stop.
func (p *Plugin) lookupPublicAppForRequest(c *gin.Context) (*IOSApp, *IOSVersion, bool) {
	slug := strings.TrimSpace(c.Param("slug"))
	app, err := p.getIOSAppBySlug(slug)
	if err != nil {
		c.String(http.StatusInternalServerError, "server error")
		return nil, nil, false
	}
	if app == nil || !app.IsPublic {
		c.String(http.StatusNotFound, "not found")
		return nil, nil, false
	}
	versions, _ := p.listIOSVersions(app.ID)
	var latest *IOSVersion
	if len(versions) > 0 {
		latest = &versions[0]
	}
	return app, latest, true
}

// renderIOSSharePage hand-rolls the HTML — single page, mobile-first,
// loosely App-Store-feeling. The form actions are JSON endpoints; we
// only need a tiny inline script.
func (p *Plugin) renderIOSSharePage(c *gin.Context, app *IOSApp, latest *IOSVersion) string {
	base := p.installPublicBaseURL(c)
	shareURL := base + "/iosdist/share/" + app.PublicSlug
	locale := iosdistLocaleFor(c)

	// Localized name: app.NameI18N[locale] → app.Name → latest IPA's
	// display name (the IPA-embedded name is the source of truth for
	// "what shows on the home screen" even if i18n is missing).
	displayName := html.EscapeString(pickI18N(app.NameI18N, locale, app.Name))
	if latest != nil && latest.IPADisplayName != "" && pickI18N(app.NameI18N, locale, "") == "" {
		displayName = html.EscapeString(latest.IPADisplayName)
	}
	bundle := html.EscapeString(app.BundleID)

	versionLine := t(locale, "share_no_version")
	sizeLine := ""
	minOSLine := ""
	releaseNotesHTML := ""
	canOTAInstall := false
	if latest != nil {
		ver := latest.Version
		if ver == "" || ver == "0" {
			ver = latest.IPAShortVersion
		}
		buildSuffix := ""
		if latest.BuildNumber != "" {
			buildSuffix = " · build " + html.EscapeString(latest.BuildNumber)
		}
		versionLine = fmt.Sprintf("v%s%s · %s", html.EscapeString(ver), buildSuffix, html.EscapeString(distTypeLabelForPublic(latest.DistributionType)))
		if latest.IPASize > 0 {
			sizeLine = fmt.Sprintf("%.1f MB", float64(latest.IPASize)/(1024*1024))
		}
		if latest.IPAMinOS != "" {
			minOSLine = "iOS " + html.EscapeString(latest.IPAMinOS) + "+"
		}
		if latest.ReleaseNotes != "" {
			releaseNotesHTML = `<div class="notes">` + html.EscapeString(latest.ReleaseNotes) + `</div>`
		}
		canOTAInstall = iosdistDistTypeOTAInstallable(latest.DistributionType) && latest.IPAUrl != ""
	}

	iconHTML := `<div class="icon-fallback">📱</div>`
	if app.IconURL != "" {
		iconHTML = fmt.Sprintf(`<img class="icon" src="%s" alt="%s" />`, html.EscapeString(app.IconURL), displayName)
	}

	// Action buttons: order is OTA install → TestFlight → App Store
	// (we only emit the buttons that actually have a destination).
	var actionsHTML strings.Builder
	if canOTAInstall {
		actionsHTML.WriteString(`<button id="installBtn" class="btn primary" type="button">` + html.EscapeString(t(locale, "share_install_btn")) + `</button>`)
	}
	if app.TestFlightURL != "" {
		actionsHTML.WriteString(fmt.Sprintf(`<a class="btn" href="%s" target="_blank" rel="noopener">%s</a>`, html.EscapeString(app.TestFlightURL), html.EscapeString(t(locale, "share_testflight_btn"))))
	}
	if app.ASCAppID != "" {
		actionsHTML.WriteString(fmt.Sprintf(`<a class="btn" href="https://apps.apple.com/app/id%s" target="_blank" rel="noopener">%s</a>`, html.EscapeString(app.ASCAppID), html.EscapeString(t(locale, "share_appstore_btn"))))
	}
	if actionsHTML.Len() == 0 {
		actionsHTML.WriteString(`<span class="muted">` + html.EscapeString(t(locale, "share_no_install")) + `</span>`)
	}

	// Secondary links: marketing site + support page. Rendered as a
	// quieter secondary row below primary CTAs.
	var linksHTML strings.Builder
	if strings.TrimSpace(app.MarketingURL) != "" {
		linksHTML.WriteString(fmt.Sprintf(`<a class="link" href="%s" target="_blank" rel="noopener">%s</a>`, html.EscapeString(app.MarketingURL), html.EscapeString(t(locale, "share_marketing_link"))))
	}
	if strings.TrimSpace(app.SupportURL) != "" {
		linksHTML.WriteString(fmt.Sprintf(`<a class="link" href="%s" target="_blank" rel="noopener">%s</a>`, html.EscapeString(app.SupportURL), html.EscapeString(t(locale, "share_support_link"))))
	}
	linksRowHTML := ""
	if linksHTML.Len() > 0 {
		linksRowHTML = `<div class="links">` + linksHTML.String() + `</div>`
	}

	requestFormHTML := ""
	if app.ASCBetaGroupID != "" {
		requestFormHTML = fmt.Sprintf(`
<section class="card">
  <h3>%s</h3>
  <p class="muted">%s</p>
  <form id="requestForm">
    <input id="reqEmail" type="email" required placeholder="%s" />
    <div class="row">
      <input id="reqFirst" type="text" placeholder="%s" />
      <input id="reqLast" type="text" placeholder="%s" />
    </div>
    <button class="btn primary" type="submit">%s</button>
    <div id="reqStatus" class="status"></div>
  </form>
</section>`,
			html.EscapeString(t(locale, "share_request_title")),
			html.EscapeString(t(locale, "share_request_desc")),
			html.EscapeString(t(locale, "share_email_ph")),
			html.EscapeString(t(locale, "share_first_ph")),
			html.EscapeString(t(locale, "share_last_ph")),
			html.EscapeString(t(locale, "share_submit")),
		)
	}

	// Promotional text is small italic above the longer description (App
	// Store visual analog). Description is the main body. Keywords show
	// as subtle pills near the bundle line. Both honor i18n overrides.
	descHTML := ""
	promoLocalized := pickI18N(app.PromotionalTextI18N, locale, app.PromotionalText)
	descLocalized := pickI18N(app.DescriptionI18N, locale, app.Description)
	if strings.TrimSpace(promoLocalized) != "" {
		descHTML += `<p class="promo">` + html.EscapeString(promoLocalized) + `</p>`
	}
	if strings.TrimSpace(descLocalized) != "" {
		descHTML += `<p class="desc">` + html.EscapeString(descLocalized) + `</p>`
	}

	keywordsHTML := ""
	if strings.TrimSpace(app.Keywords) != "" {
		var pills []string
		for _, k := range strings.Split(app.Keywords, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				pills = append(pills, `<span class="kw">`+html.EscapeString(k)+`</span>`)
			}
		}
		if len(pills) > 0 {
			keywordsHTML = `<div class="kws">` + strings.Join(pills, "") + `</div>`
		}
	}

	// "What's New" — prefer the app-level whats_new from ASC (this is
	// the latest App Store version's text), fall back to the most recent
	// platform-uploaded version's release_notes when ASC didn't supply
	// any.
	whatsNewBody := strings.TrimSpace(app.WhatsNew)
	whatsNewSource := t(locale, "share_whatsnew_asc")
	if whatsNewBody == "" && latest != nil && strings.TrimSpace(latest.ReleaseNotes) != "" {
		whatsNewBody = latest.ReleaseNotes
		whatsNewSource = t(locale, "share_whatsnew_build")
	}
	whatsNewHTML := ""
	if whatsNewBody != "" {
		whatsNewHTML = fmt.Sprintf(
			`<section class="card whatsnew"><h3>%s <span class="src">· %s</span></h3><div class="notes">%s</div></section>`,
			html.EscapeString(t(locale, "share_whatsnew_label")),
			html.EscapeString(whatsNewSource),
			html.EscapeString(whatsNewBody),
		)
	}
	releaseNotesHTML = "" // moved into whatsNewHTML above; clear the old slot

	// Inline script: install button hits POST /install, redirects to itms-services://
	// The test request form posts JSON. Localized message strings are
	// injected via the format args below — script body itself is
	// language-agnostic.
	scriptTpl := `
const installBtn = document.getElementById("installBtn");
if (installBtn) {
  installBtn.addEventListener("click", async () => {
    installBtn.disabled = true; installBtn.textContent = %q;
    try {
      const r = await fetch("%s/iosdist/share/%s/install", { method: "POST" });
      if (!r.ok) throw new Error("install token failed");
      const data = await r.json();
      window.location.href = data.itms_services;
    } catch (e) {
      alert(%q);
      installBtn.disabled = false; installBtn.textContent = %q;
    }
  });
}
const form = document.getElementById("requestForm");
if (form) {
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const status = document.getElementById("reqStatus");
    status.textContent = %q;
    try {
      const r = await fetch("%s/iosdist/share/%s/test-request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: document.getElementById("reqEmail").value.trim(),
          first_name: document.getElementById("reqFirst").value.trim(),
          last_name: document.getElementById("reqLast").value.trim(),
        }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || %q);
      status.textContent = data.delivered === false ? %q : %q;
      form.reset();
    } catch (e) {
      status.textContent = %q + e.message;
    }
  });
}
`
	script := fmt.Sprintf(scriptTpl,
		t(locale, "share_install_loading"),
		base, app.PublicSlug,
		t(locale, "share_install_fail"),
		t(locale, "share_install_btn"),
		t(locale, "share_submitting"),
		base, app.PublicSlug,
		t(locale, "share_submit_failed"),
		t(locale, "share_invite_logged"),
		t(locale, "share_invite_sent"),
		t(locale, "share_submit_failed"),
	)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>%s</title>
<meta property="og:title" content="%s">
<meta property="og:url" content="%s">
<style>
*{box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:0;background:#f2f2f7;color:#1c1c1e;-webkit-font-smoothing:antialiased}
.wrap{max-width:560px;margin:0 auto;padding:24px}
.hero{display:flex;gap:16px;align-items:flex-start;background:#fff;border-radius:18px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.icon,.icon-fallback{width:96px;height:96px;border-radius:22px;flex-shrink:0;background:linear-gradient(135deg,#e9e9ef,#cfd0d6);display:flex;align-items:center;justify-content:center;font-size:42px;color:#888;object-fit:cover}
.title{font-size:22px;font-weight:600;margin:0 0 4px;line-height:1.2}
.bundle{font-size:12px;color:#8e8e93;margin-bottom:8px;font-family:ui-monospace,Menlo,monospace;word-break:break-all}
.meta{font-size:13px;color:#3c3c43}
.meta span{display:inline-block;margin-right:10px}
.actions{display:flex;flex-direction:column;gap:10px;margin:16px 0}
.btn{appearance:none;border:none;padding:14px 18px;border-radius:14px;font-size:15px;font-weight:600;text-decoration:none;text-align:center;color:#007aff;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.04);cursor:pointer;display:block;transition:opacity .15s}
.btn:active{opacity:.6}
.btn.primary{background:#007aff;color:#fff;box-shadow:0 4px 12px rgba(0,122,255,.3)}
.muted{color:#8e8e93;font-size:13px}
.promo{margin:16px 0 4px;color:#1c1c1e;font-size:14px;font-style:italic;line-height:1.5;white-space:pre-wrap}
.desc{margin:8px 0 16px;color:#3c3c43;line-height:1.55;font-size:14px;white-space:pre-wrap}
.notes{font-size:13px;color:#3c3c43;white-space:pre-wrap;line-height:1.55}
.kws{margin:10px 0 0;display:flex;flex-wrap:wrap;gap:6px}
.kw{background:#fff;border-radius:8px;padding:3px 10px;font-size:12px;color:#3c3c43;box-shadow:0 1px 2px rgba(0,0,0,.04)}
.whatsnew h3{margin:0 0 6px;font-size:15px}
.whatsnew .src{color:#8e8e93;font-weight:normal;font-size:12px}
.links{display:flex;gap:14px;margin:16px 0 0;flex-wrap:wrap}
.link{color:#007aff;text-decoration:none;font-size:13px}
.link:active{opacity:.6}
.card{background:#fff;border-radius:18px;padding:20px;margin-top:16px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
.card h3{margin:0 0 8px;font-size:17px}
.card form{display:flex;flex-direction:column;gap:10px;margin-top:12px}
.card input{width:100%%;padding:12px;border:1px solid #d1d1d6;border-radius:10px;font-size:14px;font-family:inherit}
.card .row{display:flex;gap:8px}
.card .row input{flex:1;min-width:0}
.status{font-size:13px;color:#8e8e93;min-height:1em}
.tip{margin:24px 0;padding:14px 16px;background:#fff8e1;border-radius:12px;font-size:12px;color:#5d4e15;line-height:1.6}
.footer{margin:24px 0 8px;text-align:center;font-size:12px;color:#aeaeb2}
.lang-picker{margin:0 0 16px;font-size:12px;color:#8e8e93;text-align:right}
.lang-label{margin-right:6px}
.lang-link{color:#007aff;text-decoration:none}
.lang-link.active{color:#1c1c1e;font-weight:600;text-decoration:underline}
.lang-sep{color:#c7c7cc}
@media(prefers-color-scheme:dark){
  body{background:#000;color:#f2f2f7}
  .hero,.card,.btn,.notes,.kw{background:#1c1c1e;box-shadow:none}
  .btn{color:#0a84ff}
  .btn.primary{background:#0a84ff;color:#fff}
  .card input{background:#2c2c2e;border-color:#3a3a3c;color:#f2f2f7}
  .bundle,.muted,.meta,.desc,.promo,.status,.notes,.kw,.whatsnew .src{color:#aeaeb2}
  .link{color:#0a84ff}
  .tip{background:#3a2f15;color:#f0d97a}
  .lang-link.active{color:#f2f2f7}
}
</style>
</head><body>
<div class="wrap">
  %s
  <div class="hero">
    %s
    <div style="flex:1;min-width:0">
      <h1 class="title">%s</h1>
      <div class="bundle">%s</div>
      <div class="meta">
        <span>%s</span>
        %s
        %s
      </div>
      %s
    </div>
  </div>
  %s
  <div class="actions">%s</div>
  %s
  %s
  %s
  %s
  <div class="tip">
    %s
  </div>
  <div class="footer">%s<a href="/iosdist/plaza" style="color:inherit;text-decoration:underline">%s</a> · <a href="%s" style="color:inherit;text-decoration:underline">%s</a></div>
</div>
<script>%s</script>
</body></html>`,
		html.EscapeString(locale),
		displayName, displayName, html.EscapeString(shareURL),
		langPickerHTML(c, locale),
		iconHTML,
		displayName,
		bundle,
		versionLine,
		ifNotEmpty(sizeLine, `<span>`+sizeLine+`</span>`),
		ifNotEmpty(minOSLine, `<span>`+minOSLine+`</span>`),
		keywordsHTML,
		descHTML,
		actionsHTML.String(),
		linksRowHTML,
		releaseNotesHTML,
		whatsNewHTML,
		requestFormHTML,
		html.EscapeString(t(locale, "share_dev_mode_note")),
		html.EscapeString(t(locale, "share_footer_prefix")),
		html.EscapeString(t(locale, "share_footer_plaza")),
		html.EscapeString(shareURL),
		html.EscapeString(t(locale, "share_footer_share")),
		script,
	)
}

func ifNotEmpty(s, full string) string {
	if s == "" {
		return ""
	}
	return full
}

func distTypeLabelForPublic(t string) string {
	switch t {
	case "ad_hoc":
		return "Ad-hoc"
	case "enterprise":
		return "Enterprise"
	case "development":
		return "Development"
	case "app_store":
		return "App Store"
	}
	return t
}

// ---- /install endpoint --------------------------------------------------

func (p *Plugin) handleIOSPublicShareInstall(c *gin.Context) {
	app, latest, ok := p.lookupPublicAppForRequest(c)
	if !ok {
		return
	}
	if latest == nil || latest.IPAUrl == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "暂无可用版本"})
		return
	}
	if !iosdistDistTypeOTAInstallable(latest.DistributionType) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该版本不可通过 OTA 安装"})
		return
	}
	tok := &IOSInstallToken{
		Token:     generateIOSInstallToken(),
		VersionID: latest.ID,
		CreatedBy: app.OwnerUserID,
		ExpiresAt: time.Now().Add(iosdistTokenTTL),
	}
	if err := p.createIOSInstallToken(tok); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}
	base := p.installPublicBaseURL(c)
	manifestURL := base + "/iosdist/manifest/" + tok.Token + ".plist"
	c.JSON(http.StatusOK, gin.H{
		"install_url":   base + "/iosdist/install/" + tok.Token,
		"manifest_url":  manifestURL,
		"itms_services": "itms-services://?action=download-manifest&url=" + manifestURL,
	})
}

// ---- /test-request endpoint --------------------------------------------

type iosShareTestRequestPayload struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// In-memory IP throttler. Keyed by source IP, evicted on next access
// after the window passes. Fine for single-instance deploys; a Redis
// bucket would replace this for HA.
var (
	iosShareIPThrottleMu sync.Mutex
	iosShareIPThrottle   = map[string][]time.Time{}
)

const (
	iosShareIPMaxPerHour     = 10
	iosShareEmailDuplicateTTL = 24 * time.Hour
)

func iosShareThrottleAllow(ip string) bool {
	if ip == "" {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-time.Hour)
	iosShareIPThrottleMu.Lock()
	defer iosShareIPThrottleMu.Unlock()
	hits := iosShareIPThrottle[ip]
	pruned := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	if len(pruned) >= iosShareIPMaxPerHour {
		iosShareIPThrottle[ip] = pruned
		return false
	}
	pruned = append(pruned, now)
	iosShareIPThrottle[ip] = pruned
	return true
}

func (p *Plugin) handleIOSPublicShareTestRequest(c *gin.Context) {
	app, _, ok := p.lookupPublicAppForRequest(c)
	if !ok {
		return
	}
	var req iosShareTestRequestPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的输入数据"})
		return
	}
	email := strings.TrimSpace(req.Email)
	if _, err := mail.ParseAddress(email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱格式无效"})
		return
	}
	ip := c.ClientIP()
	if !iosShareThrottleAllow(ip) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "请求过于频繁，请稍后再试"})
		return
	}
	// De-dup: same email + same app within 24h is rejected to keep ASC
	// from sending duplicate invites.
	if n, err := p.countIOSTestRequestsByEmail(app.ID, email, time.Now().Add(-iosShareEmailDuplicateTTL)); err == nil && n > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "该邮箱在 24 小时内已申请过，请勿重复提交"})
		return
	}

	rec := &IOSTestRequest{
		AppID:     app.ID,
		Email:     email,
		FirstName: strings.TrimSpace(req.FirstName),
		LastName:  strings.TrimSpace(req.LastName),
		SourceIP:  ip,
		UserAgent: c.GetHeader("User-Agent"),
		Status:    "pending",
	}
	if err := p.createIOSTestRequest(rec); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器错误"})
		return
	}

	// Try to forward to ASC if the operator has it configured AND a
	// beta group is bound. Anything missing → keep status=pending so
	// the operator can manually invite from the admin inbox.
	delivered := false
	if app.ASCBetaGroupID != "" {
		if cfg, err := p.getIOSASCConfig(app.WorkspaceID); err == nil && cfg != nil {
			if err := p.ascCreateTester(c.Request.Context(), cfg, email, rec.FirstName, rec.LastName, []string{app.ASCBetaGroupID}); err != nil {
				_ = p.markIOSTestRequest(rec.ID, "failed", err.Error())
			} else {
				_ = p.markIOSTestRequest(rec.ID, "sent", "tester invited via ASC")
				delivered = true
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "delivered": delivered})
}
