package extractor

// Mirrors the lists in plugins/nodeCommon.py and plugins/jsAndStaticUrlFind.py.
// Keep these as plain slices — the patterns_*.go file applies them through
// hot-path Postfilt functions, which use map / slices.Contains.

// DomainBlacklist — third-party domains we never crawl (jsAndStaticUrlFind.py:10).
var DomainBlacklist = []string{
	"www.w3.org", "example.com", "github.com", "example.org", "www.google", "googleapis.com",
}

// URLSubstrBlacklist — URL substrings that should be discarded if matched
// anywhere in the candidate. nodeCommon.py:32.
var URLSubstrBlacklist = []string{
	".js?", ".css?", ".jpeg?", ".jpg?", ".png?", ".gif?",
	"github.com", "www.w3.org", "example.com", "example.org",
	"<", ">", "{", "}", "[", "]", "|", "^", ";",
	"/js/", "location.href", "javascript:void",
}

// FileExtBlacklist — file extensions that disqualify a candidate API path.
// Derived from nodeCommon.py:34-35, with the leading dot.
var FileExtBlacklist = []string{
	".exe", ".apk", ".mp4", ".mkv", ".mp3", ".flv", ".js", ".css", ".less", ".woff", ".vue",
	".svg", ".png", ".jpg", ".jpeg", ".tif", ".bmp", ".gif", ".psd", ".exif", ".fpx",
	".avif", ".apng", ".webp", ".swf", ".ico", ".svga", ".html", ".htm", ".shtml", ".ts",
	".eot", ".lrc", ".tpl", ".cur", ".success", ".error", ".complete",
}

// StaticFileExtBlacklist — extensions disqualifying static-asset candidates.
// nodeCommon.py:43-44 (a superset of FileExtBlacklist for static).
var StaticFileExtBlacklist = []string{
	".pdf", ".docx", ".doc", ".exe", ".apk", ".mp4", ".mkv", ".mp3", ".flv", ".css", ".less",
	".woff", ".vue", ".svg", ".png", ".jpg", ".jpeg", ".tif", ".bmp", ".gif", ".psd", ".exif",
	".fpx", ".avif", ".apng", ".webp", ".swf", ".ico", ".svga", ".ts", ".eot", ".lrc",
	".tpl", ".cur", ".success", ".error", ".complete", ".zip", ".rar", ".7z",
}

// APIRootBlacklist — characters that may NOT start an api path. nodeCommon.py:29.
// The "#" variant is excluded "during spider" (apiRootBlackListDuringSpider).
var APIRootBlacklistSpider = []string{
	`\`, "$", "@", "*", "+", "-", "|", "!", "%", "^", "~", "[", "]",
}

// DangerAPISubstrings — refuse to probe an API path containing any of these,
// per nodeCommon.py:51. Matches case-insensitively.
var DangerAPISubstrings = []string{
	"del", "delete", "insert", "logout", "remove", "drop", "shutdown", "stop",
	"poweroff", "restart", "rewrite", "terminate", "deactivate", "halt", "disable",
}

// BlackDomain — refuse to treat the URL as a target if its eTLD+1 is here.
// nodeCommon.py:90.
var BlackDomain = []string{
	"acronis.com", "acronis.work", "aax.com", "htc.com", "airtable.com", "apple.com",
	"arrival.com", "aliyuncs.com", "videolan.org", "alicdn.com", "ucweb.com",
	"127.0.0.1", "google.com",
}

// BlackURLHost — refuse if the URL host contains any of these. nodeCommon.py:93.
var BlackURLHost = []string{
	"fourier.taobao.com", "127.0.0.1", "passport.baidu.com",
}

// BlackText — response body markers that mean "discard this response".
// nodeCommon.py:97-114.
var BlackText = []string{
	"<RecommendDoc>https://api.aliyun.com",
	"<Code>MethodNotAllowed</Code>",
	"<Code>AccessDenied</Code>",
	"FAIL_SYS_API_NOT_FOUNDED::请求API不存在",
	`"未找到API注册信息"`,
	`"status":400,`,
	`"status":403`,
	`"msg":"参数错误"`,
	`"miss header param x-ca-key"`,
	`"message":"No message available"`,
	`"code":1003,"message":"The specified token is expired or invalid."`,
	`{"csrf":"`,
	`"status":401,"error":"Unauthorized"`,
	`"Request method 'POST' not supported"`,
	`"error":"Internal Server Error"`,
	`"code":"HttpRequestMethodNotSupported"`,
	`"accessErrorId"`,
	"<status>403</status>",
	`"code":"AUTHX_01002"`,
	"没有匹配到对应的路由",
	`<?xml version="1.0" encoding="UTF-8"?>` + "\n<Error>",
	"哎哟喂,被挤爆啦,请稍后重试",
	`"name": "全国文化和旅游市场网上举报投诉处理系统",`,
	`"A","B","C","D"`,
	"亲,访问被拒绝了哦!请检查是否使用了代理软件或vpn哦",
	"Method Not Allowed",
	"MissingParameter",
	"OLSInvalidMethod",
	"扫一扫,去手机购买",
	"fe.sopush_service",
	"currentlySelectedLocalCountry",
	`{"code":200,"data":false}`,
	`{"code":200,"data":{"success":true}}`,
	`"调用失败,请联系页面维护人员处理"`,
	`"sig":"from bx"`,
	`"name":"SERVICE_UNAVAILABLE"`,
	"missing csrf token",
	`"ErrorCode":"AccessDenied"`,
	"unauthorized method 'GET'",
	"SERVICE_NOT_AVAILABLE",
	`"code":404`,
	`"message":"尚未登录"`,
	`"code":"referrerError"`,
	`"cityData":{"cities"`,
	`"data":"非法refere"`,
	`"data":"暂无登录"`,
	`"info":"RESOURCE_UNAVAILABLE"`,
	`"data":"404 Not found!"`,
	`"data":"参数错误"`,
	`"msg":"TOKEN ERROR"`,
	`"code":"403"`,
	"login required",
	"非法请求!未取到域名信息",
	"https://static-test.wolai.com/test/",
	"系统可能登录失效,请点击登录,在新窗口登录后继续操作",
	`{"error":"404 Not Found"}`,
	"https://developer.github.com/v3/#abuse-rate-limits",
	"接口错误,请正确使用",
	"invalid csrf token",
	`"message":"用户未登录"`,
	`"status":404`,
	`"msg":"未登录!"`,
	`"缺少用户认证信息"`,
	`"message":"系统异常`,
	`"errMessage":"缺少用户认证信息"`,
	"reffer校验失败;拒绝访问",
	`"errmsg":"系统繁忙"`,
	"登录态失效,请重新登录",
	"invalid.request.method",
	`"categoryname":"云通信"`,
	"https://login.aliexpress.com?return_url=undefined",
	"https://cdn.wostatic.cn/",
	`"errMsg":"会话超时过期"`,
	"如果第三方机构或个人对您提出质疑或投诉,高德将通知您",
	"This request mismatch any routes",
	"登录已失效,请重新登录",
	`"code":401`,
	"页面已过期,请刷新页面再操作!",
	`"gists_url": "https://api.`,
	"系统繁忙,请稍后重试",
}
