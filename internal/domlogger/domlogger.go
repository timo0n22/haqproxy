// Package domlogger — DOM XSS sink tracker через инъекцию скрипта (§9 ТЗ).
//
// Настоящий DOMLogger++ — браузерное расширение. Чтобы не тащить отдельный
// технологический стек, для хостов в scope прокси инжектит маленький JS-сниппет
// первым тегом в <head> HTML-ответов. Сниппет monkey-patch'ит опасные DOM-синки
// и шлёт отчёт на «магический» путь того же origin — а прокси перехватывает этот
// путь локально (без mixed-content/CORS, т.к. запрос идёт на тот же хост через
// нас же) и пишет событие в store.
//
// Ограничение: инжектированный скрипт не увидит вызовы синков ДО своего
// выполнения — но, инжектируя первым в <head>, это редкий случай (см. §9).
package domlogger

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/loginovartem/haqproxy/internal/rawhttp"
)

// MagicPath — путь, на который сниппет шлёт отчёты и который прокси перехватывает.
const MagicPath = "/__haqproxy_domlog__"

// snippet — инжектируемый скрипт. Хукает частые опасные синки и шлёт sendBeacon.
var snippet = `<script>(function(){
try{
var EP=` + "`" + MagicPath + "`" + `;
function rep(sink,val){try{
var s=(val==null?"":String(val));if(s.length>2000)s=s.slice(0,2000);
var st="";try{throw new Error()}catch(e){st=e.stack||""}
navigator.sendBeacon(EP,JSON.stringify({sink:sink,value:s,stack:st}));
}catch(_){}}
function hookProp(obj,prop,name){try{
var d=Object.getOwnPropertyDescriptor(obj,prop);if(!d||!d.set)return;
Object.defineProperty(obj,prop,{configurable:true,enumerable:d.enumerable,
get:d.get,set:function(v){rep(name,v);return d.set.call(this,v)}});
}catch(_){}}
hookProp(Element.prototype,"innerHTML","Element.innerHTML");
hookProp(Element.prototype,"outerHTML","Element.outerHTML");
try{var iah=Element.prototype.insertAdjacentHTML;Element.prototype.insertAdjacentHTML=function(p,h){rep("insertAdjacentHTML",h);return iah.apply(this,arguments)}}catch(_){}
try{var dw=document.write;document.write=function(){rep("document.write",arguments[0]);return dw.apply(this,arguments)}}catch(_){}
try{var oe=window.eval;window.eval=function(c){rep("eval",c);return oe.call(this,c)}}catch(_){}
hookProp(HTMLElement.prototype,"onclick","onclick");
try{var sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(/^on/i.test(n)||n=="href"||n=="src")rep("setAttribute:"+n,v);return sa.apply(this,arguments)}}catch(_){}
}catch(_){}
})();</script>`

// ShouldInject решает, можно ли безопасно инжектить в этот ответ: только HTML,
// без сжатия (иначе не вставить в текст), с известной длиной тела (Content-Length),
// не chunked (мы храним chunked-тело сырым и не декодируем).
func ShouldInject(resp *rawhttp.Message) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Get("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return false
	}
	if enc := strings.TrimSpace(resp.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		return false
	}
	if strings.Contains(strings.ToLower(resp.Get("Transfer-Encoding")), "chunked") {
		return false
	}
	if resp.Get("Content-Length") == "" {
		return false
	}
	return true
}

// Inject возвращает копию ответа с внедрённым сниппетом и пересчитанным
// Content-Length. Если инъекция невозможна — возвращает (nil, false).
func Inject(resp *rawhttp.Message) ([]byte, bool) {
	if !ShouldInject(resp) {
		return nil, false
	}
	body := resp.Body
	newBody := insertSnippet(body)
	if newBody == nil {
		return nil, false
	}

	// Пересобираем заголовочный блок с обновлённым Content-Length.
	var b bytes.Buffer
	b.WriteString(resp.StartLn)
	b.WriteString("\r\n")
	for _, h := range resp.Headers {
		if strings.EqualFold(h.Name, "Content-Length") {
			b.WriteString(h.Name)
			b.WriteString(": ")
			b.WriteString(strconv.Itoa(len(newBody)))
			b.WriteString("\r\n")
			continue
		}
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.Write(newBody)
	return b.Bytes(), true
}

// insertSnippet вставляет сниппет первым содержимым <head> (иначе перед первым
// тегом/в начало). Возвращает nil, если тело не похоже на HTML с <head>/<html>.
func insertSnippet(body []byte) []byte {
	lower := bytes.ToLower(body)

	// после открывающего <head ...>
	if i := bytes.Index(lower, []byte("<head")); i >= 0 {
		if gt := bytes.IndexByte(body[i:], '>'); gt >= 0 {
			pos := i + gt + 1
			return splice(body, pos, snippet)
		}
	}
	// иначе — сразу после <html ...>
	if i := bytes.Index(lower, []byte("<html")); i >= 0 {
		if gt := bytes.IndexByte(body[i:], '>'); gt >= 0 {
			pos := i + gt + 1
			return splice(body, pos, snippet)
		}
	}
	// иначе — в самое начало тела
	return splice(body, 0, snippet)
}

func splice(body []byte, pos int, s string) []byte {
	out := make([]byte, 0, len(body)+len(s))
	out = append(out, body[:pos]...)
	out = append(out, s...)
	out = append(out, body[pos:]...)
	return out
}
