// Package rawhttp — минимальный побайтово-точный разбор HTTP/1.x поверх
// произвольного io.Reader/net.Conn.
//
// Ключевая идея всего haqproxy: НЕ использовать net/http для чтения запросов и
// ответов, потому что net/http нормализует заголовки (порядок, регистр,
// схлопывание дублей). Для security-тестирования (request smuggling, обход WAF
// по регистру/порядку заголовков) нужно сохранить и переслать ровно те байты,
// что пришли. Поэтому здесь свой ридер: он вычитывает сырой заголовочный блок
// как есть и определяет длину тела по Content-Length / Transfer-Encoding:chunked
// / до закрытия соединения — но сами байты не переписывает.
//
// Это тот самый "свой парсер поверх net.Conn", который в §4 ТЗ упоминается как
// способ получить побайтовую точность и в пассивной истории, а не только в Replay.
package rawhttp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// maxHeaderBytes — предел на размер заголовочного блока, защита от бесконечного
// чтения при мусорном вводе.
const maxHeaderBytes = 1 << 20 // 1 MiB

// Message — разобранное HTTP-сообщение (запрос или ответ). Raw содержит ПОЛНЫЕ
// сырые байты (стартовая строка + заголовки + CRLF + тело) — источник правды.
type Message struct {
	Raw      []byte            // полные сырые байты сообщения
	StartLn  string            // стартовая строка без CRLF ("GET /x HTTP/1.1" или "HTTP/1.1 200 OK")
	Headers  []Header          // заголовки в исходном порядке, с исходным регистром
	Body     []byte            // тело (уже раскодированный из chunked? — нет: как в Raw после заголовков)
	HeaderNL int               // индекс байта, где начинается тело (после \r\n\r\n)
	lower    map[string]string // нижний регистр имя→последнее значение, для внутренних решений
}

// Header — одна пара заголовка, имя и значение сохранены как в исходных байтах.
type Header struct {
	Name  string
	Value string
}

// Get возвращает значение заголовка по имени без учёта регистра (последнее, если дублей несколько).
func (m *Message) Get(name string) string {
	if m.lower == nil {
		return ""
	}
	return m.lower[strings.ToLower(name)]
}

// StartLineParts разбивает стартовую строку по пробелам на до трёх частей.
func (m *Message) StartLineParts() []string {
	return strings.SplitN(m.StartLn, " ", 3)
}

// ReadMessage читает одно HTTP-сообщение из br побайтово-точно.
// isRequest влияет только на выбор дефолтной семантики тела: у запроса без
// Content-Length/chunked тело считается пустым; у ответа без них — читается до
// закрытия соединения.
func ReadMessage(br *bufio.Reader, isRequest bool) (*Message, error) {
	headerBlock, err := readHeaderBlock(br)
	if err != nil {
		return nil, err
	}

	m := &Message{lower: map[string]string{}}
	m.HeaderNL = len(headerBlock)

	// Разбор заголовочного блока на стартовую строку и заголовки.
	lines := splitCRLF(headerBlock)
	if len(lines) == 0 {
		return nil, errors.New("empty header block")
	}
	m.StartLn = lines[0]
	for _, ln := range lines[1:] {
		if ln == "" {
			continue
		}
		idx := strings.IndexByte(ln, ':')
		if idx < 0 {
			continue // не заголовок — пропускаем для метаданных, но байты уже в Raw
		}
		name := ln[:idx]
		value := strings.TrimLeft(ln[idx+1:], " \t")
		m.Headers = append(m.Headers, Header{Name: name, Value: value})
		m.lower[strings.ToLower(strings.TrimSpace(name))] = value
	}

	// Читаем тело по правилам framing.
	body, err := readBody(br, m, isRequest)
	if err != nil {
		// частично прочитанное тело всё равно сохраняем
		m.Body = body
		m.Raw = append(append([]byte{}, headerBlock...), body...)
		return m, err
	}
	m.Body = body
	m.Raw = append(append([]byte{}, headerBlock...), body...)
	return m, nil
}

// readHeaderBlock читает байты до первого \r\n\r\n включительно.
func readHeaderBlock(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		b, err := br.ReadByte()
		if err != nil {
			if buf.Len() == 0 {
				return nil, err // чистый EOF на границе сообщения
			}
			return buf.Bytes(), io.ErrUnexpectedEOF
		}
		buf.WriteByte(b)
		if buf.Len() > maxHeaderBytes {
			return nil, errors.New("header block too large")
		}
		bs := buf.Bytes()
		if len(bs) >= 4 && bytes.Equal(bs[len(bs)-4:], []byte("\r\n\r\n")) {
			return bs, nil
		}
	}
}

func readBody(br *bufio.Reader, m *Message, isRequest bool) ([]byte, error) {
	te := strings.ToLower(m.Get("Transfer-Encoding"))
	cl := m.Get("Content-Length")

	switch {
	case strings.Contains(te, "chunked"):
		return readChunked(br)
	case cl != "":
		n, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("bad Content-Length %q", cl)
		}
		return readExact(br, n)
	case isRequest:
		// запрос без индикаторов тела — тела нет
		return nil, nil
	default:
		// ответ без Content-Length и не chunked — читаем до закрытия соединения
		return io.ReadAll(br)
	}
}

func readExact(br *bufio.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(br, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return buf, io.ErrUnexpectedEOF
	}
	return buf, err
}

// readChunked читает chunked-тело и возвращает СЫРЫЕ байты как пришли (включая
// размеры чанков и терминатор), сохраняя побайтовую точность. Разбор — по
// терминатору "0\r\n...\r\n"; chunk-extensions и trailers обрабатываются
// эвристически (как в Python-прототипе, §5/§13 ТЗ), не по всей строгости RFC.
func readChunked(br *bufio.Reader) ([]byte, error) {
	var raw bytes.Buffer
	for {
		// строка размера чанка
		sizeLine, err := readLineCRLF(br)
		if err != nil {
			return raw.Bytes(), err
		}
		raw.Write(sizeLine)
		// размер — до первого ';' (chunk-extension отбрасываем при парсинге размера)
		hexPart := strings.TrimSpace(string(sizeLine))
		if i := strings.IndexByte(hexPart, ';'); i >= 0 {
			hexPart = hexPart[:i]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(hexPart), 16, 64)
		if err != nil {
			return raw.Bytes(), fmt.Errorf("bad chunk size %q", hexPart)
		}
		if size == 0 {
			// последний чанк: читаем трейлеры до пустой строки
			for {
				line, err := readLineCRLF(br)
				if err != nil {
					return raw.Bytes(), err
				}
				raw.Write(line)
				if string(line) == "\r\n" {
					return raw.Bytes(), nil
				}
			}
		}
		// данные чанка + завершающий CRLF
		data, err := readExact(br, int(size))
		raw.Write(data)
		if err != nil {
			return raw.Bytes(), err
		}
		crlf, err := readExact(br, 2)
		raw.Write(crlf)
		if err != nil {
			return raw.Bytes(), err
		}
	}
}

func readLineCRLF(br *bufio.Reader) ([]byte, error) {
	line, err := br.ReadBytes('\n')
	if err != nil {
		return line, err
	}
	return line, nil
}

func splitCRLF(block []byte) []string {
	s := string(block)
	s = strings.TrimSuffix(s, "\r\n\r\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\r\n")
}

// StatusCode извлекает числовой статус из стартовой строки ответа ("HTTP/1.1 200 OK").
func (m *Message) StatusCode() (int, bool) {
	parts := m.StartLineParts()
	if len(parts) < 2 {
		return 0, false
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}
	return code, true
}
