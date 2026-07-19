// Package httpql — мини-язык запросов для фильтрации истории (§6 ТЗ).
//
// Грамматика v1 (полезное подмножество HTTPQL из Caido, не полный язык):
//
//	condition := field.op:"value" | field.op:number
//	field     := host | method | path | status | body | source
//	op        := eq | cont | gt | gte | lt | lte   (gt/lt/gte/lte только для status)
//	expr      := condition (and|or condition)*
//
// Примеры:
//
//	method.eq:"POST" and status.gte:400
//	host.cont:"api" and source.eq:"replay"
//
// Компилируется в ПАРАМЕТРИЗОВАННЫЙ SQL WHERE-фрагмент: значения идут только
// через placeholder'ы (?), никогда не подставляются в строку напрямую — это наш
// же инструмент, но привычка та же, что учим на самих уязвимостях.
package httpql

import (
	"fmt"
	"strconv"
	"strings"
)

// Compiled — результат компиляции: фрагмент WHERE (без слова WHERE) и аргументы.
type Compiled struct {
	SQL  string
	Args []any
}

// колонка в таблице entries для каждого поля.
var fieldColumn = map[string]string{
	"host":   "host",
	"method": "method",
	"path":   "path",
	"status": "resp_status",
	"source": "source",
	"body":   "", // особый случай: raw_request/raw_response
}

// Compile разбирает строку запроса и возвращает параметризованный WHERE-фрагмент.
// Пустая строка → пустой Compiled (без фильтра).
func Compile(query string) (*Compiled, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return &Compiled{}, nil
	}
	toks, err := tokenize(query)
	if err != nil {
		return nil, err
	}
	return compileTokens(toks)
}

type tokKind int

const (
	tokCond tokKind = iota
	tokAnd
	tokOr
)

type token struct {
	kind  tokKind
	field string
	op    string
	value string
}

func tokenize(s string) ([]token, error) {
	var toks []token
	i := 0
	n := len(s)
	for i < n {
		// пропустить пробелы
		for i < n && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		// прочитать слово до пробела, но с учётом кавычек в value-части
		start := i
		inQuote := false
		for i < n {
			c := s[i]
			if c == '"' {
				inQuote = !inQuote
				i++
				continue
			}
			if !inQuote && (c == ' ' || c == '\t') {
				break
			}
			i++
		}
		word := s[start:i]
		lw := strings.ToLower(word)
		switch lw {
		case "and":
			toks = append(toks, token{kind: tokAnd})
		case "or":
			toks = append(toks, token{kind: tokOr})
		default:
			c, err := parseCondition(word)
			if err != nil {
				return nil, err
			}
			toks = append(toks, c)
		}
	}
	return toks, nil
}

// parseCondition разбирает "field.op:value".
func parseCondition(word string) (token, error) {
	dot := strings.IndexByte(word, '.')
	colon := strings.IndexByte(word, ':')
	if dot < 0 || colon < 0 || colon < dot {
		return token{}, fmt.Errorf("некорректное условие %q (ожидается field.op:value)", word)
	}
	field := strings.ToLower(word[:dot])
	op := strings.ToLower(word[dot+1 : colon])
	value := word[colon+1:]
	value = strings.Trim(value, `"`)

	if _, ok := fieldColumn[field]; !ok {
		return token{}, fmt.Errorf("неизвестное поле %q", field)
	}
	switch op {
	case "eq", "cont":
	case "gt", "gte", "lt", "lte":
		if field != "status" {
			return token{}, fmt.Errorf("оператор %q допустим только для status", op)
		}
	default:
		return token{}, fmt.Errorf("неизвестный оператор %q", op)
	}
	return token{kind: tokCond, field: field, op: op, value: value}, nil
}

func compileTokens(toks []token) (*Compiled, error) {
	if len(toks) == 0 {
		return &Compiled{}, nil
	}
	var sb strings.Builder
	var args []any
	expectCond := true

	for _, t := range toks {
		switch t.kind {
		case tokCond:
			if !expectCond {
				return nil, fmt.Errorf("ожидался and/or перед условием")
			}
			frag, a, err := condSQL(t)
			if err != nil {
				return nil, err
			}
			sb.WriteString(frag)
			args = append(args, a...)
			expectCond = false
		case tokAnd:
			if expectCond {
				return nil, fmt.Errorf("неожиданный 'and'")
			}
			sb.WriteString(" AND ")
			expectCond = true
		case tokOr:
			if expectCond {
				return nil, fmt.Errorf("неожиданный 'or'")
			}
			sb.WriteString(" OR ")
			expectCond = true
		}
	}
	if expectCond {
		return nil, fmt.Errorf("запрос обрывается на and/or")
	}
	return &Compiled{SQL: sb.String(), Args: args}, nil
}

func condSQL(t token) (string, []any, error) {
	col := fieldColumn[t.field]

	// body — особое поле: ищем и в запросе, и в ответе.
	if t.field == "body" {
		switch t.op {
		case "cont":
			return "(raw_request LIKE ? OR raw_response LIKE ?)",
				[]any{"%" + t.value + "%", "%" + t.value + "%"}, nil
		case "eq":
			return "(raw_request = ? OR raw_response = ?)",
				[]any{t.value, t.value}, nil
		}
	}

	switch t.op {
	case "eq":
		v := t.value
		if t.field == "method" {
			v = strings.ToUpper(v)
		}
		if t.field == "status" {
			return col + " = ?", []any{mustInt(v)}, nil
		}
		return col + " = ?", []any{v}, nil
	case "cont":
		return col + " LIKE ?", []any{"%" + t.value + "%"}, nil
	case "gt":
		return col + " > ?", []any{mustInt(t.value)}, nil
	case "gte":
		return col + " >= ?", []any{mustInt(t.value)}, nil
	case "lt":
		return col + " < ?", []any{mustInt(t.value)}, nil
	case "lte":
		return col + " <= ?", []any{mustInt(t.value)}, nil
	}
	return "", nil, fmt.Errorf("необработанный оператор %q", t.op)
}

func mustInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
