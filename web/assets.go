// Package webassets встраивает шаблоны и статику в бинарник через embed.FS,
// чтобы haqproxy оставался единым статическим файлом без Node/сборки (§2 ТЗ).
package webassets

import "embed"

// FS — встроенные HTML-шаблоны и статические файлы (htmx, css).
//
//go:embed templates/*.html static/*
var FS embed.FS
