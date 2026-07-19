// Command collaborator — OOB-слушатель для VPS (DNS + HTTP), §10 ТЗ.
//
// Заглушка этапа 5: сам сервер (miekg/dns авторитативный листенер + HTTP-логгер
// + API с Bearer-авторизацией) реализуется в отдельной сессии. Оставлено, чтобы
// зафиксировать структуру репозитория из ТЗ (два бинарника из одного репо).
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	flag.Parse()
	fmt.Fprintln(os.Stderr, "collaborator: этап 5, ещё не реализован (см. haqproxy.md §10)")
	os.Exit(1)
}
