"""
"Голый" HTTP-клиент для Repeater.

Сознательно не используем requests/httpx: они нормализуют порядок и
регистр заголовков, схлопывают дубли и т.п. — а для security-тестирования
(request smuggling, обход WAF по регистру заголовка, порядок полей) важно
отправить ровно то, что написано в редакторе, байт в байт. Поэтому здесь
свой сокет + минимальный, но корректный разбор ответа (Content-Length /
chunked / до закрытия соединения).

Ограничение v1: разбор chunked-ответа детектирует конец эвристикой
"тело заканчивается на 0\\r\\n\\r\\n" — не обрабатывает chunk-extensions
и trailers по RFC во всей полноте. Для подавляющего большинства целей
этого достаточно; если понадобится строгий разбор — дорабатываем отдельно.
"""

import socket
import ssl
import time


def _chunked_complete(body: bytes) -> bool:
    return body.endswith(b"0\r\n\r\n") or body.endswith(b"0\r\n\r\n\r\n")


def _recv_exact(sock, n, already=b"") -> bytes:
    data = already
    while len(data) < n:
        chunk = sock.recv(min(65536, n - len(data)))
        if not chunk:
            break
        data += chunk
    return data


def _read_response(sock) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return buf  # соединение закрылось раньше, чем пришли полные заголовки
        buf += chunk

    header_part, _, rest = buf.partition(b"\r\n\r\n")
    header_bytes = header_part + b"\r\n\r\n"

    headers = {}
    for line in header_part.decode("latin-1").split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    content_length = headers.get("content-length")

    if transfer_encoding == "chunked":
        body = rest
        while not _chunked_complete(body):
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
        return header_bytes + body

    if content_length is not None:
        try:
            cl = int(content_length)
        except ValueError:
            cl = 0
        body = _recv_exact(sock, cl, already=rest)
        return header_bytes + body

    # Нет Content-Length и не chunked — читаем до закрытия соединения
    # (ограничено socket timeout, выставленным в send_raw_request).
    body = rest
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
    except socket.timeout:
        pass
    return header_bytes + body


def _parse_status(raw_response: bytes):
    try:
        first_line = raw_response.split(b"\r\n", 1)[0].decode("latin-1")
        return int(first_line.split(" ", 2)[1])
    except Exception:
        return None


def send_raw_request(host: str, port: int, use_tls: bool, raw_request, timeout: float = 15.0,
                      verify_tls: bool = False) -> dict:
    """
    Отправляет raw_request (str или bytes) ровно как есть на host:port.
    Возвращает dict: raw_response (str|None), status (int|None), duration_ms, error (str|None).
    """
    start = time.time()
    sock = None
    try:
        if isinstance(raw_request, str):
            raw_request = raw_request.encode("latin-1")

        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        if use_tls:
            ctx = ssl.create_default_context()
            if not verify_tls:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        sock.sendall(raw_request)
        raw_response = _read_response(sock)
        duration_ms = int((time.time() - start) * 1000)

        return {
            "raw_response": raw_response.decode("latin-1"),
            "status": _parse_status(raw_response),
            "duration_ms": duration_ms,
            "error": None,
        }
    except Exception as e:
        return {
            "raw_response": None,
            "status": None,
            "duration_ms": int((time.time() - start) * 1000),
            "error": str(e),
        }
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
