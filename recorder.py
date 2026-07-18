"""
Аддон для mitmproxy — вешаем движок TLS-перехвата на mitmproxy (не
переизобретаем это), а сами только слушаем готовые flow и пишем их
как есть в общую БД (db.py), которую потом читает Flask-бэкенд (app.py).

Запуск:
    mitmdump -s recorder.py -p 8080

Сертификат для перехвата HTTPS mitmproxy генерирует сам при первом
запуске (~/.mitmproxy/mitmproxy-ca-cert.pem) — его нужно один раз
установить в доверенные корневые сертификаты браузера/системы,
которую вы используете для тестирования. Подробности — в README.md.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import db  # noqa: E402


def _headers_to_raw(headers) -> bytes:
    """Собираем заголовки обратно в сырые байты, сохраняя порядок и дубли."""
    out = b""
    for name, value in headers.fields:
        out += name + b": " + value + b"\r\n"
    return out


def _request_to_raw(request) -> bytes:
    request_line = f"{request.method} {request.path} {request.http_version}\r\n".encode("latin-1")
    headers = _headers_to_raw(request.headers)
    body = request.raw_content or b""
    return request_line + headers + b"\r\n" + body


def _response_to_raw(response) -> bytes:
    reason = response.reason or ""
    status_line = f"{response.http_version} {response.status_code} {reason}\r\n".encode("latin-1")
    headers = _headers_to_raw(response.headers)
    body = response.raw_content or b""
    return status_line + headers + b"\r\n" + body


class Recorder:
    def load(self, loader):
        db.init_db()

    def response(self, flow):
        req = flow.request
        resp = flow.response

        raw_req = _request_to_raw(req).decode("latin-1")
        raw_resp = _response_to_raw(resp).decode("latin-1") if resp is not None else None

        duration_ms = None
        if resp is not None and req.timestamp_start and resp.timestamp_end:
            duration_ms = int((resp.timestamp_end - req.timestamp_start) * 1000)

        db.insert_entry(
            source="proxy",
            host=req.host,
            port=req.port,
            scheme=req.scheme,
            method=req.method,
            path=req.path,
            raw_request=raw_req,
            raw_response=raw_resp,
            resp_status=resp.status_code if resp is not None else None,
            duration_ms=duration_ms,
        )

    def error(self, flow):
        # Запрос не долетел до ответа (обрыв соединения, таймаут и т.п.) —
        # тоже пишем, чтобы не терять контекст (мало ли, это и есть находка).
        req = flow.request
        raw_req = _request_to_raw(req).decode("latin-1")
        db.insert_entry(
            source="proxy",
            host=req.host,
            port=req.port,
            scheme=req.scheme,
            method=req.method,
            path=req.path,
            raw_request=raw_req,
            raw_response=None,
            resp_status=None,
            error=str(flow.error) if flow.error else "unknown error",
        )


addons = [Recorder()]
