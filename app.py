"""
Веб-бэкенд hackproxy. Отдельный процесс от mitmproxy/recorder.py —
читает и пишет ту же SQLite (WAL-режим позволяет им не мешать друг другу).

Запуск:
    python app.py
Слушает http://127.0.0.1:5050 по умолчанию — открывать в браузере
(не через сам прокси, чтобы не проксировать самого себя).
"""

from flask import Flask, request, jsonify, send_from_directory
import db
import repeater

app = Flask(__name__, static_folder="static", static_url_path="")


@app.before_request
def _ensure_db():
    db.init_db()


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------- История ----------

@app.get("/api/history")
def api_history():
    entries = db.query_entries(
        host=request.args.get("host"),
        method=request.args.get("method"),
        status=request.args.get("status"),
        q=request.args.get("q"),
        source=request.args.get("source"),
        scope_only=request.args.get("scope_only") == "1",
        limit=int(request.args.get("limit", 200)),
    )
    return jsonify(entries)


@app.get("/api/history/<int:entry_id>")
def api_history_detail(entry_id):
    entry = db.get_entry(entry_id)
    if entry is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(entry)


@app.post("/api/history/<int:entry_id>/meta")
def api_history_meta(entry_id):
    payload = request.get_json(force=True) or {}
    db.update_entry_meta(entry_id, note=payload.get("note"), tag=payload.get("tag"))
    return jsonify({"ok": True})


# ---------- Repeater ----------

@app.post("/api/repeater/send")
def api_repeater_send():
    """
    Ожидает JSON: { host, port, tls, raw_request, parent_id?, verify_tls? }
    raw_request — полный сырой текст запроса (request-line + headers + \r\n\r\n + body).
    Отправляется байт-в-байт, без какой-либо нормализации.
    """
    payload = request.get_json(force=True) or {}
    host = payload.get("host")
    port = int(payload.get("port") or (443 if payload.get("tls") else 80))
    tls = bool(payload.get("tls"))
    raw_request = payload.get("raw_request", "")
    verify_tls = bool(payload.get("verify_tls", False))
    parent_id = payload.get("parent_id")

    if not host or not raw_request.strip():
        return jsonify({"error": "host и raw_request обязательны"}), 400

    result = repeater.send_raw_request(host, port, tls, raw_request, verify_tls=verify_tls)

    # первая строка raw_request — для метаданных в истории (method/path)
    method, path = "?", "?"
    try:
        first_line = raw_request.split("\r\n", 1)[0]
        parts = first_line.split(" ")
        method, path = parts[0], parts[1]
    except Exception:
        pass

    entry_id = db.insert_entry(
        source="repeater",
        parent_id=parent_id,
        host=host,
        port=port,
        scheme="https" if tls else "http",
        method=method,
        path=path,
        raw_request=raw_request,
        raw_response=result["raw_response"],
        resp_status=result["status"],
        duration_ms=result["duration_ms"],
        error=result["error"],
    )

    return jsonify({
        "entry_id": entry_id,
        "status": result["status"],
        "duration_ms": result["duration_ms"],
        "raw_response": result["raw_response"],
        "error": result["error"],
    })


# ---------- Scope ----------

@app.get("/api/scope")
def api_scope_list():
    return jsonify(db.list_scope())


@app.post("/api/scope")
def api_scope_add():
    payload = request.get_json(force=True) or {}
    pattern = (payload.get("pattern") or "").strip()
    if not pattern:
        return jsonify({"error": "pattern обязателен"}), 400
    db.add_scope(pattern)
    return jsonify({"ok": True})


@app.delete("/api/scope/<int:scope_id>")
def api_scope_delete(scope_id):
    db.remove_scope(scope_id)
    return jsonify({"ok": True})


@app.post("/api/scope/<int:scope_id>/toggle")
def api_scope_toggle(scope_id):
    payload = request.get_json(force=True) or {}
    db.set_scope_enabled(scope_id, bool(payload.get("enabled", True)))
    return jsonify({"ok": True})


if __name__ == "__main__":
    db.init_db()
    app.run(host="127.0.0.1", port=5050, debug=True)
