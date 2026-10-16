#!/usr/bin/env python3
"""Stub model server for tests/gateway.sh (eng review D6).

  GET  /v1/models              one model, "stub-model"
  POST /v1/chat/completions    one JSON object
  POST /v1/completions         one JSON object
  each other route             404 with a JSON body (the 404 of the gateway has no body)

The stub has no failure mode. tests/gateway.sh stops the process to check the 503 of the gateway.

Python standard library only. Runs on Python 3.9 and 3.12.
"""
import argparse
import http.client
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "stub-model"


def payload(chat):
    if chat:
        kind, choice = "chat.completion", {"message": {"role": "assistant", "content": "stub"}}
    else:
        kind, choice = "text_completion", {"text": "stub "}
    choice.update(index=0, finish_reason="stop")
    return {"id": "stub-1", "object": kind, "created": int(time.time()), "model": MODEL, "choices": [choice]}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if self.server.verbose:
            super().log_message(fmt, *args)

    def send_json(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/v1/models":
            self.send_json(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        # Read the body first, so that a keep-alive connection stays in step. No chunked request bodies.
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path not in ("/v1/chat/completions", "/v1/completions"):
            return self.send_json(404, {"error": "not found"})
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return self.send_json(400, {"error": "the body is not a JSON object"})
        self.send_json(200, payload(self.path == "/v1/chat/completions"))


def make_server(bind, port, verbose):
    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.verbose = verbose
    return srv


def self_test():
    srv = make_server("127.0.0.1", 0, False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def call(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        conn.request(method, path, None if body is None else json.dumps(body), {"Connection": "close"})
        return conn.getresponse()

    def check(name, ok):
        if not ok:
            sys.exit("self-test FAILED: " + name)  # exit code 1

    r = call("GET", "/v1/models")
    check("/v1/models", r.status == 200 and json.loads(r.read())["data"] == [{"id": MODEL, "object": "model"}])
    r = call("POST", "/v1/chat/completions", {"messages": []})
    check("chat: one JSON object", r.status == 200 and json.loads(r.read())["object"] == "chat.completion")
    r = call("POST", "/v1/completions", {"prompt": "hi"})
    check("completions: one JSON object", r.status == 200 and json.loads(r.read())["object"] == "text_completion")
    check("400 for a body that is not a JSON object", call("POST", "/v1/completions", []).status == 400)
    r = call("GET", "/nope")
    check("404 with a body", r.status == 404 and r.read() and call("POST", "/v1/nope", {}).status == 404)
    srv.shutdown()
    print("self-test ok")


def main():
    p = argparse.ArgumentParser(description="Stub model server for tests/gateway.sh.")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--verbose", action="store_true", help="log each request to stderr")
    p.add_argument("--self-test", action="store_true", help="run the built-in checks and exit")
    args = p.parse_args()
    if args.self_test:
        return self_test()
    srv = make_server(args.bind, args.port, args.verbose)
    print("stub-model: http://%s:%d/v1" % (args.bind, srv.server_address[1]), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
