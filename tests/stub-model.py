#!/usr/bin/env python3
"""Stub model server for the sparkpass gateway tests (eng review D6).

  GET  /v1/models              one model, "stub-model"
  POST /v1/chat/completions    with "stream": true: one SSE chunk each --interval,
  POST /v1/completions         --chunks chunks, then "data: [DONE]"; else one JSON object
  GET  /stub/status            {"running": N}, N = completion requests in progress now

The defaults (1200 chunks, 0.5 s) keep a stream open for 10 minutes, across a
five-minute deadline. When the client of a stream goes away, a later write
fails and the request leaves the count, about two intervals after the close.
The gateway test uses this to prove that the gateway closes the upstream
request when it cuts a guest.

The stub has no failure mode. Use signals on the process:
  stub stopped:  kill <pid>         connection refused; the gateway answers 503
  stub frozen:   kill -STOP <pid>   connections open but nothing answers; the gateway
                                    request times out (kill -CONT <pid> resumes)

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


def payload(chat, stream, finish):
    if not chat:
        kind, choice = "text_completion", {"text": "stub "}
    elif stream:
        kind, choice = "chat.completion.chunk", {"delta": {"content": "stub "}}
    else:
        kind, choice = "chat.completion", {"message": {"role": "assistant", "content": "stub"}}
    choice.update(index=0, finish_reason=finish)
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
        elif self.path == "/stub/status":
            self.send_json(200, {"running": self.server.running})
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        # Read the body first, so that a keep-alive connection stays in step. No chunked request bodies.
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path not in ("/v1/chat/completions", "/v1/completions"):
            return self.send_json(404, {"error": "not found"})
        try:
            stream = json.loads(raw or b"{}").get("stream") is True
        except (ValueError, AttributeError):
            return self.send_json(400, {"error": "the body is not a JSON object"})
        chat = self.path == "/v1/chat/completions"
        with self.server.lock:
            self.server.running += 1
        try:
            if stream:
                self.send_stream(chat)
            else:
                self.send_json(200, payload(chat, False, "stop"))
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True  # the client went away
        finally:
            with self.server.lock:
                self.server.running -= 1

    def send_stream(self, chat):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")  # no Content-Length: the close ends the body
        self.end_headers()
        chunks = self.server.chunks
        for i in range(chunks):
            finish = "stop" if i == chunks - 1 else None
            self.wfile.write(b"data: " + json.dumps(payload(chat, True, finish)).encode() + b"\n\n")
            self.wfile.flush()
            time.sleep(self.server.interval)
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def make_server(bind, port, interval, chunks, verbose):
    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.interval, srv.chunks, srv.verbose = interval, chunks, verbose
    srv.running, srv.lock = 0, threading.Lock()
    return srv


def self_test():
    srv = make_server("127.0.0.1", 0, 0.01, 3, False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def call(method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
        conn.request(method, path, None if body is None else json.dumps(body), {"Connection": "close"})
        return conn.getresponse()

    def running():
        return json.loads(call("GET", "/stub/status").read())["running"]

    def back_to_zero():
        end = time.time() + 2
        while running() != 0 and time.time() < end:
            time.sleep(0.01)
        return running() == 0

    def check(name, ok):
        if not ok:
            sys.exit("self-test FAILED: " + name)  # exit code 1

    r = call("GET", "/v1/models")
    check("/v1/models", r.status == 200 and json.loads(r.read())["data"] == [{"id": MODEL, "object": "model"}])
    r = call("POST", "/v1/chat/completions", {"stream": True})
    events = [line[6:] for line in r.read().decode().splitlines() if line.startswith("data: ")]
    check("short stream: 3 chunks, then [DONE]",
          r.status == 200 and r.getheader("Content-Type") == "text/event-stream" and len(events) == 4
          and events[3] == "[DONE]" and all(json.loads(e)["object"] == "chat.completion.chunk" for e in events[:3])
          and json.loads(events[2])["choices"][0]["finish_reason"] == "stop")
    r = call("POST", "/v1/completions", {"prompt": "hi"})
    check("no stream: one JSON object", r.status == 200 and json.loads(r.read())["object"] == "text_completion")
    srv.chunks = 50  # a stream of 0.5 s
    r = call("POST", "/v1/chat/completions", {"stream": True})
    r.readline()
    check("status 1 during a stream", running() == 1)
    r.read()
    check("status 0 after a stream", back_to_zero())
    srv.chunks = 100000  # the stream cannot end by itself during the test
    r = call("POST", "/v1/completions", {"stream": True})
    r.readline()
    check("status 1 before the client closes", running() == 1)
    r.close()
    check("status 0 after the client closes early", back_to_zero())
    check("404", call("GET", "/nope").status == 404 and call("POST", "/v1/nope", {}).status == 404)
    srv.shutdown()
    print("self-test ok")


def main():
    p = argparse.ArgumentParser(description="Stub model server for the sparkpass gateway tests.")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--interval", type=float, default=0.5, help="seconds between stream chunks")
    p.add_argument("--chunks", type=int, default=1200, help="number of chunks in a stream")
    p.add_argument("--verbose", action="store_true", help="log each request to stderr")
    p.add_argument("--self-test", action="store_true", help="run the built-in checks and exit")
    args = p.parse_args()
    if args.self_test:
        return self_test()
    srv = make_server(args.bind, args.port, args.interval, args.chunks, args.verbose)
    print("stub-model: http://%s:%d/v1" % (args.bind, srv.server_address[1]), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
