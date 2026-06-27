import json
from mitmproxy import http

SKIP_EXTENSIONS = (".js", ".css", ".png", ".jpg", ".gif", ".woff", ".svg", ".ico")

class LLMRecorder:
    def request(self, flow: http.HTTPFlow):
        if flow.request.path.endswith(SKIP_EXTENSIONS):
            return
        if flow.request.method == "GET":
            return

        entry = {
            "timestamp": flow.request.timestamp_start,
            "host": flow.request.pretty_host,
            "method": flow.request.method,
            "path": flow.request.path,
            "request_body": flow.request.text,
        }
        with open("recorded.json", "a") as f:
            f.write(json.dumps(entry) + "\n")

    def response(self, flow: http.HTTPFlow):
        if flow.request.method == "GET":
            return

        entry = {
            "host": flow.request.pretty_host,
            "status": flow.response.status_code,
            "response_body": flow.response.text,
        }
        with open("recorded.json", "a") as f:
            f.write(json.dumps(entry) + "\n")

addons = [LLMRecorder()]