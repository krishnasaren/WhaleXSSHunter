from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

class CollaboratorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        print("\n[+] Blind XSS hit!")
        print("Path:", parsed.path)
        print("Params:", params)
        print("Headers:")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

server = HTTPServer(("0.0.0.0", 8008), CollaboratorHandler)
print("Listening on port 8008...")
server.serve_forever()
