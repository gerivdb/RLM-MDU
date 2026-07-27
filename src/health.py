#!/usr/bin/env python3
"""
RLM-MDU Health Endpoint — Port 8793
Endpoint: POST /health, POST /detect, POST /fix
"""

import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rlm_mdu import detect, fix, health, metrics, rules, MDU_CONFIG, SCAN_TARGETS


class MDUHandler(BaseHTTPRequestHandler):
    """HTTP handler for RLM-MDU API"""
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def send_json(self, data: dict, status: int = 200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self.send_json({"error": "Invalid JSON"}, 400)
            return
        
        workspace = data.get("workspace", "D:/DO/WEB/TOOLS/L0-CANON/unified-design")
        patterns = data.get("patterns")
        
        if self.path == "/health":
            self.send_json(health())
        
        elif self.path == "/detect":
            result = detect(workspace, patterns)
            self.send_json(result)
        
        elif self.path == "/fix":
            dry_run = data.get("dry_run", False)
            result = fix(workspace, dry_run, patterns)
            self.send_json(result)
        
        else:
            self.send_json({"error": "Unknown endpoint"}, 404)
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/health":
            self.send_json(health())
        elif self.path == "/targets":
            self.send_json({"targets": SCAN_TARGETS.get("targets", [])})
        elif self.path == "/metrics":
            self.send_json(metrics())
        elif self.path == "/rules":
            self.send_json(rules())
        elif self.path == "/":
            self.send_json({
                "service": "RLM-MDU",
                "version": "1.0.0",
                "endpoints": {
                    "GET /health": "Health check",
                    "GET /targets": "List scan targets config",
                    "GET /metrics": "Get MIMIR metrics",
                    "GET /rules": "List all 14 ERR patterns",
                    "POST /health": "Health check",
                    "POST /detect": "Detect frictions in workspace (body: {workspace, patterns})",
                    "POST /fix": "Apply corrections (body: {workspace, dry_run, patterns})"
                },
                "mdu_config": MDU_CONFIG
            })
        else:
            self.send_json({"error": "Not found"}, 404)


def run_server(port: int = 8793):
    """Start the health endpoint server"""
    server = HTTPServer(("0.0.0.0", port), MDUHandler)
    print(f"[RLM-MDU] Health endpoint running on port {port}")
    print(f"[RLM-MDU] MDU Phase: {MDU_CONFIG['phase']}")
    print(f"[RLM-MDU] Endpoints: POST /health, POST /detect, POST /fix")
    server.serve_forever()


if __name__ == "__main__":
    run_server()