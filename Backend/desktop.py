"""
SecureScan desktop launcher.

Runs the FastAPI backend on localhost in a background thread, serves the built
React frontend from the same origin, and shows it in a native window (WebView2).

Dev run:   venv\\Scripts\\python desktop.py      (after `npm run build` in Frontend)
Packaged:  built by build_desktop.ps1 into dist\\SecureScan.exe
"""
import os
import socket
import sys
import threading
import time

APP_NAME = "SecureScan"
PREFERRED_PORT = 8000  # stable port keeps the WebView origin (and its localStorage) consistent

FROZEN = getattr(sys, "frozen", False)
BASE_DIR = sys._MEIPASS if FROZEN else os.path.dirname(os.path.abspath(__file__))

# Writable per-user data folder (DB + generated PDF reports). Must be set before importing the app.
if FROZEN or not os.getenv("SECURESCAN_DATA_DIR"):
    os.environ.setdefault(
        "SECURESCAN_DATA_DIR",
        os.path.join(os.getenv("APPDATA") or os.path.expanduser("~"), APP_NAME),
    )
os.makedirs(os.environ["SECURESCAN_DATA_DIR"], exist_ok=True)

# Load optional .env (next to the exe, in the data folder, or in Backend/ during dev)
try:
    from dotenv import load_dotenv

    for env_path in (
        os.path.join(os.path.dirname(sys.executable if FROZEN else __file__), ".env"),
        os.path.join(os.environ["SECURESCAN_DATA_DIR"], ".env"),
    ):
        if os.path.isfile(env_path):
            load_dotenv(env_path)
except ImportError:
    pass

if not FROZEN:
    sys.path.insert(0, BASE_DIR)

import uvicorn  # noqa: E402
import webview  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

from main import app  # noqa: E402

FRONTEND_DIR = (
    os.path.join(BASE_DIR, "frontend_dist")
    if FROZEN
    else os.path.join(BASE_DIR, "..", "Frontend", "dist")
)


def mount_frontend():
    index_html = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.isfile(index_html):
        raise SystemExit(f"Frontend build not found at {FRONTEND_DIR}. Run `npm run build` in Frontend first.")

    assets = os.path.join(FRONTEND_DIR, "assets")
    if os.path.isdir(assets):
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    # SPA fallback: serve real files from dist/, otherwise index.html (React Router handles the path)
    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404)
        candidate = os.path.normpath(os.path.join(FRONTEND_DIR, full_path))
        if full_path and candidate.startswith(os.path.normpath(FRONTEND_DIR)) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(index_html)


def pick_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", PREFERRED_PORT))
            return PREFERRED_PORT
        except OSError:
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_server(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    mount_frontend()
    port = pick_port()

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", log_config=None)
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

    if not wait_for_server(port):
        raise SystemExit("Backend failed to start.")

    webview.settings["ALLOW_DOWNLOADS"] = True                 # PDF report downloads
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True

    webview.create_window(
        APP_NAME,
        f"http://127.0.0.1:{port}/",  # not "localhost": avoids a ~2s IPv6 (::1) fallback per request
        width=1280,
        height=820,
        min_size=(1000, 640),
        background_color="#0a0d12",
    )
    # private_mode=False keeps localStorage (login session) between launches
    webview.start(private_mode=False, storage_path=os.path.join(os.environ["SECURESCAN_DATA_DIR"], "webview"))
    server.should_exit = True


if __name__ == "__main__":
    main()
