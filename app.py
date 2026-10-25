"""
LAN File Transfer Server
=========================

A tiny FastAPI app that turns a folder on your PC (./storage/) into a
drop box any device on the same Wi-Fi/LAN can reach through a browser.

Run:
    pip install -r requirements.txt
    python app.py

Then, on your phone (connected to the same Wi-Fi), open:
    http://<your-pc-lan-ip>:8000
"""

import html
import shutil
import socket
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(exist_ok=True)

app = FastAPI(title="LAN File Transfer")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def human_size(num_bytes: int) -> str:
    """Format a byte count as a short human-readable string."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def safe_path(filename: str) -> Path:
    """
    Resolve a user-supplied filename to a path strictly inside STORAGE_DIR,
    preventing path traversal (e.g. '../../etc/passwd').
    """
    # Strip any directory components the client might send.
    candidate = STORAGE_DIR / Path(filename).name
    resolved = candidate.resolve()
    if resolved.parent != STORAGE_DIR.resolve():
        raise HTTPException(status_code=400, detail="Invalid filename")
    return resolved


def local_ip() -> str:
    """Best-effort guess at this machine's LAN IP, for the startup banner."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def page(body: str) -> str:
    """Wrap body HTML in a minimal shared shell (barely any styling)."""
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>LAN File Transfer</title>
</head>
<body>
    <h1>LAN File Transfer</h1>
    {body}
</body>
</html>"""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def index():
    files = sorted(
        (p for p in STORAGE_DIR.iterdir() if p.is_file()),
        key=lambda p: p.name.lower(),
    )

    if files:
        rows = []
        for f in files:
            name = html.escape(f.name)
            size = human_size(f.stat().st_size)
            rows.append(f"""
        <tr>
            <td><a href="/download/{name}">{name}</a></td>
            <td>{size}</td>
            <td>
                <form action="/delete/{name}" method="post"
                      onsubmit="return confirm('Delete {name}?');">
                    <button type="submit">Delete</button>
                </form>
            </td>
        </tr>""")
        file_list = f"""
    <table border="1" cellpadding="6" cellspacing="0">
        <tr><th>File</th><th>Size</th><th></th></tr>
        {''.join(rows)}
    </table>"""
    else:
        file_list = "<p>No files yet.</p>"

    body = f"""
    <h2>Upload a file</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button type="submit">Upload</button>
    </form>

    <h2>Files in storage</h2>
    {file_list}
    """
    return page(body)


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    dest = STORAGE_DIR / Path(file.filename).name

    # Avoid clobbering an existing file with the same name.
    if dest.exists():
        stem, suffix = dest.stem, dest.suffix
        counter = 1
        while dest.exists():
            dest = STORAGE_DIR / f"{stem} ({counter}){suffix}"
            counter += 1

    with dest.open("wb") as out_file:
        shutil.copyfileobj(file.file, out_file)

    return RedirectResponse(url="/", status_code=303)


@app.get("/download/{filename}")
def download(filename: str):
    path = safe_path(filename)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path, filename=path.name)


@app.post("/delete/{filename}")
def delete(filename: str):
    path = safe_path(filename)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    path.unlink()
    return RedirectResponse(url="/", status_code=303)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    ip = local_ip()
    print("=" * 50)
    print(" LAN File Transfer Server")
    print(f" Storage folder: {STORAGE_DIR}")
    print(f" On this PC:     http://127.0.0.1:8000")
    print(f" On your phone:  http://{ip}:8000  (same Wi-Fi)")
    print("=" * 50)

    uvicorn.run(app, host="0.0.0.0", port=8000)
