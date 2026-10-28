"""
LAN File Transfer Server
=========================

A tiny FastAPI app that turns a folder on your PC (./storage/) into a
drop box any device on the same Wi-Fi/LAN can reach through a browser.
Protected by a single shared password.

Run:
    python -m venv venv
    source venv/bin/activate      # Windows: venv\\Scripts\\activate
    pip install -r requirements.txt
    python app.py

First run asks you to choose a password. To change it later:
    python app.py --set-password

Then, on your phone (connected to the same Wi-Fi), open:
    http://<your-pc-lan-ip>:8000
"""

import asyncio
import getpass
import hashlib
import hmac
import html
import json
import os
import secrets
import shutil
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(exist_ok=True)

AUTH_FILE = BASE_DIR / "auth.json"
SESSION_DAYS = 30
MAX_FAILS = 5            # wrong passwords allowed per IP...
LOCKOUT_SECONDS = 300    # ...before that IP is locked out for this long


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------

def hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def set_password() -> dict:
    """Prompt for a password and save its hash (never the password itself).

    Also generates a fresh session-signing key, so changing the password
    logs out every device.
    """
    while True:
        pw = getpass.getpass("Choose a password (min 8 characters): ")
        if len(pw) < 8:
            print("Too short, try again.")
            continue
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords don't match, try again.")
            continue
        break

    salt = secrets.token_bytes(16)
    data = {
        "salt": salt.hex(),
        "hash": hash_password(pw, salt).hex(),
        "secret_key": secrets.token_hex(32),
    }
    AUTH_FILE.write_text(json.dumps(data))
    try:
        os.chmod(AUTH_FILE, 0o600)  # owner-only (no-op on Windows)
    except OSError:
        pass
    return data


def load_auth() -> dict:
    if AUTH_FILE.exists():
        return json.loads(AUTH_FILE.read_text())
    if not sys.stdin.isatty():
        raise RuntimeError(
            "No password set. Run 'python app.py' in a terminal to create one."
        )
    print("First run: set a password for the site.")
    return set_password()


def verify_password(password: str) -> bool:
    salt = bytes.fromhex(AUTH["salt"])
    expected = bytes.fromhex(AUTH["hash"])
    return hmac.compare_digest(hash_password(password, salt), expected)


# Simple in-memory brute-force protection, tracked per client IP.
_fails: dict[str, list] = {}  # ip -> [failure_count, locked_until_timestamp]


def lockout_remaining(ip: str) -> int:
    entry = _fails.get(ip)
    if entry and entry[1] > time.time():
        return int(entry[1] - time.time()) + 1
    return 0


def register_failure(ip: str) -> None:
    entry = _fails.setdefault(ip, [0, 0.0])
    entry[0] += 1
    if entry[0] >= MAX_FAILS:
        entry[0] = 0
        entry[1] = time.time() + LOCKOUT_SECONDS


class NotAuthenticated(Exception):
    pass


def require_login(request: Request) -> None:
    if not request.session.get("auth"):
        raise NotAuthenticated()


# `python app.py --set-password` just changes the password and exits.
if __name__ == "__main__" and "--set-password" in sys.argv:
    set_password()
    print("Password updated. All devices will need to log in again.")
    sys.exit(0)

AUTH = load_auth()

# docs/openapi are disabled: they'd otherwise be reachable without logging in.
app = FastAPI(title="LAN File Transfer", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    SessionMiddleware,
    secret_key=AUTH["secret_key"],
    session_cookie="lan_session",
    max_age=SESSION_DAYS * 24 * 3600,
    same_site="lax",
    https_only=False,  # plain HTTP on the LAN
)

# Every route on this router requires a login.
protected = APIRouter(dependencies=[Depends(require_login)])


@app.exception_handler(NotAuthenticated)
async def redirect_to_login(request: Request, exc: NotAuthenticated):
    return RedirectResponse(url="/login", status_code=303)


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


def resolve_in_storage(rel: str) -> Path:
    """
    Resolve a user-supplied relative path ('' = storage root) to an absolute
    path strictly inside STORAGE_DIR, preventing path traversal
    (e.g. '../../etc/passwd') and symlink escapes.
    """
    root = STORAGE_DIR.resolve()
    resolved = (root / rel).resolve()
    if not resolved.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Invalid path")
    return resolved


def rel_path(p: Path) -> str:
    """Path inside storage as a forward-slash string ('' for the root)."""
    root = STORAGE_DIR.resolve()
    return "" if p == root else p.relative_to(root).as_posix()


def clean_filename(name: str) -> str:
    """Strip any directory part from an uploaded filename ('' if unusable)."""
    name = Path((name or "").replace("\\", "/")).name
    return "" if name in (".", "..") else name


def valid_folder_name(name: str) -> bool:
    return (
        bool(name)
        and name not in (".", "..")
        and len(name) <= 255
        and not any(c in name for c in '/\\<>:"|?*\0')
    )


def unique_dest(directory: Path, name: str) -> Path:
    """Return directory/name, or 'name (1).ext', 'name (2).ext'... if taken."""
    dest = directory / name
    stem, suffix = dest.stem, dest.suffix
    counter = 1
    while dest.exists():
        dest = directory / f"{stem} ({counter}){suffix}"
        counter += 1
    return dest


def browse_url(rel: str, msg: str = "") -> str:
    params = {}
    if rel:
        params["path"] = rel
    if msg:
        params["msg"] = msg
    return "/" + ("?" + urlencode(params) if params else "")


def back(rel: str, msg: str = "") -> RedirectResponse:
    """Redirect to a folder view, optionally with a one-line status message."""
    return RedirectResponse(url=browse_url(rel, msg), status_code=303)


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


def login_body(error: str = "") -> str:
    err = f'<p style="color:red">{html.escape(error)}</p>' if error else ""
    return f"""
    <h2>Log in</h2>
    {err}
    <form action="/login" method="post">
        <input type="password" name="password" placeholder="Password" autofocus required>
        <button type="submit">Log in</button>
    </form>"""


# ---------------------------------------------------------------------------
# Public routes (login / logout)
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if request.session.get("auth"):
        return RedirectResponse(url="/", status_code=303)
    return page(login_body())


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "unknown"

    wait = lockout_remaining(ip)
    if wait:
        return HTMLResponse(
            page(login_body(f"Too many failed attempts. Try again in {wait}s.")),
            status_code=429,
        )

    if verify_password(password):
        _fails.pop(ip, None)
        request.session.clear()
        request.session["auth"] = True
        return RedirectResponse(url="/", status_code=303)

    register_failure(ip)
    await asyncio.sleep(1)  # slow down guessing
    return HTMLResponse(page(login_body("Wrong password.")), status_code=401)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


# ---------------------------------------------------------------------------
# Protected routes
# ---------------------------------------------------------------------------

@protected.get("/", response_class=HTMLResponse)
def index(path: str = "", msg: str = ""):
    current = resolve_in_storage(path)
    if not current.is_dir():
        raise HTTPException(status_code=404, detail="Folder not found")
    rel = rel_path(current)

    # Folders first, then files, each A-Z.
    entries = sorted(
        (p for p in current.iterdir() if p.is_dir() or p.is_file()),
        key=lambda p: (not p.is_dir(), p.name.lower()),
    )

    # Breadcrumb: Home / folder / subfolder
    crumbs = [f'<a href="{browse_url("")}">Home</a>']
    acc = ""
    for part in rel.split("/") if rel else []:
        acc = f"{acc}/{part}" if acc else part
        crumbs.append(f'<a href="{html.escape(browse_url(acc))}">{html.escape(part)}</a>')
    breadcrumb = " / ".join(crumbs)

    if entries:
        rows = []
        for p in entries:
            child = f"{rel}/{p.name}" if rel else p.name
            name = html.escape(p.name)
            if p.is_dir():
                href = html.escape(browse_url(child))
                link = f'<a href="{href}">&#128193; {name}</a>'
                size = "&mdash;"
                question = f"Delete empty folder {p.name}?"
            else:
                href = html.escape("/download?" + urlencode({"path": child}))
                link = f'<a href="{href}">{name}</a>'
                size = human_size(p.stat().st_size)
                question = f"Delete {p.name}?"
            confirm_js = html.escape(json.dumps(question))
            rows.append(f"""
        <tr>
            <td>{link}</td>
            <td>{size}</td>
            <td>
                <form action="/delete" method="post"
                      onsubmit="return confirm({confirm_js});">
                    <input type="hidden" name="path" value="{html.escape(child)}">
                    <button type="submit">Delete</button>
                </form>
            </td>
        </tr>""")
        listing = f"""
    <table border="1" cellpadding="6" cellspacing="0">
        <tr><th>Name</th><th>Size</th><th></th></tr>
        {''.join(rows)}
    </table>"""
    else:
        listing = "<p>This folder is empty.</p>"

    note = f"<p><em>{html.escape(msg)}</em></p>" if msg else ""
    hidden_path = f'<input type="hidden" name="path" value="{html.escape(rel)}">'

    body = f"""
    <form action="/logout" method="post">
        <button type="submit">Log out</button>
    </form>

    <p>{breadcrumb}</p>
    {note}

    <h2>Upload files</h2>
    <form action="/upload" method="post" enctype="multipart/form-data">
        {hidden_path}
        <input type="file" name="files" multiple required>
        <button type="submit">Upload</button>
    </form>

    <h2>New folder</h2>
    <form action="/mkdir" method="post">
        {hidden_path}
        <input type="text" name="name" placeholder="Folder name" required>
        <button type="submit">Create</button>
    </form>

    <h2>Contents</h2>
    {listing}
    """
    return page(body)


@protected.post("/upload")
def upload(path: str = Form(""), files: list[UploadFile] = File(...)):
    # Plain `def` (not async): FastAPI runs it in a worker thread, so big
    # uploads don't block other requests.
    current = resolve_in_storage(path)
    if not current.is_dir():
        raise HTTPException(status_code=404, detail="Folder not found")

    saved = 0
    for f in files:
        name = clean_filename(f.filename)
        if not name:
            continue
        with unique_dest(current, name).open("wb") as out_file:
            shutil.copyfileobj(f.file, out_file)
        saved += 1

    rel = rel_path(current)
    if not saved:
        return back(rel, "No files were uploaded.")
    return back(rel, f"Uploaded {saved} file{'s' if saved != 1 else ''}.")


@protected.post("/mkdir")
def mkdir(path: str = Form(""), name: str = Form(...)):
    current = resolve_in_storage(path)
    if not current.is_dir():
        raise HTTPException(status_code=404, detail="Folder not found")

    rel = rel_path(current)
    name = name.strip()
    if not valid_folder_name(name):
        return back(rel, "Invalid folder name.")

    target = current / name
    if target.exists():
        return back(rel, f"'{name}' already exists.")
    target.mkdir()
    return back(rel, f"Created folder '{name}'.")


@protected.get("/download")
def download(path: str):
    target = resolve_in_storage(path)
    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(target, filename=target.name)


@protected.post("/delete")
def delete(path: str = Form(...)):
    target = resolve_in_storage(path)
    if target == STORAGE_DIR.resolve():
        raise HTTPException(status_code=400, detail="Can't delete the storage root")
    parent = rel_path(target.parent)

    if target.is_file():
        target.unlink()
        return back(parent, f"Deleted {target.name}.")
    if target.is_dir():
        try:
            target.rmdir()  # only succeeds on empty folders
        except OSError:
            return back(parent, "Folder isn't empty. Delete its contents first.")
        return back(parent, f"Deleted folder {target.name}.")
    raise HTTPException(status_code=404, detail="Not found")


app.include_router(protected)


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
    print(" Change password: python app.py --set-password")
    print("=" * 50)

    uvicorn.run(app, host="0.0.0.0", port=8000)
