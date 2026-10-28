# LAN File Transfer

A tiny FastAPI app that turns a folder on your PC into a drop box any device on the same Wi-Fi/LAN can reach through a browser. Upload from your phone, download on your PC (or the other way around).

## Features

- Password-protected: login page, 30-day session cookie, logout button
- Brute-force protection: 5 wrong passwords locks that device out for 5 minutes
- Upload multiple files at once from any device with a browser
- Create folders and browse into them (breadcrumb navigation)
- Download files, delete files and empty folders
- Duplicate filenames are auto-renamed (`photo.jpg` → `photo (1).jpg`) instead of overwritten
- Path traversal protection on every path-taking route
- Prints your LAN address on startup

## Requirements

- Python 3.9+
- Dependencies in `requirements.txt`: `fastapi`, `uvicorn[standard]`, `python-multipart`, `itsdangerous`

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

On first run it asks you to choose a password (min 8 characters). Only a salted hash is stored, in `auth.json`.

The server starts on port `8000` and prints something like:

```
==================================================
 LAN File Transfer Server
 Storage folder: /path/to/storage
 On this PC:     http://127.0.0.1:8000
 On your phone:  http://192.168.1.42:8000  (same Wi-Fi)
==================================================
```

Open the "On your phone" URL in a browser on any device connected to the same network, then log in.

To change the password (this also logs out every device):

```bash
python app.py --set-password
```

## Usage

| Action        | How                                                              |
|---------------|------------------------------------------------------------------|
| Upload        | Pick one or more files (hold Ctrl/Shift, or multi-select on a phone) and click Upload; they go into the folder you're viewing |
| New folder    | Type a name and click Create (created inside the current folder) |
| Open a folder | Click it; use the breadcrumb at the top to go back up            |
| Download      | Click a filename                                                 |
| Delete        | Click Delete and confirm. Folders must be empty first            |

Everything lives in the `storage/` folder next to `app.py` (created automatically). You can also drop files and folders into it directly.

## Routes

`path` is always relative to `storage/` (empty = root).

| Method | Path        | Auth | Description                                    |
|--------|-------------|------|------------------------------------------------|
| GET    | `/login`    | No   | Login page                                     |
| POST   | `/login`    | No   | Submit password                                |
| POST   | `/logout`   | No   | End session                                    |
| GET    | `/?path=`   | Yes  | Browse a folder (list, upload and new-folder forms) |
| POST   | `/upload`   | Yes  | Upload one or more files (`files`) into `path` |
| POST   | `/mkdir`    | Yes  | Create folder `name` inside `path`             |
| GET    | `/download?path=` | Yes | Download a file                          |
| POST   | `/delete`   | Yes  | Delete the file or empty folder at `path`      |

Unauthenticated requests to protected routes redirect to `/login`. The auto-generated `/docs` pages are disabled.

## Project Structure

```
.
├── app.py             # The whole app
├── requirements.txt
├── README.md
├── .gitignore
├── auth.json          # Password hash + session key (auto-created, keep private)
└── storage/           # Uploaded files (auto-created)
```

## Troubleshooting

- **Phone can't connect:** make sure both devices are on the same network, and allow Python/port 8000 through your PC's firewall.
- **Wrong IP shown:** the startup banner guesses your LAN IP; check it with `ipconfig` (Windows) or `ip addr` / `ifconfig` (Linux/macOS).
- **Forgot password:** delete `auth.json` and restart, or run `python app.py --set-password`.
- **Guest Wi-Fi:** many guest networks isolate devices from each other, which blocks access.

## Security Notes

- Access requires a single shared password; guest devices without it can't see or download anything.
- Traffic is **plain HTTP**, so someone actively sniffing your Wi-Fi could capture the password or session cookie. Fine for keeping casual guests out; don't expose this to the internet.
- Don't commit `auth.json` (it's in `.gitignore`).
