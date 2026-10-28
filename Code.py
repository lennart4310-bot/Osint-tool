#!/usr/bin/env python3
"""
Handle Hunt - a local username lookup tool with a browser UI.

Run:   python3 handle_hunt.py
Open:  http://127.0.0.1:8765

Optional environment variables:
  PORT          port to listen on (default 8765)
  HOST          bind address (default 127.0.0.1; use 0.0.0.0 when hosting)
  AUTH_USER     } set both to require a login (HTTP basic auth)
  AUTH_PASS     }
  RATE_LIMIT    max checks per minute per visitor (default 120)
  TRUST_PROXY   set to 1 behind a reverse proxy so visitor IPs are read
                from X-Forwarded-For

No dependencies (standard library only). Binds to localhost by default.
Checks whether a username/handle has a public profile on selected sites.
Use it on your own handles, for security research on accounts you are
authorised to investigate, or for brand/impersonation checks.
"""
import base64, collections, json, os, re, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# kind: status      -> 200 = found, 404 = not found
#       text_absent -> 200 but body contains `absent` = not found
#       json_empty  -> body is [] / null / {} = not found
# Sites with kind "link" have no reliable public lookup (login walls,
# bot protection), so the tool builds a search link to open manually.
SITES = [
    {"id": "github",   "name": "GitHub",     "cat": "Dev",      "kind": "status",
     "check": "https://api.github.com/users/{u}", "profile": "https://github.com/{u}"},
    {"id": "gitlab",   "name": "GitLab",     "cat": "Dev",      "kind": "json_empty",
     "check": "https://gitlab.com/api/v4/users?username={u}", "profile": "https://gitlab.com/{u}"},
    {"id": "codeberg", "name": "Codeberg",   "cat": "Dev",      "kind": "status",
     "check": "https://codeberg.org/{u}", "profile": "https://codeberg.org/{u}"},
    {"id": "devto",    "name": "DEV",        "cat": "Dev",      "kind": "status",
     "check": "https://dev.to/api/users/by_username?url={u}", "profile": "https://dev.to/{u}"},
    {"id": "hn",       "name": "Hacker News","cat": "Dev",      "kind": "json_empty",
     "check": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "profile": "https://news.ycombinator.com/user?id={u}"},
    {"id": "docker",   "name": "Docker Hub", "cat": "Dev",      "kind": "status",
     "check": "https://hub.docker.com/v2/users/{u}/", "profile": "https://hub.docker.com/u/{u}"},
    {"id": "keybase",  "name": "Keybase",    "cat": "Dev",      "kind": "text_absent", "absent": "[null]",
     "check": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "profile": "https://keybase.io/{u}"},
    {"id": "replit",   "name": "Replit",     "cat": "Dev",      "kind": "status",
     "check": "https://replit.com/@{u}", "profile": "https://replit.com/@{u}"},

    {"id": "minecraft","name": "Minecraft",  "cat": "Gaming",   "kind": "status",
     "check": "https://api.mojang.com/users/profiles/minecraft/{u}", "profile": "https://namemc.com/profile/{u}"},
    {"id": "steam",    "name": "Steam",      "cat": "Gaming",   "kind": "text_absent",
     "absent": "The specified profile could not be found",
     "check": "https://steamcommunity.com/id/{u}", "profile": "https://steamcommunity.com/id/{u}"},
    {"id": "chesscom", "name": "Chess.com",  "cat": "Gaming",   "kind": "status",
     "check": "https://api.chess.com/pub/player/{u}", "profile": "https://www.chess.com/member/{u}"},
    {"id": "lichess",  "name": "Lichess",    "cat": "Gaming",   "kind": "status",
     "check": "https://lichess.org/api/user/{u}", "profile": "https://lichess.org/@/{u}"},
    {"id": "fortnite", "name": "Fortnite",   "cat": "Gaming",   "kind": "link",
     "note": "Epic names have no public lookup. Opens a stats-tracker search.",
     "profile": "https://fortnitetracker.com/profile/all/{u}"},
    {"id": "discord",  "name": "Discord",    "cat": "Gaming",   "kind": "link",
     "note": "Discord has no public username lookup. Opens a Google search for the handle.",
     "profile": "https://www.google.com/search?q=%22{u}%22+discord"},

    {"id": "reddit",   "name": "Reddit",     "cat": "Social",   "kind": "status",
     "check": "https://www.reddit.com/user/{u}/about.json", "profile": "https://www.reddit.com/user/{u}"},
    {"id": "instagram","name": "Instagram",  "cat": "Social",   "kind": "link",
     "note": "Login wall blocks automated checks. Opens the profile URL.",
     "profile": "https://www.instagram.com/{u}/"},
    {"id": "tiktok",   "name": "TikTok",     "cat": "Social",   "kind": "link",
     "note": "Bot protection blocks automated checks. Opens the profile URL.",
     "profile": "https://www.tiktok.com/@{u}"},
    {"id": "x",        "name": "X",          "cat": "Social",   "kind": "link",
     "note": "Login wall blocks automated checks. Opens the profile URL.",
     "profile": "https://x.com/{u}"},

    {"id": "soundcloud","name": "SoundCloud","cat": "Creative", "kind": "status",
     "check": "https://soundcloud.com/{u}", "profile": "https://soundcloud.com/{u}"},
    {"id": "medium",   "name": "Medium",     "cat": "Creative", "kind": "status",
     "check": "https://medium.com/@{u}", "profile": "https://medium.com/@{u}"},
]
BY_ID = {s["id"]: s for s in SITES}
NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,40}$")

AUTH_USER = os.environ.get("AUTH_USER", "")
AUTH_PASS = os.environ.get("AUTH_PASS", "")
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "120"))
TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"
HITS = collections.defaultdict(collections.deque)


def run_check(site, user):
    url = site["check"].format(u=quote(user))
    req = Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    t0 = time.time()
    status, body = None, ""
    try:
        with urlopen(req, timeout=8) as r:
            status = r.status
            body = r.read(200_000).decode("utf-8", "ignore")
    except HTTPError as e:
        status = e.code
    except Exception:
        return {"state": "unknown", "ms": int((time.time() - t0) * 1000), "why": "network error"}
    ms = int((time.time() - t0) * 1000)

    if status == 404:
        return {"state": "missing", "ms": ms}
    if status != 200:
        return {"state": "unknown", "ms": ms, "why": f"HTTP {status}"}

    kind = site["kind"]
    if kind == "text_absent":
        return {"state": "missing" if site["absent"] in body else "found", "ms": ms}
    if kind == "json_empty":
        try:
            data = json.loads(body)
        except ValueError:
            return {"state": "unknown", "ms": ms, "why": "bad response"}
        return {"state": "missing" if not data else "found", "ms": ms}
    return {"state": "found", "ms": ms}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, ctype, payload):
        data = payload if isinstance(payload, bytes) else payload.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
