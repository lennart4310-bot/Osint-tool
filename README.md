# Osint-tool
# Handle Hunt

A username lookup tool with a browser UI. Pick sites, enter a handle (or a
Gmail address, in which case the part before the @ is used), and see where a
public profile exists. Standard library only, no installs.

## Run it

Install Python 3.9 or newer, then:

    python3 handle_hunt.py

Open http://127.0.0.1:8765

## What it checks

- Automatic: GitHub, GitLab, Codeberg, DEV, Hacker News, Docker Hub, Keybase,
  Replit, Minecraft, Steam, Chess.com, Lichess, Reddit, SoundCloud, Medium.
- Manual links: Fortnite, Discord, Instagram, TikTok, X. These have no public
  lookup or block automated requests, so the tool opens a search or profile
  URL for you instead.

To add a site, add one entry to the `SITES` list in `handle_hunt.py`.

## Host it for free

Use a host that runs Python (not GitHub Pages).

- Render: New > Blueprint (reads `render.yaml`). Set AUTH_USER and AUTH_PASS.
- Hugging Face Spaces: create a Docker Space and upload these files. The
  Dockerfile listens on port 7860.

## Settings (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| HOST | 127.0.0.1 | Use 0.0.0.0 when hosting |
| PORT | 8765 | Port to listen on |
| AUTH_USER / AUTH_PASS | off | Require a login when both are set |
| RATE_LIMIT | 120 | Max checks per minute per visitor |
| TRUST_PROXY | off | Set to 1 behind a proxy |

## Responsible use

Use it on handles you own, for brand or impersonation checks, or for research
you are authorised to do. If you host it publicly, keep the login on.

