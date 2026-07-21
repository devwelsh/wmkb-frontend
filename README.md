# WMKB Frontend

A modern, public-facing **Knowledge Base** website and companion to
[Warehouse Manager](../warehouse-manager). It surfaces your product instruction
sheets, guides, diagrams, images and documents to the public with an elegant
sidebar layout, centralized live search, and light/dark themes — while a
separate admin area at `/admin` controls the secure connection to Warehouse
Manager and content sync. Branding is set in Warehouse Manager and synced down.

## How it works

```
┌────────────────────┐   X-API-Key (read-only)   ┌──────────────────────────┐
│ Warehouse Manager  │ ◀───────────────────────── │ WMKB Frontend            │
│  (private)         │   /api/external/kb/*       │  wmkb-sync  → local DB    │
└────────────────────┘                            │  wmkb-frontend → public  │
                                                   └──────────────────────────┘
```

The frontend **syncs** the KB category tree, documents and files from Warehouse
Manager into its own SQLite store and file cache, so the public site is fast and
stays up even when Warehouse Manager is unreachable. Sync runs on a schedule (its
own background process) and on demand from the admin dashboard.

## Features

- **Public knowledge base** — sidebar category tree with counts, centralized
  debounced live search, document cards with featured-image thumbnails, and a
  detail view with inline PDF/image preview, vehicle fitment, associated part
  numbers, and download.
- **Light & dark themes** — per-visitor, with the default set in Warehouse
  Manager (which also picks the default card/list view).
- **Secure admin area at `/admin`** — own login (account lockout), first-run
  setup wizard, and a tabbed Settings modal.
- **Secure API connection** — pulls records from Warehouse Manager's external KB
  API using an `X-API-Key` read-only key.
- **Category tree sync** — mirrors the Warehouse Manager KB category tree.
- **Full branding** for the public frontend *and* the admin backend — logos,
  names, tagline, favicon, Apple touch icon, Open Graph image + description,
  custom sidebar/footer links, default theme and default view. All of it is
  edited in Warehouse Manager (Settings → Knowledge Base) and pulled down on
  every sync; SVGs are sanitized before being stored.
- **Optional Cloudflare Turnstile** on the admin login.
- Runs behind a reverse proxy; Docker Compose + Flask + gunicorn.

## Quick start

1. **In Warehouse Manager** (v1.8.0+): Settings → Options → **API Keys** →
   generate a key. Copy it (shown once).

2. **Run this app:**
   ```bash
   cp .env.example .env        # optional: set WMKB_PORT, SECRET_KEY, WMKB_SECURE_COOKIES
   sudo docker compose up -d --build
   ```

3. Open `http://<host>:5070/admin` and complete setup:
   create your admin account → enter the Warehouse Manager URL + API key
   (use **Test**) → **Sync now & finish**.

4. The public site is live at `http://<host>:5070/`. Point your reverse proxy /
   domain at it. Tune the sync interval and set your branding, logos and custom
   sidebar links in **Settings**.

## Configuration

| Env var | Purpose | Default |
|---|---|---|
| `WMKB_PORT` | Host port for the public site | `5070` |
| `SECRET_KEY` | Session signing key (else auto-generated + persisted) | — |
| `WMKB_DATA_DIR` | Data dir for DB, cache, branding | `/data` (container) |
| `WMKB_SECURE_COOKIES` | Set `1` behind HTTPS (Secure cookies + HSTS) | off |

## Services

- `wmkb-frontend` — the web app (gunicorn).
- `wmkb-sync` — the scheduled sync process (same image), the single KB writer.

Both share the `wmkb-data` volume (SQLite + `cache/` + `branding/`).

## License

See [LICENSE](LICENSE).
