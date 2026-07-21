# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

WMKB Frontend is a public-facing Knowledge Base website and companion to
**Warehouse Manager** (`~/warehouse-manager`). It mirrors Warehouse Manager's
Knowledge Base module over a secure, API-key-authenticated read API into its own
SQLite store + file cache, then serves it as a modern, searchable public site
with a separate admin area at `/admin`. It is designed to run behind a reverse
proxy (no TLS/proxy concerns in the app). Visually it is a sibling of Warehouse
Manager — same Inter font and design tokens (light/dark only).

## Commands

```bash
# Dev: web app on :5070  (DB + cache created in repo root when WMKB_DATA_DIR unset)
python3 run.py
# Dev: scheduled sync (separate process), in another terminal
python3 sync.py

# Production via compose (web + sync services, image: viibeware/wmkb-frontend)
sudo docker compose up -d --build
sudo docker compose logs -f
```

Env vars: `WMKB_DATA_DIR` (where `wmkb.db`, `cache/`, `branding/`, `.secret_key`
live — `/data` in the container), `SECRET_KEY` (optional; else persisted to
`.secret_key`), `WMKB_PORT` (host port), `WMKB_SECURE_COOKIES` (set to 1 behind
HTTPS). No test suite or linter.

## Architecture

**Three modules, one image.**
- `app.py` — Flask app: config, SQLite + migrations, settings helpers, auth
  (Flask-Login), the public site routes, and the admin API. Single file by
  design (like Warehouse Manager). `init_db()` runs migrations under an fcntl
  lock (gunicorn-multiworker safe).
- `wm_client.py` — outbound client for Warehouse Manager's `/api/external/kb/*`
  API. Auth is the API key in the `X-API-Key` header (never the URL). Downloads
  stream to a temp file and are atomically renamed into the cache; per-request
  timeout and a hard size cap.
- `sync.py` — the sync engine (`run_sync()`) and a long-lived daemon
  (`python sync.py`). The daemon is the **only scheduler** and runs as its own
  `wmkb-sync` compose service sharing the data volume — there is no in-web-worker
  scheduler election. SQLite WAL lets the web workers read while the sync daemon
  is the single KB writer.

**Sync model.** Full re-sync each run: pull categories + documents, upsert by
`remote_id`, prune anything that vanished upstream (and its cached files), and
(re)download a file only when its `file_sha256` (or, when absent, `file_size`)
changed or the local copy is missing. Network downloads happen **outside** the
DB write transaction.

**Data model (local mirror).** `kb_categories` and `kb_documents` carry a
`remote_id` (the Warehouse Manager id) plus `local_file` / `local_featured`
(cache filenames). `app_settings` is JSON key/value (`wm_connection`,
`sync_config`, `turnstile_config`, `branding`, `setup_complete`). `users` are
admins (Flask-Login, pbkdf2, lockout). `sync_log` records each run.

**Public site (`templates/index.html`).** Vanilla-JS SPA: sidebar category tree,
centralized debounced live search hitting `/api/kb/documents?q=`, cards →
detail view with inline preview/download. `<head>` branding/OG/favicon are
server-rendered by Jinja (crawlers don't run JS). Files are served from the
cache by `remote_id` via `/kb/<id>/download` and `/kb/<id>/featured` (public,
`nosniff`; non-previewable types download as attachments).

**Admin (`/admin`).** `login.html` (optional Turnstile), `setup.html` (first-run
wizard: create admin → connect to Warehouse Manager → finish), `admin.html`
(dashboard + tabbed Settings modal). All settings persist to `app_settings`.

**Branding.** One `branding` setting holds names/tagline/OG text plus five
uploadable assets (`frontend_logo`, `admin_logo`, `favicon`, `apple_touch_icon`,
`og_image`) stored under `branding/` and served via `/branding/<asset>` (public —
the login page and OG tags need them pre-auth). SVGs are sanitized
(`_sanitize_svg`, ported from Warehouse Manager); PNG/JPG are verified via Pillow.
Custom sidebar and footer links live in the `nav_links` / `footer_links` settings
and are edited in the admin's Branding / Navigation tabs.

## Dependency on Warehouse Manager

This app consumes Warehouse Manager's external KB API (added in WM v1.7.0):
`GET /api/external/kb/{categories,documents,documents/<id>,documents/<id>/download,documents/<id>/featured}`,
authenticated with `X-API-Key`. Generate a key in Warehouse Manager →
Settings → Options → API Keys. If that API changes, update `wm_client.py` and the
sync upsert in `sync.py`.

## Conventions

- Bump `APP_VERSION` in `app.py` and add a CHANGELOG entry for user-visible changes.
- Settings live in `app_settings` as JSON via `_get_setting`/`_set_setting`.
- Never echo Warehouse Manager's internal filenames; the public site serves
  everything by `remote_id` from the local cache.
