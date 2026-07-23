# WMKB Frontend

A modern, public-facing **Knowledge Base** website and companion to
[Warehouse Manager](https://github.com/viibeware/warehouse-manager). It surfaces
your product instruction sheets, guides, diagrams, images and documents to the
public with an elegant sidebar layout, centralized live search, and light/dark
themes — while a separate admin area at `/admin` controls the secure connection
to Warehouse Manager, content sync, and all of the site's branding.

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

Nothing is ever written back to Warehouse Manager — the API key it uses is
read-only.

## Features

- **Public knowledge base** — sidebar category tree with counts, centralized
  debounced live search, document cards with featured-image thumbnails, and a
  detail view with inline PDF/image preview, vehicle fitment, associated part
  numbers, and download.
- **Readable, shareable URLs** — every category and document has its own
  address (`/kb/<category>/<document>`) with per-page title, description,
  canonical link, Open Graph/Twitter cards and schema.org data, plus
  `/sitemap.xml` and `/robots.txt`. Share and Copy-link buttons on each
  document; `/kb/<id>` is a permanent short link.
- **Light & dark themes** — per-visitor, chosen from the sidebar. The document
  index opens in list view by default; a visitor's own choice is remembered.
- **Secure admin area at `/admin`** — own login (account lockout), first-run
  setup wizard, and a tabbed Settings modal.
- **Secure API connection** — pulls records from Warehouse Manager's external KB
  API using an `X-API-Key` read-only key.
- **Category tree sync** — mirrors the Warehouse Manager KB category tree.
- **Full branding** for the public frontend *and* the admin backend — logos,
  names, tagline, favicon, Apple touch icon, Open Graph image + description,
  custom sidebar/footer links and default theme, all set in the admin's
  Branding and Navigation tabs. SVG uploads are server-side sanitized.
- **Optional Cloudflare Turnstile** on the admin login.
- Runs behind a reverse proxy; Docker Compose + Flask + gunicorn.

---

# Installation

## What you need first

1. **A host with Docker and the Compose plugin.** Check with:
   ```bash
   docker --version
   docker compose version      # v2 syntax — "docker compose", not "docker-compose"
   ```
2. **A running Warehouse Manager** (v1.7.0 or newer) that this host can reach
   over the network, and an admin account on it.
3. **A read-only API key from Warehouse Manager.** In Warehouse Manager go to
   **Settings → Options → API Keys → Generate**. Copy the key immediately — it
   is shown once and stored hashed, so it cannot be retrieved later. If you lose
   it, generate a new one.
4. Optionally, a domain name and a reverse proxy for TLS. You can install first
   and add the proxy afterwards.

## Option A — install from the published image (recommended)

The image is on Docker Hub as
[`viibeware/wmkb-frontend`](https://hub.docker.com/r/viibeware/wmkb-frontend),
so the server never needs the source or a build step.

### 1. Create a directory for the deployment

Everything the app *stores* lives in a Docker volume, so this directory only
holds two small files: the compose file and your `.env`.

```bash
mkdir -p /opt/wmkb && cd /opt/wmkb
```

### 2. Download the production compose file

```bash
curl -O https://raw.githubusercontent.com/viibeware/wmkb-frontend/main/docker-compose.prod.yml
```

Or create it by hand — this is the whole file:

```yaml
# docker-compose.prod.yml
services:
  wmkb-frontend:
    image: viibeware/wmkb-frontend:latest
    container_name: wmkb-frontend
    restart: unless-stopped
    ports:
      - "${WMKB_PORT:-5070}:5000"
    volumes:
      - wmkb-data:/data
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      - WMKB_DATA_DIR=/data
      - WMKB_SECURE_COOKIES=${WMKB_SECURE_COOKIES:-1}

  # Scheduled sync runs as its own process (no in-web-worker scheduler election).
  # Shares the same image and data volume; it is the single DB writer for KB
  # content while the web workers are readers.
  wmkb-sync:
    image: viibeware/wmkb-frontend:latest
    container_name: wmkb-sync
    restart: unless-stopped
    command: ["python", "sync.py"]
    volumes:
      - wmkb-data:/data
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      - WMKB_DATA_DIR=/data
    depends_on:
      - wmkb-frontend

volumes:
  wmkb-data:
```

Two services sharing one data volume:

| Service | What it does |
|---|---|
| `wmkb-frontend` | The public website + admin area (gunicorn, 2 workers). The only one that publishes a port. |
| `wmkb-sync` | The scheduled sync process. Same image, no port, runs `python sync.py` instead of the web server. |

`${WMKB_PORT:-5070}` and friends are Compose's own substitution syntax: the
value comes from your `.env` (next step), and the part after `:-` is the
fallback when it isn't set. The container always listens on **5000** internally
— `WMKB_PORT` only changes the host side of the mapping. Pin a specific release
instead of `latest` by replacing both `image:` lines with e.g.
`viibeware/wmkb-frontend:1.1.0`.

### 3. Create your `.env`

The compose file reads its settings from a `.env` file **in the same
directory**. Create it:

```bash
cat > .env <<'EOF'
# Host port the public site is exposed on
WMKB_PORT=5070

# Session signing key
SECRET_KEY=

# Set to 1 once you are serving the site over HTTPS
WMKB_SECURE_COOKIES=1
EOF
```

Then generate a secret key and paste it in:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

See [Environment reference](#environment-reference) below for what each setting
does and when to change it.

> **If you are testing over plain `http://` first**, set
> `WMKB_SECURE_COOKIES=0`. With it on, the browser refuses to send the session
> cookie over http and the admin login will appear to silently fail. Switch it
> back to `1` as soon as TLS is in front.

### 4. Start it

```bash
docker compose -f docker-compose.prod.yml up -d
```

Confirm both containers are up, and watch the logs if anything looks wrong:

```bash
docker compose -f docker-compose.prod.yml ps
docker compose -f docker-compose.prod.yml logs -f
```

### 5. Run the first-run setup wizard

Open `http://<host>:5070/admin` in a browser. The wizard has three steps:

1. **Create your admin account.** The password needs at least 10 characters and
   a mix of at least 3 of: lowercase, uppercase, numbers, symbols. This account
   is only for this app — it is unrelated to your Warehouse Manager login.
2. **Connect to Warehouse Manager.** Enter its base URL (e.g.
   `https://wm.example.com`, no trailing path) and the API key from step 3 of
   *What you need first*. Press **Test** — it should report the connection is
   working. If it fails, see [Troubleshooting](#troubleshooting).
3. **Sync now & finish.** The first sync pulls the category tree, every
   document's metadata, its file and its featured image. On a large knowledge
   base this takes a minute or two; subsequent syncs only re-download files
   whose content actually changed.

### 6. Visit the public site

`http://<host>:5070/` is now live. From **Settings** in the admin you can:

- set the site name, tagline, logos, favicon and Open Graph image (**Branding**),
- add custom sidebar and footer links (**Navigation**),
- pick the default theme new visitors see, and change your own password (**General**),
- change the sync interval or run one on demand (**Sync**),
- turn on a Cloudflare Turnstile challenge for the admin login (**Security**),
- add more admin accounts (**Users**).

### 7. Put a reverse proxy in front (for TLS)

The app does not terminate TLS itself. Point your proxy at the port from
`WMKB_PORT` and forward the standard headers — the app trusts exactly one hop of
`X-Forwarded-*`, which is what makes the canonical and Open Graph URLs come out
as your real public https address.

**Caddy** (`/etc/caddy/Caddyfile`) — certificates are automatic:

```
kb.example.com {
    reverse_proxy 127.0.0.1:5070
}
```

**nginx**:

```nginx
server {
    listen 443 ssl;
    server_name kb.example.com;

    # ssl_certificate / ssl_certificate_key from certbot or your CA

    client_max_body_size 16M;   # branding uploads

    location / {
        proxy_pass         http://127.0.0.1:5070;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

With TLS working, make sure `WMKB_SECURE_COOKIES=1` in `.env` and re-run
`docker compose -f docker-compose.prod.yml up -d`.

## Option B — install from source

Use this if you want to modify the app or build the image yourself. The repo's
own `docker-compose.yml` is the same file as above with two changes: each
service gets `build: .` so the image is built from the checkout rather than
pulled, and `WMKB_SECURE_COOKIES` defaults to **off** instead of `1` (dev is
usually plain http). `.env` and the setup wizard work exactly as above.

```bash
git clone https://github.com/viibeware/wmkb-frontend.git
cd wmkb-frontend
cp .env.example .env          # then edit it
docker compose up -d --build
```

To run it without Docker at all (development):

```bash
pip install -r requirements.txt
python3 run.py                # web app on :5070
python3 sync.py               # scheduled sync, in a second terminal
```

Without `WMKB_DATA_DIR` set, the database, cache and branding uploads are
created in the repo directory.

---

## Environment reference

Every setting is optional — the app boots with no `.env` at all — but you will
normally want to set at least `WMKB_PORT` and `WMKB_SECURE_COOKIES`.

| Variable | Purpose | Default | Notes |
|---|---|---|---|
| `WMKB_PORT` | Host port the public site is published on | `5070` | Only the host side; the container always listens on 5000. Change it if 5070 is taken, or set it to `127.0.0.1:5070` style bindings by editing the compose file directly if you want it reachable only via the proxy. |
| `SECRET_KEY` | Signs session cookies | auto-generated | Leave blank and one is generated on first boot and persisted to `/data/.secret_key`, which survives restarts and upgrades. Set it explicitly if you want to control it or rotate it — changing it logs every admin out. |
| `WMKB_SECURE_COOKIES` | Marks cookies `Secure` and sends HSTS | `1` in `docker-compose.prod.yml`, off in `docker-compose.yml` | Turn **on** once you are on https. Leave **off** while testing over plain http, or the admin login will not stick. |
| `WMKB_DATA_DIR` | Where the DB, file cache, branding uploads and secret key live | `/data` in the container | Set by the compose files; do not change it unless you also change the volume mount. |

`.env` is read by Docker Compose, not by the app, so it must sit next to the
compose file you pass to `docker compose -f`. It is in `.gitignore` — never
commit it.

## Upgrading

```bash
cd /opt/wmkb
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

Your data lives in the `wmkb-data` volume, not the image, so it carries over.
Database migrations run automatically on boot, under a lock so multiple gunicorn
workers can't race each other. Check the version you are on in **Settings →
About**, which also shows the changelog.

## Backup and restore

One named volume holds everything: the SQLite database, the synced file cache,
branding uploads and the secret key.

```bash
# Back up to wmkb-data.tar.gz in the current directory
docker run --rm -v wmkb-data:/data -v "$PWD":/backup alpine \
    tar czf /backup/wmkb-data.tar.gz -C /data .

# Restore into a fresh volume
docker run --rm -v wmkb-data:/data -v "$PWD":/backup alpine \
    sh -c "rm -rf /data/* && tar xzf /backup/wmkb-data.tar.gz -C /data"
```

Strictly speaking only the admin accounts and settings are irreplaceable — the
documents themselves can always be re-synced from Warehouse Manager.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| **Test connection fails** in the wizard | The URL is wrong or unreachable *from inside the container* (`localhost` there is the container, not your host — use the LAN IP or the public hostname); the API key was mistyped; or the Knowledge Base module is disabled in Warehouse Manager, which makes its KB API return 403. |
| **Admin login appears to do nothing** | `WMKB_SECURE_COOKIES=1` while browsing over plain http. Set it to `0`, or finish setting up TLS. |
| **`/admin` shows the setup wizard again** | No active admin account exists in the database — usually a fresh or replaced volume. |
| **Documents appear but files or thumbnails 404** | The sync fetched metadata but not the files. Check **Settings → Sync** for the last run's error, then use **Sync now**. |
| **Nothing syncs on schedule** | The `wmkb-sync` container isn't running — it's the only scheduler. `docker compose -f docker-compose.prod.yml ps` should list it as up. |
| **Port already in use** on start | Something else holds `WMKB_PORT`; pick another and re-run `up -d`. |

## Services

- `wmkb-frontend` — the web app (gunicorn).
- `wmkb-sync` — the scheduled sync process (same image), the single KB writer.

Both share the `wmkb-data` volume (SQLite + `cache/` + `branding/`).

## Dependency on Warehouse Manager

This app consumes Warehouse Manager's external KB API, added in Warehouse
Manager **v1.7.0**:
`GET /api/external/kb/{categories,documents,documents/<id>,documents/<id>/download,documents/<id>/featured}`,
authenticated with the `X-API-Key` header. The Knowledge Base module must be
enabled in Warehouse Manager for those endpoints to answer.

## License

See [LICENSE](LICENSE).
