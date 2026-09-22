# Changelog

## v1.4.8
- A little more air between the sidebar's site name and tagline (9px, was 3px).

## v1.4.7
- The sidebar brand is centred: logo above the site name above the tagline.
  A custom logo can be up to 160px wide now that it has the row to itself.

## v1.4.6
- The list view drops its Open column — clicking a row already opens the
  document, and the file is one click away in the document window. The
  Document column takes the freed width.
- The list view's frame casts the same small, neutral shadow as the cards.

## v1.4.5
- Document cards cast a smaller, neutral shadow at rest and on hover; the
  blue-tinted glow is gone.
- Sidebar category highlight and the outer frame of the Cards/List switcher
  use a 10px radius; the switcher's inner pill matches the 7px buttons.

## v1.4.4
- Document and glossary modals may now grow to 1180px wide (was 900px); on
  desktop the document window still fills the viewport height.
- Button corners tightened from 12px to 7px across the interface.

## v1.4.3
- **Full-screen document window on desktop.** Opening a document now fills the
  viewport with a 16px margin, and a PDF preview stretches to use the height
  left under the details rather than stopping at a fixed size.
- **12px corners everywhere.** Every button — including the icon buttons, the
  Cards/List switcher, the modal tools and the lightbox controls — and every
  modal (document, glossary, search palette) now shares a 12px radius.

## v1.4.2
- **Flat page background.** The drifting aurora gradient behind the site is
  gone; the page sits on a plain background with only the faint grain.
- **Softer corners, fewer shadows.** Document cards and the list table use a
  12px radius; the sidebar, the logo tile and icon-button hovers no longer
  cast shadows.
- The page heading sits 12px closer to the top of the content pane.

## v1.4.1
- **Flatter, squarer controls.** Buttons, the Cards/List switcher and the new
  search button use an 8px corner radius and a flat accent fill instead of the
  gradient pill; buttons also gained 2px of vertical padding.
- **Search moved into the page header.** The sidebar's search bar is now a
  search icon next to the Cards/List switcher; it opens the same search
  palette (⌘K / Ctrl+K and `/` still work).
- The site-name eyebrow above the page title is gone, and the document count
  under the heading reads plainly (`12 documents`).

## v1.4.0
- **Part-number search that ignores punctuation.** Searches no longer match the
  text as typed: both the query and every document are folded to bare
  alphanumerics first, so `AB-123/4`, `AB123/4`, `ab 1234` and `AB 123 4` all
  find each other — whichever way the number is written in the document and
  whichever way it is typed into the search box. Dashes, slashes, dots and
  spaces inside a part number are all irrelevant.
- **Every term has to land, in any order.** A multi-word query now matches
  documents that contain all of its terms wherever they appear (`caliper
  rebuild` and `rebuild caliper` return the same thing) instead of only exact
  substrings of the query.
- **Results come back in relevance order.** A document whose associated part
  number *is* the query sorts above one that merely mentions it, and title
  matches outrank matches buried in a description. The list view's column sorts
  still apply on top.
- **Fuzzy fallback.** When a search matches nothing outright, near misses are
  offered instead — a typo, a transposed pair of digits or a misspelling
  (`ab1243` still finds `AB-123/4`, `calliper` finds "Caliper"). Exact matches
  always win; the fuzzy pass only runs when there are none.
- The glossary filter (both the `/api/kb/glossary?q=` endpoint and the in-page
  filter box) folds terms the same way.
- Schema v5 adds two folded search columns to `kb_documents`; they are
  backfilled on upgrade and rebuilt by every sync. No action needed.

## v1.3.1
- The list view's columns are sortable: click **Document**, **Category**, **Vehicle fitment**, **Parts** or **Type** to sort, click again to reverse, and a third click restores the default order. The active column is highlighted with a direction arrow, headers are keyboard-focusable buttons carrying `aria-sort`, and rows with an empty cell always sink to the bottom. The sort applies to whatever the list is showing (a category or search results) and resets on reload.

## v1.3.0

Security release — a full-codebase security review, fixed in one pass. Nothing
user-visible changes on the public site; admins should read the upgrade notes.

**Content from Warehouse Manager is now treated as untrusted on this origin:**
- Document descriptions are sanitized server-side (`nh3` allowlist: basic
  formatting tags, `http(s)`/`mailto` links only) before they reach the API or
  the page, with a second client-side pass as a safety net. A malicious
  description can no longer run script on the site (stored XSS).
- Downloads no longer trust the upstream `mime_type`: the served Content-Type
  comes from a local extension allowlist, `txt` is always `text/plain`, and
  inline SVG previews are sandboxed with a CSP that blocks script and network
  access inside them. Everything outside the allowlist downloads as an
  attachment. Associated-parts links are now also filtered server-side
  (http/https only).
- HTML pages send a baseline Content-Security-Policy (`object-src 'none'`,
  `base-uri 'self'`, `frame-ancestors 'none'`, `form-action 'self'`).

**Auth and API hardening:**
- Mutating admin/auth/setup API calls require a same-origin `Origin`/`Referer`
  header (CSRF guard); cross-origin requests get a 403.
- Per-IP rate limits: 10/min on login, 5/hour on setup, 60/min on the public
  KB API. Search queries are capped at 120 chars and results at 500 rows.
- Account lockout now escalates (1 → 5 → 15 min, reset daily) instead of a
  flat 15 minutes, so a stranger hammering the login can't lock the real admin
  out indefinitely — the IP rate limit is the primary brake.
- Changing a password invalidates every other active session and remember-me
  cookie for that user (the session you changed it from stays signed in).
  **Upgrade note: all admins are signed out once after this upgrade.**
- Failed logins, lockouts, setting changes, uploads and user changes are
  written to the app log as structured `AUDIT` lines.

**Deployment hardening:**
- The Warehouse Manager base URL must now be `https://` and non-loopback.
  **Upgrade note:** if your WM runs on plain http or localhost (LAN/internal
  setups), set `WMKB_ALLOW_INTERNAL_WM=1` or the sync will refuse to run. The
  WM client also no longer follows redirects, so the API key can't be bounced
  to another host.
- `X-Forwarded-*` trust is now opt-in via `WMKB_BEHIND_PROXY` (the compose
  files set it to `1`, matching the documented reverse-proxy deployment).
  Without it, anyone could spoof the host/proto in canonical URLs and the
  sitemap when the port was exposed directly.
- The container runs as an unprivileged `wmkb` user (existing data volumes are
  fixed up automatically on first start).
- Dependencies are pinned with hashes (`requirements.txt` compiled from
  `requirements.in`) and audited weekly in CI (`pip-audit`).
- The dev server only enables the Werkzeug debugger with `FLASK_DEBUG=1`, and
  then binds to localhost only.
- Smaller fixes: scheme-relative `//host` URLs rejected in nav/footer links,
  manual sync can no longer overlap the sync daemon (file lock, 409 when
  busy), SVG branding uploads parsed with `defusedxml` plus a 2 MB cap, ICO
  uploads verified by magic bytes, `/admin` and `/api/admin` responses sent
  with `noindex`/`no-store`, and the SQLite file is created `0600`.

## v1.2.3
- The backdrop behind the search window (⌘K / Ctrl K) no longer blurs the page — it's the same plain darkened overlay the document window uses.

## v1.2.2
- A document URL with a trailing slash (`/category/document/`) no longer 404s — it permanently redirects to the canonical form without the slash. Category pages already accepted both forms.

## v1.2.1
- Public URLs dropped the `/kb/` prefix: categories now live at `/<category>` and documents at `/<category>/<document>`. Every previously published `/kb/...` link keeps working via a permanent redirect, and the numeric short link `/kb/<id>` plus the file endpoints (`/kb/<id>/download`, `/kb/<id>/featured`) are unchanged. Root-level names the app itself uses (`admin`, `api`, `kb`, `static`, `branding`, …) are reserved so a category slug can never collide with them. The sitemap, canonical tags, breadcrumbs and share links all use the new addresses.

## v1.2.0
- **The glossary now syncs from Warehouse Manager** (requires WM v1.7.5, which adds `GET /api/external/kb/glossary` to the external KB API). Terms mirror into a local `kb_glossary` table (migration v3) on every sync run — full replace, so edits, deletions and the WM glossary sub-module toggle all propagate. Older Warehouse Manager versions without the endpoint are detected (404) and simply leave the mirror untouched.
- The public site shows the synced glossary: a **Glossary** entry appears in the sidebar under "Reference" (only when terms exist), opening a window with the terms grouped by letter and a filter box that searches terms and definitions. Served at `/api/kb/glossary`.

## v1.1.8
- Lightbox zoom is now a single click: click zooms in at that point, click again zooms back out (was double-click). Dragging to pan never triggers the zoom toggle.

## v1.1.7
- The image lightbox can now zoom: + / − buttons in the top-right corner, the scroll wheel (zooming toward the cursor), the + / − keys, or double-click to jump between fitted and 2.5×. When zoomed in, the image can be dragged to pan; switching image or reopening resets the view.

## v1.1.6
- The dark backdrop behind the document window no longer blurs the page — it's a plain darkened overlay now.
- Images in the document window (the featured image and image-type documents) show as a grid of thumbnails instead of full-width, with a full-screen lightbox on click — arrow keys / on-screen arrows move between images, Esc or a click outside closes. PDFs keep their inline preview.

## v1.1.5
- Uploading an admin logo no longer hides the Admin Area Name in the admin sidebar. The logo now replaces only the letter-mark tile, with the name and "Admin" label always shown beside it (logo capped at 64px wide so the name keeps its room).

## v1.1.4
- On phones, the logo and site name now sit at the top of the page itself — centered on the same line as the menu button — instead of inside the slide-out sidebar, so the branding is visible without opening the menu. The tagline stays in the sidebar, above the search box. The site-name eyebrow above the category heading is hidden on phones — the brand line right above it already says the same thing.

## v1.1.3
- In the document window, the featured image no longer sits above the details. The order is now: detail strip (category, fitment, file, size, parts), description, featured image, then the document preview.

## v1.1.2
- Removed the Share button (and its drop-down of share targets) from the document window; **Copy link** stays and is the one way to pass a document around.
- Removed the Search button from the page header — it duplicated the sidebar search box. The sidebar box and the ⌘K / Ctrl K shortcut both still open the search window.
- Associated parts now live inside the document window's detail strip alongside Category, Vehicle fitment, File and Size, instead of in their own block underneath — everything factual about the document is now in one place. The part chips are still links.

## v1.1.1
- The search shortcut chip now draws the ⌘ symbol as a bundled icon instead of relying on the visitor's fonts, which rendered it at the wrong size on Windows — and on Windows and Linux it now reads "Ctrl K" instead, matching the keys those visitors actually press (both Ctrl+K and ⌘K have always worked).
- The search window (⌘K) now has a solid background instead of a frosted-glass one, so the page behind it no longer shows through the results.
- Fixed the admin sidebar footer: the account name, version and the settings / theme / sign-out icon buttons were stacked vertically; they now sit in a single row as intended.
- The sidebar header now centers the site name against the logo, with the tagline hanging below the name without pushing it out of line. The desktop sidebar is also slightly wider (286px → 320px) so longer site names fit on a single line. On phones the sidebar still slides in as an overlay and is capped so it never covers the whole screen.

## v1.1.0
- **Every document now has its own readable address**, built from its category and its name: `/kb/instructions-and-guides/of19a-instructions` instead of a `#doc-41` fragment on the home page. Categories are pages too (`/kb/diagrams`), and each one is a real, linkable URL — reload it, bookmark it, or send it to someone and they land on exactly that document.
- Each of those addresses is served with its own `<title>`, description, canonical link, Open Graph / Twitter card and schema.org data, so a shared link previews as the document itself rather than as the site, and search engines index the documents individually. A `/sitemap.xml` lists every category and document, and `/robots.txt` points at it.
- Vehicle fitment now sits in the document window's detail strip next to Category, File and Size instead of in a separate block underneath, so everything factual about the document is in one place. Associated parts stay below as links.
- The document window's actions now sit together in its header: **Download document**, then **Share**, **Copy link** and close. The download button used to be halfway down the body, below the description and fitment chips, so on a long document you had to scroll to reach it. On phones it shrinks to its icon so the title keeps its room.
- Added a **Share** button and a **Copy link** button to the document window. Share opens the device's own share sheet where one exists (phones, Safari, Edge) and otherwise drops down a small menu — Email, X, Facebook, LinkedIn, WhatsApp, Copy link. Copying works on plain-HTTP deployments too, not just HTTPS.
- Document titles and category names in both views are real links now: hover to see where they go, middle-click or ⌘/Ctrl-click to open in a new tab. Clicking normally still opens the document window in place, and the browser's Back button closes it.
- Old `#doc-<id>` links still work — they redirect to the new address. `/kb/<id>` is a permanent short link to any document, and moving a document to another category redirects its old URL instead of breaking it.
- Crawlers and anyone browsing without JavaScript now get a plain list of documents (and the document's own text) at every URL instead of a blank page.

## v1.0.3
- The public site now opens in **list view** by default instead of cards. A visitor who picks a view still keeps their own choice, and simply loading the page no longer counts as picking one — previously the first page load saved the current default as a preference, so a later change to the default would never have reached anyone.
- `/admin/` with a trailing slash used to 404 instead of opening the admin, which read as "this app has no admin". It now works, as do `/admin/login/`, `/admin/setup/` and `/admin/logout/`.

## v1.0.2
- List view no longer clips its right-hand columns on narrower desktop windows. The table used automatic column sizing, so the chip columns (vehicle fitment, parts) claimed width first and squeezed the Document column down until titles stacked over three lines — and past a certain width the Type and Open columns were cut off entirely by the container's `overflow: hidden`, with the horizontal scrollbar stranded at the bottom of a 90-row table where nobody would find it. Columns now hold deliberate proportions, and the low-value chip columns drop out as the window narrows (below 1200px Parts goes, below 1000px Vehicle fitment, below 640px Category) rather than everything scrolling sideways. Nothing is lost — both are still shown in the document window. Phones get tighter cells and a smaller thumbnail so the table fits without sideways scrolling at all.

## v1.0.1
- Document modal is now a solid panel instead of a translucent, blurred one — the page behind it no longer shows through the detail view.
- The modal's scrollbar is confined to the body content; the title/close header is a fixed row that no longer sits inside the scroll area.
- The public stylesheet is requested with a version query string so a released CSS change reaches browsers without a hard refresh.

## v1.0.0
- Initial release. Public-facing Knowledge Base frontend and companion to Warehouse Manager.
- Syncs the KB category tree, documents, files and featured images from Warehouse Manager over the secure, API-key-authenticated external KB API into a local SQLite mirror + file cache. Manual "Sync now" plus a scheduled background sync that runs in its own process.
- Modern, elegant public site: sidebar category tree, centralized live search, document cards with featured-image thumbnails, and a detail view with inline PDF/image preview and download. Light and dark themes.
- Separate admin area at `/admin` with its own secure login (Flask-Login, pbkdf2, account lockout), first-run setup wizard, and a tabbed Settings modal (Connection, Sync, Branding, Security, Users, About).
- Optional Cloudflare Turnstile challenge on the admin login.
- Full branding for both the public frontend and the admin backend: custom logos, names, tagline, favicon, Apple touch icon, Open Graph image + description. SVG uploads are server-side sanitized.
