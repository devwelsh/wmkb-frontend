# Changelog

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
