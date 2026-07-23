# Changelog

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
