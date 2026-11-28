# Website

The project website is a static site in [`site/`](../site), published with GitHub Pages at
<https://passtunnel.github.io/>. Its main page explains what PassTunnel does, how to install it, the
CLI and MCP setup and the security model; a second page is the step-by-step user guide
(<https://passtunnel.github.io/guide/>), a third holds the privacy policy
(<https://passtunnel.github.io/privacy/>), and the site serves `llms.txt` for tools that read it. The
main page also exists in Turkish (<https://passtunnel.github.io/tr/>, see [Turkish page](#turkish-page)).
Every page describes itself to search engines and other tools with structured data (see
[Structured data and search](#structured-data-and-search)).

This document is the spec for the site: what is on it, the rules it follows and how it is
maintained. The code in `site/` is the source of truth for the exact look.

## Rules

- **Static and self-contained.** Plain HTML, one stylesheet, two small vanilla scripts. No
  framework, no build step, no package manager, no CDN, no web fonts, no trackers, analytics,
  cookies or third-party requests of any kind. Everything a page loads comes from `site/`.
- **Strict Content Security Policy** (meta tag): `default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'`. That means no inline `<script>`, no `style="…"` attributes and no
  `on…=` handlers anywhere; SVG presentation attributes (`fill`, `stroke`, …) are fine. The one
  exception is the structured data block, `<script type="application/ld+json">`: with a type that is
  not JavaScript, the browser treats it as a data block and never runs it, so `script-src` does not
  apply to it and the policy stays as it is.
- **Facts only.** Every claim must match the app (`docs/APP.md`, `docs/ARCHITECTURE.md`,
  `SECURITY.md`). No testimonials, user counts, download numbers, ratings, logos or "trusted by".
  No version numbers either, so the site never goes stale between releases.
- **Generic examples only**: profile names like Work, Lab, Data Center; hosts like
  `vpn.example.com`, `203.0.113.10`.
- **Real app visuals only.** Screenshots come from the app's own renderer (see
  [Images](#images)); the UI is never redrawn with different features. The live code demo is the
  one exception and says on the page that its codes are not real.
- **Light and dark.** Follows `prefers-color-scheme`; a header button overrides it (Auto → Light →
  Dark), saved in `localStorage` (wrapped in try/catch; the page works without it).
- **Accessible**: WCAG 2.1 AA contrast in both themes, visible focus, 44 px targets, keyboard
  operable, meaningful `alt` text, `prefers-reduced-motion` respected (no drifting, pulsing or
  ring animation; the demo still works).
- **Light on the wire**: screenshots are near-lossless WebP (indistinguishable from lossless,
  about 30% smaller) in three widths, 1x, 1.5x and 2x of the displayed size, listed with width
  descriptors and a `sizes` that matches the layout, so every screen downloads only the width it
  needs. Small images (icons) stay lossless with 1x/2x `srcset`. All images have
  real `width`/`height` and `loading="lazy"`, which keeps the theme not shown from downloading
  (a lazy image that is not displayed is never fetched). The hero screenshot gets no fetch
  priority: on phones it is below the fold and would compete with `style.css`. Scripts never force
  a layout at start-up (measure in `requestAnimationFrame` or a `ResizeObserver`). The whole first
  view stays well under 500 KB.
- **Known limits**: `style.css` and `theme.js` block rendering on purpose (the CSP forbids inline
  styles and scripts, and the theme must be set before the first paint), and GitHub Pages caches
  everything for 10 minutes; neither can be changed here.
- **Translatable.** Copy lives in the HTML; the strings scripts show live in `main.js`, one set per
  page language (`<html lang>`), English when a language has none. The main page has a Turkish
  version (see [Turkish page](#turkish-page)); the guide, the privacy policy and the 404 page are
  English only.

## Files

| Path | What |
|---|---|
| `site/index.html` | The main page |
| `site/tr/index.html` | The main page in Turkish (see [Turkish page](#turkish-page)) |
| `site/guide/index.html` | The user guide (see [User guide](#user-guide)) |
| `site/privacy/index.html` | The privacy policy (see [Privacy policy](#privacy-policy)) |
| `site/assets/style.css` | All styles; design tokens as custom properties on `:root` |
| `site/assets/theme.js` | Loaded in `<head>` before the stylesheet paints: applies the saved theme (no flash) |
| `site/assets/main.js` | Theme button, mobile menu, copy buttons, format picker, live code demo (strings in English and Turkish) |
| `site/assets/img/` | Generated images (do not edit by hand) |
| `site/llms.txt` | Plain-text summary for language-model tools: what it is, install, CLI, MCP setup, links (including the FAQ) |
| `site/404.html`, `site/robots.txt`, `site/sitemap.xml` | The usual (the sitemap lists every indexable page with its `lastmod`, and both main pages with their `xhtml:link` language alternates) |
| `scripts/site-assets.sh` | Regenerates everything in `site/assets/img/` |
| `scripts/site/og.html` | Source of the social preview image (not published) |
| `scripts/check-site.sh` | Static checks run by CI (see [Checks](#checks)) |
| `.github/workflows/site.yml` | Hands a new `site/` on `main` to the deploying repository (see [Preview and deploy](#preview-and-deploy)) |

## Look

Calm and mostly monochrome: lots of white (pure black in dark mode), generous whitespace, large
and tight system-font headings (weight 500, negative tracking), black pill buttons (white in dark
mode), soft rounded cards with 1 px borders instead of heavy shadows. The only color is a soft
green–blue–indigo glow behind the hero and the final call to action, and the green/amber state
colors (connected, waiting) that the app itself uses. Monospace only for code, commands and
one-time codes.

## Sections

Header (sticky, translucent): app icon + name, section links (the last one, "Guide", opens the user guide), GitHub, theme button, Download.
Every Download button (header, hero, Install, call to action) links straight to the latest disk
image, <https://github.com/PassTunnel/passtunnel/releases/latest/download/PassTunnel.dmg> (every
release also uploads its DMG under that name without the version, see
[RELEASING.md](RELEASING.md)); release notes and the footer's Releases link go to
<https://github.com/PassTunnel/passtunnel/releases/latest>.
Below 900 px the section links move into a menu button (disclosure pattern: `aria-expanded`,
closes on Escape, on outside click and when a link is chosen).

1. **Hero.** Eyebrow "For OpenVPN, FortiGate SSL VPN, Cisco AnyConnect and Palo Alto GlobalProtect on macOS", the tagline as `h1`, one
   sentence of explanation, "Download for Mac" (the latest disk image) and the Homebrew one-liner
   with a copy button (`brew trust passtunnel/tap && brew install --cask passtunnel/tap/passtunnel`).
   The one-liner is focusable and scrolls sideways with a fade at the cut edge; below 640 px it is
   replaced by an "Install with Homebrew" button that jumps to the Install section. Then
   "macOS 13+ · Apple silicon · Free & open source (MIT)" (the Cisco AnyConnect and Palo Alto GlobalProtect requirement of macOS 15.4 is stated where the types are listed: the FAQ, Install and the call to action). Below that, on the glow: the live code
   demo next to the main window screenshot (stacked on narrow screens, demo first).
2. **One-time codes, handled.** Format picker (Append, Prepend, password:code, password,code,
   Custom template, Sent separately) showing what the server receives; Custom template shows the
   `{password}` / `{otp}` placeholders; Sent separately shows the password and the code as two
   fields (OpenVPN static challenge, FortiGate OTP field, the second password field of Cisco AnyConnect and Palo Alto GlobalProtect). Next to it the profile editor
   screenshot (a saved profile with its code and what the server receives). Four cards: authenticator-style window (live codes, countdown ring,
   click to copy, clipboard cleared after 1 minute, codes can be hidden), QR import (scan on screen, drop,
   choose or paste), Touch ID per profile (secrets then encrypted with a Secure Enclave key), auto-type
   shortcut ⌃⌥C.
3. **VPN client.** OpenVPN, FortiGate SSL VPN, Cisco AnyConnect and Palo Alto GlobalProtect with signed `openvpn` / `openfortivpn` /
   `openconnect` bundled.
   Menu bar card: text next to the rendered menu bar panel (profiles with state, code and switch,
   the copy items), light and dark.
   Cards: stays connected (auto-reconnect with backoff, health check, reconnect after wake,
   session limit reminder), several VPNs at once, shareable `.passtunnel` profiles (never contain
   passwords, TOTP secrets or user names), English and Turkish. General settings screenshot.
4. **CLI & MCP.** CLI card (same features, `--json`, stable exit codes, copyable example block:
   `passtunnel connect work`, `passtunnel code work -c`, `passtunnel status --json`). MCP card:
   `passtunnel mcp` works with Claude Code, Claude Desktop, Cursor, VS Code and other MCP clients
   to check status, read logs and diagnose; read-only by default, connecting needs
   `--allow-connect`, Touch ID-protected profiles still ask on the Mac, never hands out passwords,
   secrets or codes; copyable `claude mcp add passtunnel -- passtunnel mcp`; the Claude Desktop
   `.mcpb` bundle from the latest release (double-click).
5. **Security model.** Diagram: PassTunnel.app (Developer ID, notarized, signature-checked
   updates) → XPC → privileged helper (approved once in System Settings, accepts only the signed
   app) → bundled `openvpn` / `openfortivpn` / `openconnect` (signed, sanitized OpenVPN configurations); a text
   equivalent for screen readers. Two cards: login Keychain without iCloud sync; nothing sent
   anywhere except your VPN server (no sudoers rule, no admin password at every connect).
   First-run screenshot (Add your first VPN, with the Install the helper card). Link: "Read the full security model" → SECURITY.md.
   Touch ID/Secure Enclave is covered in section 2 and the FAQ, not repeated here.
6. **Install.** ("macOS 13 or later on Apple silicon (Cisco AnyConnect and Palo Alto GlobalProtect need macOS 15.4)".) Download ("Download the disk image, open it and drag PassTunnel to
   Applications", a "Release notes" link to the latest release, "Download for Mac"), Homebrew (the
   two commands, copyable), build from source (README). The lead points to the user guide.
7. **FAQ** (`<details>`), questions phrased the way people ask them and answers that each read
   correctly when quoted alone. First, open by default, "What is PassTunnel?": the definition (free,
   open-source VPN client for macOS, the four types, TOTP secret in the Keychain, code sent with the
   password on Connect, Apple silicon and macOS 13, CLI and MCP server). Then: free and open source
   (MIT, GitHub, no accounts or tracking, link to the privacy policy), which Macs and macOS versions
   (13 on Apple silicon, 15.4 for Cisco AnyConnect and Palo Alto GlobalProtect, 14 for scanning a QR
   code on screen), which VPN types, how the one-time code is sent (the formats, waiting for a fresh
   code, never twice), does it work without TOTP ("None" or "Ask each time"), where passwords and TOTP
   secrets are stored, why a privileged helper, the command line, the MCP server, install, uninstall
   and where to get help (troubleshooting, `passtunnel diagnose`, issues, the security policy). Most
   answers link to the matching guide section (`class="text-link"`). The VPN types answer names the four types and
   what Cisco AnyConnect does not do (browser/SAML sign-in, host scan, client certificates, RSA SecurID) and
   needs (macOS 15.4), and the same for Palo Alto GlobalProtect (no single sign-on or client
   certificates, the host information report is never sent so access may be limited; macOS 15.4).
   The FAQ is mirrored word for word in the page's `FAQPage` structured data (see below).
8. **Call to action**, then **footer**: GitHub, Releases, Security, Guide, Privacy, License (MIT), Türkçe
   (the Turkish page, `hreflang="tr"`), and
   "PassTunnel is not affiliated with OpenVPN Inc., Fortinet, Cisco or Palo Alto Networks. OpenVPN, FortiGate, Cisco AnyConnect and Palo Alto GlobalProtect
   are trademarks of their respective owners." The privacy page and the 404 page carry the same footer.

## Privacy policy

`site/privacy/index.html`, linked from the footer of every page; both app stores and both mobile
apps link to it ([MOBILE.md](MOBILE.md), phase 0). The same header (section links point to `/#…`) and footer as
the main page, then one readable column (`.doc`): eyebrow "Privacy", `h1`, a one-sentence summary,
"Last updated" with a `<time>`, an "In short" card, and short sections: who publishes PassTunnel,
what the policy covers (the Mac app and CLI, the Android and iPhone apps, described as in
development, and this website), information collected (none), what stays on the device (per
platform), network connections (per platform: the user's VPN servers, the Mac's health check and
*Fetch fingerprint* (FortiGate and Cisco AnyConnect), its clock checks (the FortiGate gateway after a rejected sign-in, Apple's time
server on request), Sparkle update checks to GitHub, the local MCP server), permissions (per
platform), this website, children, changes (the public repository history) and contact (GitHub
issues and the security policy; no email address). Every statement must match `SECURITY.md`,
`docs/APP.md`, `docs/ARCHITECTURE.md` and `docs/MOBILE.md`: a change to what the apps store, send or
ask for updates this page and its date in the same pull request.

## User guide

`site/guide/index.html`, linked from the header ("Guide") and the footer of every page. The same header
(section links point to `/#…`) and footer as the privacy page, then one readable column (`.doc`):
eyebrow "Guide", `h1`, a one-sentence summary and a table of contents (`nav.doc-toc`) that links to every
section. Each section is a `section` with an `id`, so it can be linked directly (`/guide/#helper`).
Short paragraphs, numbered steps (`ol.steps`) and the exact labels the app uses. In order: Install, Approve the
helper, Add a profile (per VPN type), Add the one-time code, Choose how the code is sent, Connect and
disconnect (main window, menu bar panel, copying, hiding and typing codes), Protect a profile with Touch ID,
Stay connected, Share profiles, Command line, Use with AI assistants (MCP), Updates, Troubleshooting and
Uninstall. It reuses the existing screenshots (first run, profile editor, menu bar panel, General settings)
with the same `srcset`/`sizes`/`loading="lazy"` rules as the main page; it has no renders of
its own. Every statement must match `README.md`, `docs/APP.md`, `docs/ARCHITECTURE.md` and `SECURITY.md`; a
step that is not documented there stays out. **An app change that shows in the guide (a label, a menu path,
a setting, a default, a limit) updates the guide in the same pull request.**

## Turkish page

`site/tr/index.html` is the main page in Turkish, at <https://passtunnel.github.io/tr/>, for people who
search or ask in Turkish. It is a translation, not a different page: the same sections in the same
order, the same element ids (so `/tr/#faq` works like `/#faq`), the same images, the same 13 FAQ
items and the same structured data node types.

- **Same change, both pages.** A change to the text of the English main page (`site/index.html`) is
  made to the Turkish page in the same pull request, and the other way round. A change to the
  `main.js` strings updates both sets. `scripts/check-site.sh` fails when the two pages' element ids
  or FAQ item counts differ or their language links do not match; it cannot see a sentence that was
  changed on one page only, so the review has to.
- **Words.** Natural, concise Turkish in the same voice as the English page, not a word-for-word
  copy. Names of app UI elements (buttons, settings, menu paths, the code formats) are the app's own
  Turkish strings from `Sources/PassTunnel/Resources/Localizable.xcstrings`, so the page matches what a
  Turkish Mac shows (for example **Bağlan**, **Ayarlar → Genel → Diğer → Komut satırı aracı**,
  **Yardımcıyı Kaldır…**, **Her seferinde sor**, *parola:kod*); macOS's own places use Apple's Turkish
  names (Sistem Ayarları → Genel → Giriş Öğeleri, Anahtar Zinciri, Uygulamalar klasörü), as the app's
  strings do. Product and protocol names, commands and code stay as they are. "Yapay zekâ asistanları"
  appears only in the MCP card and the MCP answer, like "AI assistants" on the English page. The
  screenshots stay the English renders; their `alt` text describes them in Turkish, with the app's
  Turkish names for what they show.
- **Links to English pages.** The guide and the privacy policy are English only. Every link to them
  from the Turkish page carries `hreflang="en"` and says so in its text ("Kılavuz (İngilizce)",
  "İngilizce kullanım kılavuzu"); GitHub pages (README, SECURITY.md) are named as English where the
  text points to them. Paths are absolute (`/assets/…`, `/guide/…`), since the page lives one folder
  down.
- **Language links.** Both main pages carry `<link rel="alternate" hreflang="en">`,
  `hreflang="tr"` and `hreflang="x-default"` (the English page), `og:locale` with
  `og:locale:alternate`, and a footer link to the other language ("Türkçe" / "English", with `lang`
  and `hreflang`). `sitemap.xml` lists both with the same `xhtml:link` alternates. In the structured
  data the English `FAQPage` names the Turkish one as `workTranslation`, and the Turkish one names the
  English one as `translationOfWork`; both pages share the `Organization`, `WebSite`,
  `SoftwareApplication` and `SoftwareSourceCode` `@id`s, each describing them in its own language.
- **Social image.** The Turkish page uses the shared English `og.png`.

## Structured data and search

What search engines and other tools read besides the visible text. All of it says only what the
pages already say: no ratings, reviews, user counts, prices other than free, or version numbers.

The markup is not there for Google's rich results, and none are expected from it: Google shows FAQ
rich results only for a few authoritative government and health sites (since 2023), no longer shows
HowTo rich results at all, and wants ratings or reviews (which this site does not have and will not
invent) before it shows a `SoftwareApplication` result. It is there for the other consumers of
structured data, such as other search engines and tools that read a page's JSON-LD to understand
what the product is, what it needs and what its FAQ answers. The guide keeps its `HowTo` nodes for
the same reason.

- **Titles and descriptions** name the category in the words people search with (macOS VPN client,
  TOTP, OpenVPN, FortiGate SSL VPN, Cisco AnyConnect, GlobalProtect) and stay natural: a title of
  about 60 characters, a description of about 155. The `og:` and `twitter:` copies are the same text.
  - Home: "PassTunnel: macOS VPN client that fills in your TOTP code".
  - Turkish home: "PassTunnel: TOTP kodunu otomatik giren Mac VPN istemcisi" (Turkish searches say
    "Mac" more than "macOS").
  - Guide: "PassTunnel user guide: set up a macOS VPN with TOTP codes".
  - Privacy: "Privacy policy · PassTunnel".
- **JSON-LD**, one `<script type="application/ld+json">` block per page in `<head>`, a `@graph` of
  nodes that refer to each other by `@id` (`https://passtunnel.github.io/#organization`, `#website`,
  `#app`, `/guide/#article`):
  - Home (and the Turkish home, in Turkish): `Organization` (PassTunnel, the GitHub organization, the app icon as logo), `WebSite`,
    `SoftwareApplication` (macOS 13 on Apple silicon, 15.4 for Cisco AnyConnect and Palo Alto
    GlobalProtect, free, MIT license, the latest disk image as `downloadUrl`, the latest release as
    release notes, the guide as `softwareHelp`, a feature list taken from the page, two screenshots,
    English and Turkish), `SoftwareSourceCode` (the repository) and `FAQPage`, whose questions and
    answers are the visible FAQ as plain text, in the same order.
  - Guide: `TechArticle` (the section titles as `articleSection`, the requirements as
    `dependencies`), two `HowTo`s that follow the numbered steps on the page (install and approve the
    helper; uninstall) and a `BreadcrumbList`.
  - Privacy: `WebPage` with `dateModified` equal to its "Last updated" date, and a `BreadcrumbList`.
  - A change to the visible text that a block repeats (the FAQ, the guide's steps or section titles,
    the privacy date, a title or description) updates the block in the same pull request;
    `scripts/check-site.sh` catches the FAQ, the date, missing files and `#fragment`s.
- **`sitemap.xml`** gives each page a `lastmod`; change it when the page's content changes.
- **`llms.txt`** stays a short summary with links; the full text lives in the guide and the
  README it links to, so there is no second copy (`llms-full.txt`) to fall out of date.
- **`robots.txt`** allows everything and names the sitemap; it names no particular crawler.

## Live code demo

A card styled like a profile row: profile "Work", `vpn.example.com · OpenVPN`, a six-digit code
in two groups, a countdown ring, a Connect button and a "Sent to the server" line. It follows the
app's rule (with "Wait for a fresh code" on, the default): 30-second windows aligned to the clock;
with more than 5 seconds left, Connect sends the masked password plus the current code; with 5 or
less, it waits for the next window (ring and state turn amber), then shows Connecting… and
Connected, and Disconnect resets it. Codes come from a hash of the window number, not from a real
secret. The button never becomes `disabled` (it uses `aria-disabled` so keyboard focus stays on
it); state changes are announced through a polite live region, the ticking countdown is not. The
timer stops while the demo is off screen or the tab is hidden.

## Images

All screenshots are produced by the app's offscreen renderer with sample profiles and a throwaway
Keychain service, never from a real Mac's data:

```sh
scripts/site-assets.sh          # builds the app, renders, converts to WebP, writes site/assets/img/
```

The script runs `PASSTUNNEL_RENDER=<tmp> .build/…/PassTunnel`, picks the screens the site uses
(the hero, the narrow split main window `main-split-hero` (800 pt, two tunnels) light/dark at identical sizes, also used for `og.png`; the wide `main-split` only for the README, the profile editor sheet, the
menu bar panel `menubar-panel`, General settings without its version line, the `first-run` view),
writes the screenshots as 1x, 1.5x and 2x near-lossless WebP and the icons as 1x and 2x lossless WebP,
the 2x screenshots the README shows as PNG in `docs/images/`,
the favicon and Apple touch icon from `Resources/AppIcon.icns`, and the 1200×630 social image from
`scripts/site/og.html` (headless Chrome). It needs `cwebp` (`brew install webp`) and
Google Chrome. Rerun it after UI changes that show up in these screens.

## Checks

`scripts/check-site.sh` (CI job **Site**, also fine to run locally; needs `jq` 1.6 or later, which
macOS 15 and GitHub's runners have) fails when:

- any HTML file has a `style` attribute, an inline `<script>` or an `on…=` handler (a
  `<script type="application/ld+json">` block, written exactly like that, is allowed);
- a JSON-LD block is not one JSON object with `"@context": "https://schema.org"`, names a URL of
  this site with no file behind it or with a `#fragment` that is no `id` in that file (`@id` values
  are node names and are not checked), has a `dateModified` without the same `<time datetime>` on the
  page, or its `FAQPage` questions and answers differ from the visible FAQ (each item's question in
  `<summary><span>` and its whole answer after `</summary>`, as plain text, in order);
- a page's canonical URL is not its own address (written in any attribute order), a page with a
  canonical URL has no JSON-LD block or is missing from `sitemap.xml`, or a URL in the sitemap has no
  file;
- a local link (or a link to this site's address), `src` or `srcset` points to a missing file or
  outside `site/`, or an `#anchor` has no target in the page it points to (paths with `../` are
  resolved first; ids, URLs and language codes are compared in their exact letter case);
- a link to a page in another language has no `hreflang` with that page's `<html lang>`, or a wrong one;
- the pages of a translation set (`<link rel="alternate" hreflang>`) do not all list the same
  alternates, each itself under its own language plus `x-default`; their element ids (in order) or
  FAQ item counts differ; or `sitemap.xml` lists other alternates for them;
- a `srcset` has a malformed descriptor, mixes width and density descriptors, or has width
  descriptors without `sizes`;
- a resource loads from another origin (links to github.com and the site's own address are fine);
- an `<img>` lacks `alt`, `width` or `height`;
- the CSP meta tag is missing or changed.

## Preview and deploy

Preview: `python3 -m http.server -d site 8000` and open <http://localhost:8000>.

The site is served from the root of the host, so every absolute path and URL in `site/` starts at
`/` (`https://passtunnel.github.io/…`). GitHub serves the root only from the repository named after
the host, so [PassTunnel/passtunnel.github.io](https://github.com/PassTunnel/passtunnel.github.io)
deploys it, while `site/` here stays the source:

- That repository's `site.ref` holds the commit of this repository's `main` whose `site/` is live.
  Its Pages workflow (on every push to its `main`, and by hand) checks out `site/` and
  `scripts/check-site.sh` at that commit, runs the checks, and deploys `site/` together with the
  few files of its own: the Search Console verification file and a redirect from the old address
  `/passtunnel/` to `/` that keeps the `#section`.
- `site.yml` here runs on every push to `main` that touches `site/` (and by hand, on `main`): it runs
  `scripts/check-site.sh`, then writes the pushed commit into `site.ref` and pushes it with a write
  deploy key of that repository (secret `SITE_DEPLOY_KEY` in the environment `website`, which allows
  only `main`). So the site always describes the released app: site changes go out with the next
  release merge, or by running `site.yml` by hand.
- To publish an older or newer `site/` by hand, change `site.ref` in that repository.

This repository has no GitHub Pages of its own.
