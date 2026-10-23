# Website

The project website is a single static page in [`site/`](../site), published with GitHub Pages at
<https://passtunnel.github.io/>. It explains what PassTunnel does, how to install it, the CLI and
MCP setup and the security model, and it serves `llms.txt` for tools that read it.

This document is the spec for the site: what is on it, the rules it follows and how it is
maintained. The code in `site/` is the source of truth for the exact look.

## Rules

- **Static and self-contained.** Plain HTML, one stylesheet, two small vanilla scripts. No
  framework, no build step, no package manager, no CDN, no web fonts, no trackers, analytics,
  cookies or third-party requests of any kind. Everything the page loads comes from `site/`.
- **Strict Content Security Policy** (meta tag): `default-src 'none'; script-src 'self';
  style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'`. That means no inline `<script>`, no `style="…"` attributes and no
  `on…=` handlers anywhere; SVG presentation attributes (`fill`, `stroke`, …) are fine.
- **Facts only.** Every claim must match the app (`docs/APP.md`, `docs/ARCHITECTURE.md`,
  `SECURITY.md`). No testimonials, user counts, download numbers, ratings, logos or "trusted by".
  No version numbers either, so the page never goes stale between releases.
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
- **Light on the wire**: images are lossless WebP at the displayed size with 1x/2x `srcset`,
  real `width`/`height`, `loading="lazy"` below the fold; images of the theme not shown are not
  downloaded. The whole first view stays well under 500 KB.
- **Translatable.** English only for now. Copy lives in the HTML; the strings scripts show live in
  one object at the top of `main.js`. A Turkish page will be `site/tr/index.html`; the footer gets
  its "Türkçe" link only when that page exists (no dead links).

## Files

| Path | What |
|---|---|
| `site/index.html` | The page |
| `site/assets/style.css` | All styles; design tokens as custom properties on `:root` |
| `site/assets/theme.js` | Loaded in `<head>` before the stylesheet paints: applies the saved theme (no flash) |
| `site/assets/main.js` | Theme button, mobile menu, copy buttons, format picker, palette picker, live code demo |
| `site/assets/img/` | Generated images (do not edit by hand) |
| `site/llms.txt` | Plain-text summary for language-model tools: what it is, install, CLI, MCP setup, links |
| `site/404.html`, `site/robots.txt`, `site/sitemap.xml` | The usual |
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

Header (sticky, translucent): app icon + name, section links, GitHub, theme button, Download.
Below 900 px the section links move into a menu button (disclosure pattern: `aria-expanded`,
closes on Escape, on outside click and when a link is chosen).

1. **Hero.** Eyebrow "For OpenVPN and FortiGate SSL VPN on macOS", the tagline as `h1`, one
   sentence of explanation, "Download for Mac" (latest release) and the Homebrew one-liner with a
   copy button (`brew trust passtunnel/tap && brew install --cask passtunnel/tap/passtunnel`).
   The one-liner is focusable and scrolls sideways with a fade at the cut edge; below 640 px it is
   replaced by an "Install with Homebrew" button that jumps to the Install section. Then
   "macOS 13+ · Apple silicon · Free & open source (MIT)". Below that, on the glow: the live code
   demo next to the main window screenshot (stacked on narrow screens, demo first).
2. **One-time codes, handled.** Format picker (Append, Prepend, password:code, password,code,
   Custom template, Sent separately) showing what the server receives; Custom template shows the
   `{password}` / `{otp}` placeholders; Sent separately shows the password and the code as two
   fields (OpenVPN static challenge, FortiGate OTP field). Next to it the profile editor's
   one-time code screenshot. Four cards: authenticator-style window (live codes, countdown ring,
   click to copy, clipboard cleared after 30 s, codes can be hidden), QR import (drop, choose or
   paste), Touch ID per profile (secrets then encrypted with a Secure Enclave key), auto-type
   shortcut ⌃⌥C.
3. **VPN client.** OpenVPN and FortiGate SSL VPN with signed `openvpn` / `openfortivpn` bundled.
   Menu bar card: a neutral menu bar strip on a soft backdrop holding the real rendered badges,
   with a picker for the five palettes (Pastel, Vivid, Soft, Candy, Earth) that swaps the image.
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
   app) → bundled `openvpn` / `openfortivpn` (signed, sanitized OpenVPN configurations); a text
   equivalent for screen readers. Two cards: login Keychain without iCloud sync; nothing sent
   anywhere except your VPN server (no sudoers rule, no admin password at every connect).
   Onboarding screenshot of the helper step. Link: "Read the full security model" → SECURITY.md.
   Touch ID/Secure Enclave is covered in section 2 and the FAQ, not repeated here.
6. **Install.** Download (DMG from GitHub Releases, drag to Applications), Homebrew (the two
   commands, copyable), build from source (README).
7. **FAQ** (`<details>`): why a privileged helper, where secrets are stored, which VPN types,
   does it work without TOTP ("None" or "Ask each time").
8. **Call to action**, then **footer**: GitHub, Releases, Security, License (MIT), and "PassTunnel
   is not affiliated with OpenVPN Inc. or Fortinet. OpenVPN and FortiGate are trademarks of their
   respective owners."

## Live code demo

A card styled like a profile row: profile "Work", `vpn.example.com · OpenVPN`, a six-digit code
in two groups, a countdown ring, a Connect button and a "Sent to the server" line. It follows the
app's rule: 30-second windows aligned to the clock; with 8 seconds or more left, Connect sends
the masked password plus the current code; with less, it waits for the next window (ring and
state turn amber), then shows Connecting… and Connected, and Disconnect resets it. Codes come from
a hash of the window number, not from a real secret. The button never becomes `disabled`
(it uses `aria-disabled` so keyboard focus stays on it); state changes are announced through a
polite live region, the ticking countdown is not. The timer stops while the demo is off screen or
the tab is hidden.

## Images

All screenshots are produced by the app's offscreen renderer with sample profiles and a throwaway
Keychain service, never from a real Mac's data:

```sh
scripts/site-assets.sh          # builds the app, renders, converts to WebP, writes site/assets/img/
```

The script runs `PASSTUNNEL_RENDER=<tmp> .build/…/PassTunnel`, picks the screens the site uses
(main window light/dark at identical sizes, profile editor one-time code section, menu bar badges
for every palette light/dark, General settings, helper onboarding step), writes 1x and 2x lossless
WebP, the favicon and Apple touch icon from `Resources/AppIcon.icns`, and the 1200×630 social
image from `scripts/site/og.html` (headless Chrome). It needs `cwebp` (`brew install webp`) and
Google Chrome. Rerun it after UI changes that show up in these screens.

## Checks

`scripts/check-site.sh` (CI job **Site**, also fine to run locally) fails when:

- any HTML file has a `style` attribute, an inline `<script>` or an `on…=` handler;
- a local link, `src` or `srcset` points to a missing file, or an in-page `#anchor` has no target;
- a resource loads from another origin (links to github.com are fine);
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
