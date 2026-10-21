<!--
Title: type(scope): description, for example "feat: fill in the code for GlobalProtect" or
"fix(cli): exit with 3 for a missing profile". Types and what they release: CONTRIBUTING.md.
Pull requests go into dev and are squash-merged; the title is the commit and the release-notes line.
-->

Closes #

## What and why

<!-- What does this change, and why? -->

## How it was tested

<!-- e.g. swift test, manual connect with OpenVPN / FortiGate, screenshots via PASSTUNNEL_RENDER -->

## Checklist

- [ ] `swift build` and `swift test` pass
- [ ] New functionality or the fixed bug is covered by a test
- [ ] New user-facing strings use `String(localized:)` and have a Turkish translation in `Localizable.xcstrings`
- [ ] Changes to the helper or the config sanitizer keep the rules in `docs/ARCHITECTURE.md` and `SECURITY.md` (and update them if needed)
- [ ] No real host names, company names or credentials in code, tests or screenshots
- [ ] Docs updated (README, `docs/`) if behavior changed
