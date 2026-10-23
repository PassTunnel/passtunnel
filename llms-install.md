# Installing the PassTunnel MCP server

PassTunnel is a macOS app (Apple silicon, macOS 13 or later); the MCP server is part of the app. There is
nothing to install from npm or pip.

1. Install the app (ask the user before running):
   ```sh
   brew trust passtunnel/tap
   brew install --cask passtunnel/tap/passtunnel
   ```
   Without Homebrew: download the disk image from
   https://github.com/PassTunnel/passtunnel/releases/latest/download/PassTunnel.dmg, open it and drag
   PassTunnel to /Applications.
2. The user opens PassTunnel once and approves the helper in System Settings -> General -> Login Items.
   Profiles, passwords and TOTP secrets are set up by the user in the app; never ask for them.
3. Add the server (stdio). Command: `/Applications/PassTunnel.app/Contents/MacOS/PassTunnel`, args: `["mcp"]`.
   ```json
   { "mcpServers": { "passtunnel": { "command": "/Applications/PassTunnel.app/Contents/MacOS/PassTunnel", "args": ["mcp"] } } }
   ```
   Add `"--allow-connect"` to args only if the user wants the assistant to connect and disconnect.
4. Check: call `diagnose`; it reports the app version, helper state and per-profile problems.
