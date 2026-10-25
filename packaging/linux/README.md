# PassTunnel for Linux

`passtunnel` is the command line and the MCP server (`passtunnel mcp`); `passtunneld` is the root
daemon that starts and stops the VPN tools for the users allowed to connect. There is no desktop app
on Linux yet. How it works and what it checks: docs/LINUX.md in the source repository,
<https://github.com/PassTunnel/passtunnel/blob/main/docs/LINUX.md>.

```
bin/passtunnel                          the command and the MCP server
sbin/passtunneld                        the daemon
lib/systemd/system/passtunnel.socket    the daemon's socket, /run/passtunnel/daemon.sock
lib/systemd/system/passtunnel.service   the daemon, started through the socket
LICENSE                                 PassTunnel's license (MIT)
THIRD_PARTY_NOTICES.md, licenses/       what is linked into the binaries, and its licenses
```

## Requirements

- Linux with systemd on x86_64 or aarch64, glibc 2.35 or later (Ubuntu 22.04, Debian 12, RHEL 10
  and later).
  The Swift runtime is linked into the binaries; from the system they need only glibc, libstdc++
  and libgcc_s.
- OpenVPN profiles: `openvpn` 2.6 or later, the distribution's (`/usr/sbin/openvpn` or
  `/usr/bin/openvpn`).
- FortiGate profiles: `openfortivpn` 1.21 or later (`/usr/bin/openfortivpn`) and `pppd` 2.4.7 or
  later (`/usr/sbin/pppd`, package `ppp`).
- A place for passwords and TOTP secrets, one of: the desktop keyring (GNOME Keyring, KDE Wallet,
  KeePassXC) through `secret-tool` (package `libsecret-tools` on Debian and Ubuntu, `libsecret` on
  Fedora); `systemd-creds` (systemd 256 or later for users other than root); or an encrypted file
  with a passphrase, which needs nothing installed. `passtunnel secret-store` shows which one is used.

The daemon runs only the tools at these fixed paths, root's and writable by root only, and refuses
older versions.

## Install

As root, from the unpacked directory:

```sh
install -m 0755 bin/passtunnel /usr/local/bin/passtunnel
install -m 0755 sbin/passtunneld /usr/local/sbin/passtunneld
install -d -m 0755 /usr/local/lib/systemd/system
install -m 0644 lib/systemd/system/passtunnel.socket lib/systemd/system/passtunnel.service \
    /usr/local/lib/systemd/system/
groupadd --system passtunnel
usermod -a -G passtunnel alice                 # every user who may connect
systemctl daemon-reload
systemctl enable --now passtunnel.socket
```

Root and the members of the group `passtunnel` may start connections; everyone may see and stop
only their own. The daemon looks up the group when a request comes in, so a new member needs no new
login. The daemon refuses to start from a file that anyone but root could replace, so keep it where
`install` puts it. `passtunnel` finds it there (`/usr/local/sbin` next to `/usr/local/bin`) and
compares it with the daemon that runs.

Then, as the user:

```sh
passtunnel helper status       # the daemon: enabled, responding, not outdated
passtunnel import client.ovpn  # or: passtunnel add NAME --type openvpn|forti
passtunnel help
```

## Update

Install the new files as above (the group and the enabled socket stay), then
`systemctl daemon-reload` and, once no VPN is connected, `systemctl restart passtunnel.service`:
restarting the daemon ends every session it runs. Until then `passtunnel helper status` reports
the running daemon as outdated.

## Uninstall

```sh
systemctl disable --now passtunnel.socket passtunnel.service
rm /usr/local/bin/passtunnel /usr/local/sbin/passtunneld \
    /usr/local/lib/systemd/system/passtunnel.socket /usr/local/lib/systemd/system/passtunnel.service
systemctl daemon-reload
groupdel passtunnel
```

Profiles stay in each user's `~/.local/share/passtunnel/`, and their secrets in the store they were
saved to.
