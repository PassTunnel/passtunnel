/// The long options of openconnect 9.21 (`long_options`, main.c 235–326) and what PassTunnel does with
/// each: the two files it renders (`OpenConnectConfig`, `OpenConnectAuthConfig`) write a fixed set of
/// keys, and every other option is refused by their final checks. There is no raw option input at all;
/// the reasons below say why an option must never be added to either file.
public enum OpenConnectOptions {
    /// One long option: its name, and whether it takes a value (`has_arg`; openconnect has no option with
    /// an optional value).
    public struct Option: Equatable {
        public let name: String
        public let takesValue: Bool
    }

    /// Every long option of openconnect 9.21 built with GnuTLS (the Mac's bundle and the Linux
    /// distributions'), in the order of its table, which is the order its config-file reader tries them in.
    /// `openssl-ciphers` (the OpenSSL build's name for `gnutls-priority`) is listed too.
    public static let all: [Option] = [
        .init(name: "background", takesValue: false), .init(name: "pid-file", takesValue: true),
        .init(name: "setuid", takesValue: true), .init(name: "script-tun", takesValue: false),
        .init(name: "syslog", takesValue: false), .init(name: "csd-user", takesValue: true),
        .init(name: "csd-wrapper", takesValue: true), .init(name: "external-browser", takesValue: true),
        .init(name: "no-external-auth", takesValue: false), .init(name: "pfs", takesValue: false),
        .init(name: "allow-insecure-crypto", takesValue: false), .init(name: "certificate", takesValue: true),
        .init(name: "sslkey", takesValue: true), .init(name: "cookie", takesValue: true),
        .init(name: "compression", takesValue: true), .init(name: "deflate", takesValue: false),
        .init(name: "juniper", takesValue: false), .init(name: "no-deflate", takesValue: false),
        .init(name: "cert-expire-warning", takesValue: true), .init(name: "usergroup", takesValue: true),
        .init(name: "help", takesValue: false), .init(name: "http-auth", takesValue: true),
        .init(name: "interface", takesValue: true), .init(name: "mtu", takesValue: true),
        .init(name: "base-mtu", takesValue: true), .init(name: "script", takesValue: true),
        .init(name: "timestamp", takesValue: false), .init(name: "passtos", takesValue: false),
        .init(name: "key-password", takesValue: true), .init(name: "proxy", takesValue: true),
        .init(name: "proxy-auth", takesValue: true), .init(name: "user", takesValue: true),
        .init(name: "verbose", takesValue: false), .init(name: "version", takesValue: false),
        .init(name: "cafile", takesValue: true), .init(name: "config", takesValue: true),
        .init(name: "no-dtls", takesValue: false), .init(name: "authenticate", takesValue: false),
        .init(name: "cookieonly", takesValue: false), .init(name: "printcookie", takesValue: false),
        .init(name: "quiet", takesValue: false), .init(name: "queue-len", takesValue: true),
        .init(name: "xmlconfig", takesValue: true), .init(name: "cookie-on-stdin", takesValue: false),
        .init(name: "passwd-on-stdin", takesValue: false), .init(name: "no-passwd", takesValue: false),
        .init(name: "reconnect-timeout", takesValue: true), .init(name: "dtls-ciphers", takesValue: true),
        .init(name: "dtls12-ciphers", takesValue: true), .init(name: "authgroup", takesValue: true),
        .init(name: "servercert", takesValue: true), .init(name: "resolve", takesValue: true),
        .init(name: "sni", takesValue: true), .init(name: "key-password-from-fsid", takesValue: false),
        .init(name: "useragent", takesValue: true), .init(name: "version-string", takesValue: true),
        .init(name: "local-hostname", takesValue: true), .init(name: "disable-ipv6", takesValue: false),
        .init(name: "no-proxy", takesValue: false), .init(name: "libproxy", takesValue: false),
        .init(name: "no-http-keepalive", takesValue: false), .init(name: "no-cert-check", takesValue: false),
        .init(name: "force-dpd", takesValue: true), .init(name: "force-trojan", takesValue: true),
        .init(name: "non-inter", takesValue: false), .init(name: "dtls-local-port", takesValue: true),
        .init(name: "token-mode", takesValue: true), .init(name: "token-secret", takesValue: true),
        .init(name: "os", takesValue: true), .init(name: "no-xmlpost", takesValue: false),
        .init(name: "dump-http-traffic", takesValue: false), .init(name: "no-system-trust", takesValue: false),
        .init(name: "protocol", takesValue: true), .init(name: "form-entry", takesValue: true),
        .init(name: "gnutls-debug", takesValue: true), .init(name: "gnutls-priority", takesValue: true),
        .init(name: "openssl-ciphers", takesValue: true), .init(name: "server", takesValue: true),
        .init(name: "mca-certificate", takesValue: true), .init(name: "mca-key", takesValue: true),
        .init(name: "mca-key-password", takesValue: true)
    ]

    /// Options neither rendered file ever contains, each with the reason (for either protocol, Cisco
    /// AnyConnect's and Palo Alto GlobalProtect's). Together with the two files' `renderedKeys` this covers
    /// `all`. `disable-ipv6` is rendered only in GlobalProtect files (for a Linux openconnect older than 9.20)
    /// and refused in every other.
    public static let refused: [(option: String, reason: String)] = [
        // Run a program, or change who or what runs.
        ("script-tun", "hands the tunnel to a program instead of a tun device"),
        (
            "csd-user",
            "runs the server's host-scan (CSD) program, as the named user; for GlobalProtect the HIP script, "
                + "which would run as root in the tunnel run"
        ),
        (
            "csd-wrapper",
            "runs a program for the server's host scan (CSD, HIP, TNCC); GlobalProtect's HIP script would run as root, "
                + "in the tunnel run, after the sign-in and again at every interval"
        ),
        ("external-browser", "runs a program for single sign-on"),
        ("force-trojan", "runs the host-scan program again at an interval (for GlobalProtect the HIP script, as root)"),
        ("setuid", "drops root after the tunnel is up, so the hook would run unprivileged"),
        ("background", "forks away from the supervisor"),
        ("config", "reads options from another file (and cannot be nested)"),
        // Read or write files as root.
        ("pid-file", "writes a file at a path of its choice, as root"),
        ("xmlconfig", "writes the server's XML profile to a path, as root"),
        ("certificate", "reads a client certificate file or PKCS#11 object, as root"),
        ("sslkey", "reads a private key file or PKCS#11 object, as root"),
        ("key-password", "a secret for a key file; no client certificates in Phase 1"),
        ("key-password-from-fsid", "derives a key password from a file system id; no client certificates"),
        ("mca-certificate", "reads a second client certificate, as root"),
        ("mca-key", "reads a second private key, as root"),
        ("mca-key-password", "a secret for the second key"),
        ("token-mode", "openconnect would compute the one-time code itself, past PassTunnel's code rules"),
        ("token-secret", "a token secret, or `@file` read as root"),
        // Weaken or bypass the server check or the encryption.
        ("no-cert-check", "turns the server certificate check off"),
        ("allow-insecure-crypto", "allows 3DES and RC4"),
        ("gnutls-priority", "replaces the TLS cipher priorities"),
        ("openssl-ciphers", "replaces the TLS ciphers (OpenSSL builds)"),
        ("dtls-ciphers", "replaces the DTLS ciphers"),
        ("dtls12-ciphers", "replaces the DTLS 1.2 ciphers"),
        ("sni", "sends a server name other than the profile's host"),
        // Send traffic elsewhere.
        ("proxy", "sends the connection, and the cookie, through a proxy"),
        ("proxy-auth", "proxy credentials"),
        ("libproxy", "lets the system's proxy settings (or a PAC script) pick a proxy"),
        ("no-proxy", "no proxy is ever set; not needed"),
        ("http-auth", "proxy authentication methods; no proxy"),
        ("interface", "a named device could attach to another user's persistent tun (Linux)"),
        ("dtls-local-port", "binds a chosen local UDP port, as root"),
        ("passtos", "copies the inner packets' TOS bits to the outer packets"),
        // Print or log secrets, or hide what the log parser needs.
        ("dump-http-traffic", "logs the HTTP traffic, with the cookie"),
        ("verbose", "higher log levels print the cookie and the HTTP traffic"),
        ("gnutls-debug", "TLS debug output"),
        ("syslog", "logs to syslog instead of the session log"),
        ("quiet", "hides the progress lines the log parser reads"),
        ("timestamp", "changes the log line format the log parser reads"),
        ("authenticate", "prints the cookie; given on the sign-in run's command line, never in a file"),
        ("cookieonly", "prints the cookie and exits"),
        ("printcookie", "prints the cookie"),
        ("cookie-on-stdin", "the cookie is in the root file; stdin is /dev/null"),
        // Change what the client tells the server, or how it signs in.
        (
            "useragent",
            "no user agent field in Phase 1; a line break would add HTTP headers; for GlobalProtect openconnect sends "
                + "PAN GlobalProtect itself"
        ),
        (
            "version-string",
            "claims another client version (for GlobalProtect app-version, by which gateways choose HIP and client policies)"
        ),
        ("local-hostname", "sends a chosen host name to the server (for GlobalProtect computer, also in the cookie)"),
        (
            "os",
            "claims another operating system (it picks the host-scan program; for GlobalProtect clientos, by which gateways "
                + "choose HIP and client policies)"
        ),
        (
            "usergroup",
            "the group is the sign-in URL's path; the tunnel run connects without it; for GlobalProtect the path decides "
                + "portal or gateway and can name a single sign-on cookie field"
        ),
        ("form-entry", "submits arbitrary sign-in form values (for GlobalProtect also the portal's gateway choice)"),
        ("no-passwd", "turns off password sign-in"),
        ("no-xmlpost", "changes the sign-in protocol (9.21 exits on it)"),
        ("juniper", "selects another protocol (`nc`)"),
        ("force-dpd", "overrides the server's dead peer detection interval"),
        // Not needed; the server's values or openconnect's defaults apply.
        ("compression", "compression is not needed"),
        ("deflate", "compression is not needed"),
        ("no-deflate", "compression is not needed"),
        ("pfs", "not needed"),
        ("mtu", "not needed; the server's value applies"),
        ("base-mtu", "not needed; the server's value applies"),
        ("queue-len", "not needed"),
        ("cert-expire-warning", "not needed"),
        ("no-http-keepalive", "not needed"),
        ("help", "prints help and exits"),
        ("version", "prints the version and exits")
    ]
}
