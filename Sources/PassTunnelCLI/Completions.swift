import PassTunnelCore
import PassTunnelKit

/// Shell completion scripts (`passtunnel completion zsh|bash|fish`). Profile ids come from
/// `passtunnel list --quiet`.
enum CLICompletions {
    static let profileCommands = [
        "status", "connect", "disconnect", "toggle", "code", "show", "set", "export",
        "rm", "secret", "default", "pin", "unpin", "log"
    ]

    static func script(for shell: CLICommand.Shell) -> String {
        switch shell {
        case .zsh: return zsh
        case .bash: return bash
        case .fish: return fish
        }
    }

    static var commands: String { CLICommand.commandNames.joined(separator: " ") }

    /// Options offered after a profile id.
    static let profileFlags = [
        "--json", "--all", "--copy", "--follow", "--lines", "--activity", "--yes", "--force", "--wait",
        "--timeout", "--no-input", "--no-auth-prompt"
    ]

    /// `secret-store` (Linux only): its cases, put in front of the `mcp` case of each script.
    static var storeNames: String { SecretStoreChoice.allCases.map(\.rawValue).joined(separator: " ") }
    #if os(Linux)
    static var zshSecretStore: String { "secret-store) _values 'store' \(storeNames) ;;\n    " }
    static var bashSecretStore: String { "secret-store) COMPREPLY=($(compgen -W \"\(storeNames) --json\" -- \"$cur\")) ;;\n    " }
    #else
    static let zshSecretStore = ""
    static let bashSecretStore = ""
    #endif

    static var zsh: String {
        """
        #compdef passtunnel
        # Install: passtunnel completion zsh > "${fpath[1]}/_passtunnel"

        _passtunnel() {
          local -a commands
          commands=(\(CLICommand.commandNames.map { "'\($0)'" }.joined(separator: " ")))
          if (( CURRENT == 2 )); then
            _describe 'command' commands
            return
          fi
          local cmd=${words[2]}
          case $cmd in
            \(profileCommands.joined(separator: "|")))
              if (( CURRENT == 3 )); then
                local -a ids
                ids=(${(f)"$(passtunnel list --quiet 2>/dev/null)"})
                _describe 'profile' ids
              elif [[ $cmd == secret ]]; then
                _values 'secret' password totp
              elif [[ $cmd == set ]]; then
                _values -S = 'key' \(ProfileFields.keys.joined(separator: " "))
              else
                _arguments \(profileFlags.map { "'\($0)'" }.joined(separator: " "))
              fi
              ;;
            import) _arguments '--name' '--json' '*:file:_files' ;;
            add) _arguments '--type[VPN type]:type:(openvpn forti)' '--json' ;;
            helper) _values 'action' status install uninstall ;;
            diagnose) _arguments '--check-clock[also ask the time server]' '--json' ;;
            \(zshSecretStore)mcp) _arguments '--allow-connect[also offer connect and disconnect]' '--no-auth-prompt' ;;
            list|version) _arguments '--json' ;;
            completion) _values 'shell' zsh bash fish ;;
            help) _describe 'command' commands ;;
          esac
        }

        _passtunnel "$@"

        """
    }

    static var bash: String {
        """
        # Install: passtunnel completion bash > /usr/local/etc/bash_completion.d/passtunnel
        _passtunnel() {
          local cur=${COMP_WORDS[COMP_CWORD]}
          local cmd=${COMP_WORDS[1]}
          if [[ $COMP_CWORD -eq 1 ]]; then
            COMPREPLY=($(compgen -W "\(commands)" -- "$cur"))
            return
          fi
          case $cmd in
            \(profileCommands.joined(separator: "|")))
              if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=($(compgen -W "$(passtunnel list --quiet 2>/dev/null)" -- "$cur"))
              elif [[ $cmd == secret ]]; then
                COMPREPLY=($(compgen -W "password totp" -- "$cur"))
              elif [[ $cmd == set ]]; then
                compopt -o nospace 2>/dev/null
                COMPREPLY=($(compgen -S = -W "\(ProfileFields.keys.joined(separator: " "))" -- "$cur"))
              else
                COMPREPLY=($(compgen -W "\(profileFlags.joined(separator: " "))" -- "$cur"))
              fi
              ;;
            import) COMPREPLY=($(compgen -f -- "$cur")) ;;
            add) COMPREPLY=($(compgen -W "--type openvpn forti --json" -- "$cur")) ;;
            helper) COMPREPLY=($(compgen -W "status install uninstall --json" -- "$cur")) ;;
            diagnose) COMPREPLY=($(compgen -W "--check-clock --json" -- "$cur")) ;;
            \(bashSecretStore)mcp) COMPREPLY=($(compgen -W "--allow-connect --no-auth-prompt" -- "$cur")) ;;
            list|version) COMPREPLY=($(compgen -W "--json --quiet" -- "$cur")) ;;
            completion) COMPREPLY=($(compgen -W "zsh bash fish" -- "$cur")) ;;
            help) COMPREPLY=($(compgen -W "\(commands)" -- "$cur")) ;;
          esac
        }
        complete -F _passtunnel passtunnel

        """
    }

    static var fish: String {
        var lines = [
            "# Install: passtunnel completion fish > ~/.config/fish/completions/passtunnel.fish",
            "complete -c passtunnel -f",
            "complete -c passtunnel -n '__fish_use_subcommand' -a '\(commands)'",
            "complete -c passtunnel -n '__fish_seen_subcommand_from \(profileCommands.joined(separator: " "))' "
                + "-a '(passtunnel list --quiet 2>/dev/null)'",
            "complete -c passtunnel -n '__fish_seen_subcommand_from secret' -a 'password totp'",
            "complete -c passtunnel -n '__fish_seen_subcommand_from set' -a '\(ProfileFields.keys.map { $0 + "=" }.joined(separator: " "))'",
            "complete -c passtunnel -n '__fish_seen_subcommand_from add' -l type -xa 'openvpn forti'",
            "complete -c passtunnel -n '__fish_seen_subcommand_from import' -F",
            "complete -c passtunnel -n '__fish_seen_subcommand_from helper' -a 'status install uninstall'",
            "complete -c passtunnel -n '__fish_seen_subcommand_from completion' -a 'zsh bash fish'",
            "complete -c passtunnel -n '__fish_seen_subcommand_from help' -a '\(commands)'"
        ]
        let commonJSONCommands =
            "status connect disconnect toggle code list show set add import export rm secret default pin unpin log diagnose helper version"
        #if os(Linux)
        lines.insert(
            "complete -c passtunnel -n '__fish_seen_subcommand_from secret-store' -a '\(storeNames)'",
            at: lines.count - 1)
        let jsonCommands = commonJSONCommands + " secret-store"
        #else
        let jsonCommands = commonJSONCommands
        #endif
        for (flag, cmds) in [
            ("json", jsonCommands), ("all", "disconnect"), ("copy", "code"),
            ("follow", "log"), ("lines", "log"), ("activity", "log"), ("yes", "rm"), ("force", "connect"), ("name", "import"),
            ("output", "export"), ("wait", "connect disconnect"), ("timeout", "connect disconnect"),
            ("allow-connect", "mcp"), ("check-clock", "diagnose"), ("no-input", commands), ("no-auth-prompt", commands)
        ] {
            lines.append("complete -c passtunnel -n '__fish_seen_subcommand_from \(cmds)' -l \(flag)")
        }
        return lines.joined(separator: "\n") + "\n"
    }
}
