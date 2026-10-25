import Foundation
import PassTunnelCLI

// The `passtunnel` command on Linux (docs/LINUX.md): the CLI and the MCP server. On the Mac the app
// binary runs the same CLI (Sources/PassTunnel/main.swift); this target is not built there.
exit(PassTunnelCLI.run(CommandLine.arguments))
