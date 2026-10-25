# PassTunnel's MCP server, `passtunnel mcp` on stdin and stdout, in a container: for MCP directories
# that build and introspect servers from a Dockerfile (docs/LINUX.md, Distribution).
#
#   docker build -t passtunnel .
#   docker run -i --rm passtunnel
#
# It starts without profiles or a secret store and answers `initialize` and `tools/list`. Inside a
# container it can only manage that container's own VPN connections, and only with a passtunneld
# running there: to manage this computer's VPN, install PassTunnel on it instead. A development build
# (version 0.0.0-dev); the release builds are scripts/build-app.sh (macOS) and
# scripts/build-linux.sh.

# swift:6.4.1-noble, the image of the Linux CI jobs, pinned by the digest of its multi-arch index.
FROM swift:6.4.1-noble@sha256:19cbe56bdaec1918f7cf5fdeba42b9bd55bdd8a6149c9990d0e0e3a89a127d63 AS build
WORKDIR /src
COPY . .
RUN swift build -c release --static-swift-stdlib --product passtunnel \
    && install -D -m 0755 "$(swift build -c release --static-swift-stdlib --show-bin-path)/passtunnel" /out/passtunnel \
    && strip --strip-debug /out/passtunnel

# ubuntu:24.04, the release the build image is based on (the same glibc and libstdc++), pinned by the
# digest of its multi-arch index. It follows the build image's release and is changed by hand together
# with it: Dependabot only updates the digest (.github/dependabot.yml). The Swift runtime is linked
# into the binary.
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac
RUN groupadd --gid 10001 mcp \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin mcp
COPY --from=build /out/passtunnel /usr/local/bin/passtunnel
USER 10001:10001
WORKDIR /home/mcp
ENTRYPOINT ["passtunnel", "mcp"]
