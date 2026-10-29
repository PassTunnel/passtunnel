# A client machine for tunnel-test.sh (Tests/ocserv/README.md). TEST ONLY. One stage for each base image,
# chosen with `docker build --target client-ubuntu|client-debian` (run-tunnel-tests.sh): both name their
# image literally, by tag and by the digest of its multi-arch index, so that scanners and Dependabot see
# the pin (the root Dockerfile's and Tests/ocserv/Dockerfile's images, which stay the same release).
# EXTRA adds the DNS backend's packages (openresolv, or systemd with systemd-resolved, which then runs
# as the container's init); install-client-packages.sh is shared by both stages.

FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac AS client-ubuntu
ARG EXTRA=""
COPY install-client-packages.sh /tmp/install-client-packages.sh
RUN sh /tmp/install-client-packages.sh ${EXTRA} && rm /tmp/install-client-packages.sh

FROM debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS client-debian
ARG EXTRA=""
COPY install-client-packages.sh /tmp/install-client-packages.sh
RUN sh /tmp/install-client-packages.sh ${EXTRA} && rm /tmp/install-client-packages.sh
