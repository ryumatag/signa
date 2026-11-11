# The image both sides of the interoperability runs use: the Rust toolchain
# that builds signa-ua's tests at its MSRV, and SIPp from Debian bookworm.
# The SIPp package is pinned, so that a change in bookworm fails the build
# rather than changing the profile.
FROM rust:1.85-bookworm@sha256:e51d0265072d2d9d5d320f6a44dde6b9ef13653b035098febd68cce8fa7c0bc4

RUN apt-get update \
    && apt-get install -y --no-install-recommends sip-tester=1:3.6.1-1+b2 \
    && rm -rf /var/lib/apt/lists/*
