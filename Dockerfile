# azula serve, in a container — the app's terminal connects to the bash shell
# running inside this image over iroh (no inbound ports; holepunched).
#
#   docker compose up --build          # build + run
#   docker compose logs | grep endpoint   # copy the connect code into the app
#
# Outbound internet is required (iroh relays / discovery + TLS).

# ---- build stage ---------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --bin azula

# ---- runtime stage -------------------------------------------------------
FROM debian:bookworm-slim

# A real, friendly shell environment so the terminal demo feels alive.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates coreutils procps curl git vim-tiny less nano tree \
    && rm -rf /var/lib/apt/lists/*

# Runs as root so the mounted identity volume (root-owned) is writable — the
# connect code then stays stable across restarts. The shell still presents as
# "azula" (the prompt/banner are branded in .bashrc), and the container is an
# isolated, throwaway sandbox.
COPY --from=build /src/target/release/azula /usr/local/bin/azula
COPY docker/bash_profile /root/.bash_profile
COPY docker/bashrc /root/.bashrc
COPY docker/playground /root/playground

WORKDIR /root
ENV SHELL=/bin/bash TERM=xterm-256color HOME=/root
# ~/.azula holds the persisted key so the connect code is stable across restarts;
# mount a volume there (see docker-compose.yml). --term-only so a connecting app
# lands directly in the shell rather than an LLM chat.
CMD ["azula", "serve", "--term-only"]
