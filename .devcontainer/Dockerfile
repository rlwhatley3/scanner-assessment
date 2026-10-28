FROM rust:bookworm AS rust

FROM node:24-bookworm

USER root

SHELL ["/bin/bash", "-c"]

COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo /usr/local/cargo

ENV HOME=/root \
  RUSTUP_HOME=/usr/local/rustup \
  CARGO_HOME=/usr/local/cargo \
  PATH=/usr/local/cargo/bin:/usr/local/bin:${PATH} \
  SKIP_PRELOAD=1 \
  HOST=0.0.0.0 \
  API_HOST=0.0.0.0 \
  IS_SANDBOX=1

RUN npm install -g @anthropic-ai/claude-code@latest @openai/codex@latest @opencode/cli@latest

RUN printf '%s\n' \
  'alias claude="claude --dangerously-skip-permissions"' \
  'alias codex="codex --yolo --no-daemon"' \
  'alias opencode="opencode"' \
  >> /root/.bashrc

WORKDIR /workspace

COPY server/rust-toolchain.toml ./server/rust-toolchain.toml
COPY server/Cargo.toml server/Cargo.lock ./server/
COPY server/src ./server/src

RUN set -o pipefail \
  && curl -fsSL https://raw.githubusercontent.com/cargo-bins/cargo-binstall/v1.26.0/install-from-binstall-release.sh | sh -s -- \
  && cd server \
  && cargo binstall --no-confirm cargo-watch --version 8.5.3 \
  && rustc --version && cargo --version && cargo fetch --locked

COPY ui/package.json ui/package-lock.json ./ui/
RUN npm install --no-audit --no-fund --prefix ./ui

ENTRYPOINT []

CMD ["./start.sh"]
