# sparkpass

A guest pass tool for a model that is served on two linked NVIDIA DGX Spark units.
The design, with the reason for each safety rule, is in `docs/designs/guest-pass-mvp.md`.

## Testing

The development Mac has no Rust toolchain. `cargo` runs in a local Docker image
(Linux ARM64, the same platform as the units). Build the image one time:

```bash
docker build -t sparkpass-dev - <<'EOF'
FROM rust:1-slim-bookworm
RUN rustup component add clippy
EOF
```

Five checks, the same as `.github/workflows/ci.yml`. Run all five before a push.

Unit tests:

```bash
docker run --rm -v "$PWD":/work -v sparkpass-cargo:/usr/local/cargo/registry -v sparkpass-target:/target -e CARGO_TARGET_DIR=/target -w /work sparkpass-dev cargo test --locked
```

Lint:

```bash
docker run --rm -v "$PWD":/work -v sparkpass-cargo:/usr/local/cargo/registry -v sparkpass-target:/target -e CARGO_TARGET_DIR=/target -w /work sparkpass-dev cargo clippy --locked --all-targets -- -D warnings
```

Stub model server:

```bash
python3 tests/stub-model.py --self-test
```

Shell files (the local image `koalaman/shellcheck:stable`; CI runs the same check):

```bash
git ls-files '*.sh' | xargs docker run --rm -v "$PWD":/mnt:ro -w /mnt koalaman/shellcheck:stable
```

Gateway, with a real Caddy in Docker (the images `caddy:2` and `caddy:2.6.2`, the Ubuntu 24.04 package):

```bash
bash tests/gateway.sh && CADDY_IMAGE=caddy:2.6.2 bash tests/gateway.sh
```

Rules for tests:

- Unit tests live in `#[cfg(test)]` modules next to the code. They use the `FakeRunner`
  in `src/runner.rs` and a temporary directory for each test. They need no hardware.
- `tests/cli.rs` starts the real binary, which uses the real root `/`. It may only make
  calls that cannot change the host, such as the call with no arguments.
- The container runs as root, so permission bits do not force a failed write. To force
  one, use a path that is a directory.
- Each test must fail if the behavior that it protects is removed.
- systemd and curl behavior cannot be tested here. Caddy is tested in Docker by `tests/gateway.sh`
  (the Caddyfile and the token rule); its systemd unit and the inbound path are proven only on the units.
- `install.sh` and `tests/expiry.sh` change the host. Never run them here; they run on the head unit.
- The token rule format lives in `gateway::rule` in `src/gateway.rs`, the guard in `gateway/Caddyfile`,
  `lease_rule` and `deny_all` in `tests/gateway.sh`, and the deny-all text in `install.sh` and
  `tests/expiry.sh`. Change all of them together. A unit test in `src/gateway.rs` checks each copy.
