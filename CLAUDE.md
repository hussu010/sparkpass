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

Three checks, the same as `.github/workflows/ci.yml`. Run all three before a push.
CI also runs `shellcheck` on each tracked `*.sh` file. The repository has no shell file yet.

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

Rules for tests:

- Unit tests live in `#[cfg(test)]` modules next to the code. They use the `FakeRunner`
  in `src/runner.rs` and a temporary directory for each test. They need no hardware.
- `tests/cli.rs` starts the real binary, which uses the real root `/`. It may only make
  calls that cannot change the host, such as the call with no arguments.
- The container runs as root, so permission bits do not force a failed write. To force
  one, use a path that is a directory.
- Each test must fail if the behavior that it protects is removed.
- systemd, Caddy, and curl behavior cannot be tested here. It is proven only on the units.
