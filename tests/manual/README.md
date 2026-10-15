# Manual and historical scripts (NOT part of CI)

These scripts are quarantined here so they never run by accident.

- `live1.sh` — HISTORICAL. Ran 2026-10-15 with explicit approval as root:
  Tor/Privoxy stop/start and `/etc/privoxy/config` backup/edit/restore.
  Do not re-run without fresh approval. Exits nonzero unless the restored
  hash, mode, owner, and service states match the recorded initial values.
- `live2.sh` — HISTORICAL. Ran 2026-10-15 with approval: exactly one
  authenticated SIGNAL NEWNYM. Do not re-run; approval covered one signal.
- `recon.sh`, `git1.sh` — read-only probes used during development.
- `check.sh` — local build checklist. Read-only: runs `cargo fmt --check`
  (never `cargo fmt`), clippy, tests, release build, and `--help`.
- `verify.sh` — same checks in one WSL run (read-only).

Rules: run only scripts you have read; never run `live*.sh` without
explicit approval; `live2.sh` must not send more than one NEWNYM per approval.
