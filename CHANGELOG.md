# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.1.1]

### Bug Fixes
- `SessionClient::service_sign_callback` now signs via `try_sign` and fails closed to a `LOCKED` error
  when the profile is locked, instead of framing the all-zero fail-safe signature into a success
  envelope (SPEC §3.4 / §5.6.7).

## [0.1.0] - 2026-07-19

### Features
- Seed dig-ipc-protocol v0.1.0 canonical dig-app/dig-node IPC session contract


