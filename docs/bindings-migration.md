# Bindings migration notes

This repo now targets the curated interface crates instead of consuming raw WIT directly:

- Hosts use `greentic-interfaces-host` for capability traits and `greentic-interfaces-wasmtime` for linker helpers.
- Guest components targeting `wasm32-wasip2` should use `greentic-interfaces-guest`.

## What changed here

- Workspace dependencies switched to `greentic-interfaces-host`, `greentic-interfaces-guest`, and `greentic-interfaces-wasmtime` (`0.4.34`).
- The legacy `greentic-interfaces` dependency was removed; no local bindgen/WIT remains.

## How to adopt in downstream crates

1. Add the host or guest crate to `Cargo.toml`:
   - Hosts: `greentic-interfaces-host = "0.4.34"`
   - Guests: `greentic-interfaces-guest = "0.4.34"`
   - Wasmtime glue: `greentic-interfaces-wasmtime = "0.4.34"`
2. Replace raw `greentic_interfaces::...` or bindgen modules with the curated modules:
   - Hosts: `use greentic_interfaces_host::oauth::*;` (and other capability modules)
   - Guests: `use greentic_interfaces_guest::oauth::*;`
3. Remove embedded `.wit` or bindgen output tied to the old `greentic-interfaces` crate.
4. Rewire Wasmtime linker setup through `greentic-interfaces-wasmtime` helpers where applicable.

## Status

- Host helper (`greentic-oauth-host`) is already component-ready and does not rely on raw WIT.
- Workspace dependencies have been updated; remaining downstream repos should mirror this pattern and drop direct `greentic-interfaces` usage.
