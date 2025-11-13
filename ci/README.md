# Local Checks

`ci/check_local.sh` mirrors the repository’s GitHub Actions workflow so you can sanity check the workspace before pushing. The legacy `ci/local_check.sh` simply forwards to the new entrypoint for backwards compatibility.

## Usage

```bash
ci/check_local.sh
```

### Helpful toggles

- `LOCAL_CHECK_ONLINE=0` — force offline mode (default is `1`, meaning online).
- `LOCAL_CHECK_STRICT=1` — treat missing tools/env as hard failures instead of soft skips.
- `LOCAL_CHECK_VERBOSE=1` — print each command before it executes.

Combine them when needed, for example:

```bash
LOCAL_CHECK_ONLINE=0 LOCAL_CHECK_STRICT=1 ci/check_local.sh
```
