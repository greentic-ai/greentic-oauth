# Local Checks

`ci/local_check.sh` mirrors the repository’s GitHub Actions workflow so you can sanity check the workspace before pushing.

## Usage

```bash
ci/local_check.sh
```

### Helpful toggles

- `LOCAL_CHECK_ONLINE=0` — force offline mode (default is `1`, meaning online).
- `LOCAL_CHECK_STRICT=1` — treat missing tools/env as hard failures instead of soft skips.
- `LOCAL_CHECK_VERBOSE=1` — print each command before it executes.

Combine them when needed, for example:

```bash
LOCAL_CHECK_ONLINE=0 LOCAL_CHECK_STRICT=1 ci/local_check.sh
```
