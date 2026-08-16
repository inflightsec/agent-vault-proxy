# PyPI smoke test

End-to-end smoke for the **published PyPI wheel** of `kow`. Different from `tests/docker-e2e/`: that one builds from local source and tests the in-repo code; this one pip-installs from PyPI and tests the artifact users actually download.

## What it does

1. Builds a minimal `python:3.12-slim-bookworm` image that runs `pip install --only-binary :all: keys-on-the-wire==<version>` from PyPI (or any `--index-url` you point at).
2. Stands up the proxy + a `mendhak/http-https-echo` upstream on an isolated bridge network, with the same hardening (`read_only`, `cap_drop: [ALL]`, `no-new-privileges`) as the docker-e2e stack.
3. Runs the same positive (placeholder → real secret on the wire, audit recorded) + negative (unbound destination denied, audit recorded) assertions as `docker-e2e/`.

If a published wheel ever stops doing what it's supposed to do — broken metadata, wrong entry point, transitive dep yanked, Python-minor incompatibility surfacing — this harness fails before users notice.

## Running locally

```bash
# Smoke the version that's published right now on PyPI:
bash tests/pypi-smoke/run.sh 0.9.0

# Smoke against TestPyPI:
PACKAGE_INDEX_URL=https://test.pypi.org/simple/ bash tests/pypi-smoke/run.sh 0.9.0

# Leave the stack up for debugging:
bash tests/pypi-smoke/run.sh 0.9.0 --keep
# Then: docker compose -f tests/pypi-smoke/docker-compose.yml logs avp
# Tear down: cd tests/pypi-smoke && docker compose down -v
```

Exit 0 = the wheel works end-to-end. Non-zero = something between PyPI and `docker run` is broken.

### Pre-release dry-run: smoke a locally-built wheel

Before tagging a release, you can run the same harness against a wheel you've just built — no PyPI involvement, no version-number commitment. Catches harness-side bugs and validates the v0.4.x code path before pushing the tag.

```bash
# 1. Build the wheel
rm -rf dist && python -m build

# 2. Smoke it through the same harness CI will run
bash tests/pypi-smoke/run.sh --local-wheel dist/keys_on_the_wire-0.9.0-py3-none-any.whl

# 3. If green, push the tag — CI runs the same harness against the
#    published PyPI artifact, which exercises the identical code path.
```

The script parses the version from the wheel filename, copies the wheel into `tests/pypi-smoke/wheels/` (gitignored), and builds the smoke image with `INSTALL_SOURCE=local` so the Dockerfile installs from the staged wheel instead of resolving from PyPI.

## CI integration

Two workflows consume this harness:

- **`.github/workflows/release.yml`** — `pypi-install-smoke` job runs after `publish-pypi` succeeds. Waits ~90s for PyPI CDN propagation, then runs this harness against the just-published version. If it fails, the GitHub Release isn't created and the operator yanks the broken version from PyPI manually.
- **`.github/workflows/pypi-canary.yml`** — scheduled daily. Fetches the latest released version from PyPI's JSON API and runs this harness against it. Failure opens a GitHub Issue tagged `pypi-canary` so it's harder to miss than a red workflow run.

## Port + name collision avoidance

This stack uses host port `127.0.0.1:14323` and the `avp-pypi-smoke-*` container/network/volume names so it can run side-by-side with `docker-e2e/` (which uses `14322` and `avp-e2e-*`).

## What it doesn't test

- TLS / HTTPS — same caveat as docker-e2e. Plain HTTP echo skips the upstream-cert-trust dance. Live HTTPS coverage is in `tests/smoke/layer3_proxy_anthropic.py` against `api.anthropic.com`.
- BWS backend — the harness uses the `static` backend with a fixture secret. The BWS code path is covered by `tests/test_caching.py` + unit tests + the integration runs in `tests/smoke/`.
- Multi-Python-version install — the smoke image is `python:3.12-slim`. The CI matrix in `test.yml` covers 3.12 and 3.13 against locally-built wheels; if you want PyPI install tested on 3.13 too, extend the canary with a matrix.
