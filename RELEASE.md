# Release checklist — bastionfuse

Codifies the by-hand release we did for bastionskill so every tool ships the same way.
Publishing is automatic: pushing a **GitHub Release** tag triggers the OIDC publish workflow.

## Pre-flight

- [ ] Working tree clean, on the default branch, up to date with origin.
- [ ] CI green on the matrix (Python 3.10–3.13).
- [ ] Corpus/format contract tests green (`pytest -q`) — if this tool consumes a shared format (injections.jsonl adapters, policy.yaml, trace schema), its contract test still parses the golden fixture.

## Bump

- [ ] Bump `__version__` in the package `__init__.py` **and** `version` in `pyproject.toml` (keep them equal).
- [ ] Update `CHANGELOG.md` (or the README changelog section) with the new version + date.

## Command words

- [ ] Re-check `policy.DEFAULT_COMMANDS` and `DEFAULT_LABELS` against current Claude Code tool names
      (hooks docs). A renamed built-in tool silently loses its label.

## Build & verify locally

```bash
python -m build
twine check dist/*
```

- [ ] `twine check` passes (README renders, metadata valid).

## Publish

- [ ] Tag + create a GitHub Release `v<version>` — the `publish.yml` OIDC workflow builds and uploads to PyPI.
- [ ] Confirm on PyPI: `pip install -U bastionfuse` pulls the new version.

## Propagate version truth (PRP G5)

- [ ] Update `suite.json` in the **bastion-site** repo (or let the build-time `scripts/fetch-github-stats.mjs` re-fetch), so bastiondefense.dev never shows a stale version.
- [ ] `bastionsupply doctor` reports the new version as latest.
