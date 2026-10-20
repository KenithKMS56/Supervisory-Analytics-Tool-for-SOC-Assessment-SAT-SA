# Dependency vulnerability audit

The packages SAT-SA pins in `uv.lock`, checked against a public vulnerability advisory
database. The check needs the network: it sends each package's name and version (nothing else)
to the advisory service. It is run by hand, with the owner's agreement, before a release.

## 2026-10-20

Run on the development machine (Windows 11, Python 3.13.2), on branch
`feat/post-brief-followups` (lock unchanged since Phase 5):

```
uv export --frozen --no-dev --no-emit-project --format requirements-txt > build/audit-requirements.txt
uvx pip-audit --require-hashes --disable-pip -r build/audit-requirements.txt --desc
uv export --frozen --all-groups --no-emit-project --format requirements-txt > build/audit-requirements-all.txt
uvx pip-audit --require-hashes --disable-pip -r build/audit-requirements-all.txt
```

| Set | Packages | Tool | Result |
|---|---:|---|---|
| Runtime (what the wheelhouse ships) | 36 | pip-audit 2.10.1, default advisory service | No known vulnerabilities found |
| Runtime and development tools (pytest, ruff, mypy, Playwright, ...) | 56 | pip-audit 2.10.1, default advisory service | No known vulnerabilities found |

`--require-hashes` makes pip-audit resolve exactly the pinned, hash-checked versions; nothing
was installed into the project environment.

**What this does not show.** Only advisories published by that date are checked; a package
with an undisclosed flaw passes. SAT-SA's own code is not covered (see
`tests/test_security_suite.py` and `docs/security/`). The result goes stale as advisories are
published: rerun before every release with `SATSA_AUDIT=1` in the wheelhouse build, which
writes `pip-audit.txt` next to the wheels.
