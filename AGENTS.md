# AGENTS.md — Utility Belt monorepo

Guidance for AI coding agents (and humans) working in this repo. Project-specific
rules live in each project's own `AGENTS.md` / `README.md` and take precedence
inside that project (e.g. `apps/osint/AGENTS.md`: that Next.js version has
breaking changes, so read its bundled docs before editing).

## Layout

```
apps/                     runnable, user-facing apps that compose the packages
  overlay/                Overlay HUD (PySide6). Imports packages/* by path via overlay/core/bridge.py
  osint/                  Image Geolocator (Next.js 16 / TypeScript)
packages/                 standalone engines, each also usable on its own (CLI/GUI)
  asphalt/                packet capture, decode, analysis (Python; src/ layout, pytest)
  port-scanner/           TCP/UDP scanner + host recon (stdlib Python)
  stegkit/                multi-format steganography (Python package, pytest)
scripts/check.py          single entry point that runs every verification pipeline
benchmarks/               old-vs-new performance and output-equivalence checks
.github/                  CI (runs scripts/check.py) and Dependabot
requirements-dev.txt      all Python deps needed for checks + benchmarks
```

Each `packages/*` and `apps/*` directory mirrors its own upstream GitHub repo
(see README.md). **Keep each project's internal layout intact.** Structural
change happens at the monorepo level, not inside a project.

## Commands

```bash
pip install -r requirements-dev.txt          # Python deps (use a venv)
(cd apps/osint && npm ci)                    # web app deps

python scripts/check.py                      # all pipelines: tests, smoke, lint, osint tsc+eslint
python scripts/check.py asphalt stegkit      # a subset (--list shows names)
python scripts/check.py osint --build        # include the Next.js production build
python benchmarks/compare.py --base HEAD     # working tree vs a ref: speed + identical output
```

`python scripts/check.py` must pass before you report work as done. CI runs the
same script, so don't add checks to the workflow that the script doesn't run.

## Rules

- **Cross-project imports only through `apps/overlay/overlay/core/bridge.py`.**
  It resolves `packages/port-scanner`, `packages/stegkit`, `packages/asphalt/src`
  from `PROJECT_ROOT`. If you move a package, update `bridge.py`; the `overlay`
  pipeline in `check.py` fails if those paths break.
- **Performance changes need proof.** Run `benchmarks/compare.py`. A speedup with
  `same output = NO` is a regression unless it fixes a documented bug.
- **Bug fixes get a regression test** in that project's `tests/` (see
  `packages/asphalt/tests/test_readers.py` for the pattern).
- Asphalt modules import each other by top-level name (`analysis`, `capture`,
  `utils`). Its `tests/conftest.py` puts `src/` on the path, as the entrypoints do.
- Overlay runtime state (`_settings.json`, `_webprofile*/`, `_screenshots/`) is
  git-ignored; never commit it.
- `apps/osint` on an exFAT drive: Turbopack can't create junctions there, so
  `next build` fails. Build from an NTFS path (CI builds on Linux).
- Security tooling: only use it against systems you own or are authorized to test.

## Agent skills for this repo

Vetted on skills.sh (reputable source, high install count) for this repo's
DevOps work. Install globally, and review each `SKILL.md` before relying on it.
Skills run with full agent permissions.

| Skill | Use it for | Installs |
|---|---|---|
| `wshobson/agents@monorepo-management` | Workspace layout, shared tooling, cross-package boundaries | 13K |
| `wshobson/agents@github-actions-templates` | Extending `.github/workflows/ci.yml` (matrices, caching, artifacts) | 16K |
| `github/awesome-copilot@github-actions-hardening` | Pinning actions, least-privilege `permissions:`, supply-chain hygiene | 1.4K (GitHub) |
| `addyosmani/agent-skills@ci-cd-and-automation` | Release/deploy automation beyond CI checks | 34K |
| `wshobson/agents@python-packaging` | Moving Asphalt/Port Scanner to `pyproject.toml` builds | 12K |
| `getsentry/skills@agents-md` | Keeping this file and per-project AGENTS.md accurate | 5.6K (Sentry) |

```bash
npx skills add wshobson/agents@monorepo-management -g -y
npx skills add wshobson/agents@github-actions-templates -g -y
npx skills add github/awesome-copilot@github-actions-hardening -g -y
npx skills add addyosmani/agent-skills@ci-cd-and-automation -g -y
npx skills add wshobson/agents@python-packaging -g -y
npx skills add getsentry/skills@agents-md -g -y
```

Already installed user-wide and useful here: `improve-codebase-architecture`
(structural review report), `impeccable` / `frontend-design` (osint and Overlay
UI work).
