# Changelog

## 0.1.0 — 2026-11-19

First version.

- **Incident check.** Given a package, an ecosystem and bad versions, gives every repo in a
  GitHub org one verdict (affected, at risk, safe version, not used, could not check) with the
  file and line behind it, confirms the incident against OSV and the registry, and writes an
  issue with a checklist and a ready-to-send reply.
- **Daily watch.** Asks OSV about every package the org uses and reports only known-malicious
  releases that match.
- **Active branches.** Deploy-named and recently pushed branches are read by difference.
- **Three front ends.** Command line, a GitHub Action called from your own private repo, and a
  Claude Code skill. The tool's repo holds code only; results stay in the caller's repo.
- **Optional article reader.** Turns an article link into an unconfirmed incident with Claude.
- **File formats.** requirements files, pyproject (PEP 621, Poetry, uv, PDM), setup.cfg,
  setup.py, Pipfile, Conda environments, uv/poetry/pdm/Pipfile locks, package.json, npm, yarn
  and pnpm locks, go.mod, Cargo.toml, Cargo.lock, pom.xml.
