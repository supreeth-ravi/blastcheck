# blastcheck

A package gets compromised. Someone forwards the article and asks: *are we using it?*

`blastcheck` answers that for every repo in your GitHub org in about a minute, and drafts the
reply. It runs in your own setup with your own credentials. Nothing is hosted, and your code is
never sent anywhere.

```
$ blastcheck check --org acme-labs --package agent-framework --ecosystem pypi --bad 1.26.1,1.26.2

AT RISK — a loose version range could have pulled a bad version
confirmed: OSV lists MAL-2026-20101 for agent-framework 1.26.1

We checked all 142 repos. None pin an affected version of agent-framework (1.26.1 and 1.26.2),
but 2 use it with a loose version range that could have pulled one: billing-api, ops-notebooks. ...
```

## What it does

1. Lists the org's repos and downloads **only dependency and lock files** through the GitHub API.
   No source code is read and nothing from a repo is executed.
2. Compares them with the incident: a package, an ecosystem and the bad versions.
3. Asks OSV and the package registry whether those versions are really bad.
4. Gives every repo one verdict and writes a report with the evidence, a checklist and a reply.

| Verdict | Meaning |
|---|---|
| Affected | A bad version is pinned in a lock file or exact pin |
| At risk | A version range (or no version) would accept a bad version, and no lock file of the same tool in that folder pins a safe one. A `requirements.txt` is never treated as protected by a lock, because pip does not read one |
| Uses the package at a safe version | Pinned outside the bad set |
| Does not use the package | |
| Could not fully check | The repo, or one of its dependency files, could not be read or is in a format not supported yet |

It never reports "not affected" for something it could not read: one unreadable repo turns a
clean result into **incomplete**, and the drafted reply says so.

When in doubt it flags. Pre-release versions, dist-tags such as `next`, and specifiers it cannot
parse are treated as "could pull the bad version", so expect the occasional false alarm and no
silent passes.

## Three ways to run it

### 1. On your laptop

```bash
pip install .
gh auth login            # if you have not already
blastcheck check --org <org> --package <name> --ecosystem pypi --bad 1.2.3,1.2.4
```

The first run reads every repo. Later runs reuse `.blastcheck/inventory.json` and only re-read
repos that have been pushed to since.

### 2. As a GitHub Action in your org

1. Click **Use this template** and create a **private** repo in your org, for example `security-scan`.
2. Add a secret `BLASTCHECK_ORG_TOKEN`: a fine-grained token with read-only **Contents** and
   **Metadata** access to all repositories in the org.
3. Open **Actions → Incident check → Run workflow**, enter the package and bad versions, and run.

The result is a GitHub issue in that repo, labelled `blastcheck`. Running the same incident
again updates the issue. The run shows red when the verdict is affected, at risk or incomplete.

Keep the scan repo private. The report names your private repos and files, so the tool refuses
to write the issue in a public repo unless you pass `--allow-public-issue-repo`.

Anyone who can push a branch to the scan repo can run a modified workflow and read its
secrets. Limit write access to it, or move the secrets into a GitHub Environment restricted to
the default branch. For a stricter setup, pin the actions in the workflow to commit SHAs.

Optional secrets:

| Secret | What it enables |
|---|---|
| `ANTHROPIC_API_KEY` | Paste an article link instead of the package and versions |
| `BLASTCHECK_SLACK_WEBHOOK` | A short notice in Slack |
| `BLASTCHECK_SMTP_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `BLASTCHECK_MAIL_FROM`, `BLASTCHECK_MAIL_TO` | A short notice by email |

### 3. In Claude Code

Copy `skill/incident-check` into `~/.claude/skills/`, then:

```
/incident-check https://example.com/some-attack-writeup
```

Claude Code reads the article, runs `blastcheck` with your `gh` login and reports the result.
No API key is needed for this route.

## Automatic mode

`blastcheck watch --org <org>` needs no incident. It asks the public malware database (OSV)
about every package your repos use and runs the same check for each malware advisory it finds.

- A pinned bad version is always reported.
- A loose range that could resolve to a bad version is reported only while the advisory is
  recent (7 days by default, `--recent-days`). Malicious releases are removed from the registry
  quickly, after which a loose range can no longer pull them.
- Nothing matching means no issue, no notice and a green run.
- An issue someone has closed is left closed.
- If OSV cannot be reached the run fails; it never reports a quiet day it did not check.

The **Daily watch** workflow runs this every day at 02:30 UTC with the same secret as the
incident check. It covers malicious releases only; ordinary vulnerabilities are out of scope.

A Conda package that shares its name and version with a bad PyPI release is reported as a name
collision to verify, not as affected: Conda does not install from PyPI.

## Which branches are read

Each repo's default branch, plus branches whose code is likely being installed now:

- branches named like a deploy target (`develop`, `staging`, `uat`, `prod`, `release/…`, `hotfix/…`)
- branches pushed in the last 30 days

This stays cheap because a branch is read by difference. One request lists a branch's files with
a content fingerprint for each, and a dependency file identical to the default branch's is never
downloaded. A finding on a branch names that branch in the report.

| Flag | Effect |
|---|---|
| `--branch-days 90` | Widen (or narrow) the recency window; `0` keeps only deploy-named branches |
| `--max-branches 15` | Most extra branches read per repo; the report says if any were left out |
| `--no-branches` | Default branches only |

## What leaves your environment

| Sent to | What |
|---|---|
| GitHub API | Requests for your own repos' file lists and dependency files |
| OSV and the package registry | The public package name and versions from the incident |
| Claude API (only with `--url`) | The text of the public article |

Repo contents are not sent to OSV, the registry or Claude.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Not affected |
| 1 | Affected or at risk |
| 2 | Incomplete: some repos could not be read |
| 3 | The check could not run |

## What it does not cover

- Branches that are neither deploy-named nor recently pushed (see below), and past states of a lock file
- Archived repos, unless you pass `--include-archived` (the report says how many were skipped)
- Dockerfiles and CI workflow files (`pip install` lines there are a known blind spot)
- Gradle files and Bun lock files: a repo that has them is reported as "could not fully check"
  for that ecosystem
- What is installed on laptops, servers or in built images
- GitLab, Bitbucket and Azure DevOps
- General vulnerability scanning: this checks one named incident at a time

An article-derived incident is marked **unconfirmed** until OSV or the registry agrees. Read the
report's confirmation line before acting on it.

## Supported files

- **Python:** any `*requirements*.txt` / `.in`, `constraints*.txt`, files inside a
  `requirements/` folder, `pyproject.toml` (PEP 621, Poetry, uv, PDM), `setup.cfg`, `setup.py`
  (read as text, never run), `Pipfile`, `Pipfile.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`,
  Conda `environment.yml`
- **JavaScript:** `package.json` (including overrides and resolutions), `package-lock.json`,
  `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`
- **Other:** `go.mod`, `Cargo.toml`, `Cargo.lock`, `pom.xml`

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest --cov=blastcheck
```

The core has no runtime dependencies. The `ai` extra adds the Anthropic SDK for `--url`.

## License

MIT
