# Security

blastcheck is a security tool that organisations run against their own code hosts, so its own
safety matters. This page says what it can touch and how to report a problem in it.

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Use **Security → Report a vulnerability** on this repository (GitHub private vulnerability
reporting). Include what you found, how to reproduce it, and what an attacker could gain.
You should get a first reply within five working days.

Things worth reporting include:

- a way for content in a scanned repo, or in an article, to make blastcheck report a repo as
  clean when it is not
- a way for such content to inject links, images, mentions or HTML into the issue it writes
- token leakage in logs, error messages, reports or caches
- requests sent anywhere other than GitHub, OSV, the package registry, or (with `--url`) the
  article's own host and the Claude API
- anything in the workflows that exposes secrets or lets untrusted input reach a shell

## What blastcheck can access

| | |
|---|---|
| GitHub | Read-only. It lists repos and branches and downloads dependency and lock files. It contains no code that commits, pushes or opens pull requests in the repos it scans. |
| Writes | Issues in the one scan repo you name, and files under `.blastcheck/` on the machine or runner. |
| Outbound | GitHub API; OSV and the package registry (public package names and versions only); with `--url`, the article's host and the Claude API (the public article text only). |
| Never | Source code is not read. Nothing from a scanned repo is executed. Repo contents are not sent to any model. |

## Design rules that should hold

If you find a case where one of these does not hold, that is a vulnerability.

1. **No false "all clear".** A repo, branch or dependency file that could not be read makes
   the verdict *incomplete*. This includes failed lookups, truncated responses, unsupported lock
   formats and partly recovered files.
2. **Untrusted text is inert.** File paths, version specifiers, parse errors and article text
   are escaped before they reach markdown, and length-capped.
3. **An article cannot make a verdict.** An incident drafted from an article is validated
   against a fixed shape and stays *unconfirmed* until OSV or the registry agrees.
4. **Nothing private in public.** The issue and the run summary are not written when the
   target repo is public, or when its visibility cannot be established.
5. **Requests stay where they were sent.** HTTPS only; redirects are followed only to the same
   host; responses are size-capped; article links that resolve to private addresses are refused.

6. **Code here, data there.** This repository holds only code and never runs a scan. Results
   live in the private repo the action is called from. Under GitHub Actions, blastcheck checks
   that repo's visibility before reading anything and stops if it is public or cannot be
   confirmed private.

## Hardening your own install

- Call the action from a **private** repo, and limit who can push to it. Anyone who can run a modified
  workflow there can read its secrets.
- Give `BLASTCHECK_ORG_TOKEN` read-only **Contents** access and nothing else.
- For a stricter setup, put the secrets in a GitHub Environment restricted to the default
  branch, and pin `supreeth-ravi/blastcheck` in your workflows to a commit SHA rather than a tag.

## Supported versions

Fixes are made on the latest release only.
