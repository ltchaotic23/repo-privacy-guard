# repo-privacy-guard

Git hooks and a GitHub Action that stop you accidentally publishing secrets **and personal
details** from a git repository. Python standard library only: nothing to install from a
package index.

Secret scanners are good at API keys. They usually miss the personal details that slip into
solo projects: a home-folder path with your username in it, your own email address in a test
fixture, a phone number or postcode in sample data, your home IP address in a config file.
This kit checks for both, at the last moments before anything leaves your machine (commit
and push), and once more on GitHub.

## What's in it

| Part | What it does |
|---|---|
| `.githooks/pre-commit` | Scans the added lines and names of staged files, and the email your commit will carry. |
| `.githooks/commit-msg` | Scans the commit message before the commit is made. |
| `.githooks/pre-push` | Scans every commit and annotated tag about to be pushed, one at a time, including messages and author and tagger emails. A secret added in one commit and deleted in the next is still caught. |
| `.githooks/privacy-guard.toml` | Every pattern and allowlist, in one file you can edit. |
| `install.py` | One command that installs the hooks in a repository (or turns them off again). |
| `templates/visibility-guard-*.yml` | A GitHub Action in two modes: raise the alarm if a private repository is made public, or scan the whole history before you make one public. |
| [`CHECKLIST.md`](CHECKLIST.md) | A "ready to publish?" checklist for the things a tool can't check. |

## What it looks for

- **Secrets** (always block): private key blocks; AWS, GitHub, Google, Slack, Stripe, GitLab,
  Hugging Face, npm, PyPI, Telegram and Discord tokens; Slack and Discord webhook URLs;
  `sk-` style API keys (OpenAI, Anthropic and others); JSON Web Tokens; passwords inside
  URLs; npm registry credentials in `.npmrc`; values assigned to names such as `password`,
  `secret`, `token` or `api_key`, whether quoted in code (including escaped quotes in JSON
  and notebooks, backticks, and Python `b"..."` and `r"..."` strings), in `.env` and
  Compose `NAME=value` form, in Dockerfile `ENV` and `ARG` lines, in XML elements such as
  `<password>`, or unquoted in YAML, `.properties`, INI and TOML files.
- **Files that shouldn't be committed** (always block): `.env` files (but not
  `.env.example`), private keys and keystores (`id_rsa`, `*.pem`, `*.key`, `*.p12` and
  similar), certificates, Terraform state and variables (`*.tfvars`), app signing
  properties (`keystore.properties`, `signing.properties`), and credentials files such as
  `.netrc`, `.git-credentials` and `credentials.json`.
- **Personal details:** home-folder paths with a username (`C:\Users\<name>`, including the
  Git Bash, WSL and file-URL forms, `/home/<name>` and `/Users/<name>`), email addresses, and
  author, committer and tagger emails that aren't a GitHub `noreply` address all **block**.
  Phone numbers (international, UK and North American formats), public IPv4 and IPv6
  addresses, UK postcodes and Discord-style IDs (17 to 20-digit "snowflakes") **warn**,
  because ordinary numbers in code can look like them. Use `--strict`, or set
  `strict = true` in the config, to make every rule block.
- **Messages:** the text of commit and annotated tag messages, with the same rules.

Values reserved for documentation and tests are ignored by default, so sample data written
the recommended way doesn't block a commit: `example.com`, `example.net` and `example.org`
addresses, and addresses at the top-level domains reserved for testing (`.test`,
`.example`, `.invalid` and `.localhost`); the documentation IP ranges `192.0.2.x`, `198.51.100.x`, `203.0.113.x` and
`2001:db8::`; Ofcom's drama phone numbers (such as `07700 900xxx`) and North America's
`555-0100` to `555-0199`; the placeholder postcode `ZZ99 9ZZ`; and the username
`exampleuser`. Use `--report-examples`, or set `report_examples = true` in the config, to
have them reported too, which is a quick way to check that the guard works.

The output names the file, line and rule, and **never shows the matched text**, so it is
safe to paste into an issue or to show in a CI log. Blocking findings come first, secrets
before personal details, then warnings. A blocked commit looks like this:

```text
privacy-guard: commit blocked: 3 possible leaks (the matched text is never shown)

  app/settings.py:2
      secret: a GitHub token [github-token]
  app/settings.py:2
      secret: a quoted value assigned to a password, secret, token or key [secret-assignment]
  notes.md:3
      personal: a Windows home-folder path containing a username [home-path-windows]

privacy-guard: 1 warning, not blocking (use --strict, or strict = true in the config, to block these too):

  sample.md:3
      personal: a public IPv4 address [public-ipv4]

Remove the value. Keep secrets in an untracked file or a secret manager.
False alarm? Add 'privacy-guard:allow=<rule-id>' to the line for a personal detail (secrets can only be allowed in the config), or add an allowlist entry in .githooks/privacy-guard.toml.
To skip the guard once (not recommended): git commit --no-verify
```

## Requirements

- Git, and Python 3.11 or newer on your `PATH` as `python3`, `python` or `py`.
- The hooks run through the `sh` that comes with Git, so they work on Windows too.
- If Python can't be found, the hooks block the commit or push rather than let it through.

## Install

```sh
git clone https://github.com/ltchaotic23/repo-privacy-guard.git
python repo-privacy-guard/install.py path/to/your-repo
```

This copies `pre-commit`, `commit-msg`, `pre-push`, `privacy_guard.py` and
`privacy-guard.toml` into `path/to/your-repo/.githooks/`, records the scripts' checksums in
`privacy-guard.sha256`, and runs `git config core.hooksPath .githooks` there. Then commit
the guard so it travels with the repository. The `--chmod=+x` keeps the hooks executable for
anyone who clones it on Linux or macOS:

```sh
cd path/to/your-repo
git add --chmod=+x .githooks/pre-commit .githooks/pre-push .githooks/commit-msg
git add .githooks/privacy_guard.py .githooks/privacy-guard.toml .githooks/privacy-guard.sha256
git commit -m "Add repo-privacy-guard hooks"
```

If the installer says so, also add these lines to `.gitattributes`, so the guard's files
keep Unix line endings when someone clones with Windows line endings turned on. The hooks
then still run under a Linux `/bin/sh`. (The installer itself ignores line endings when it
compares files.)

```text
.githooks/pre-commit text eol=lf
.githooks/pre-push text eol=lf
.githooks/commit-msg text eol=lf
.githooks/privacy_guard.py text eol=lf
.githooks/privacy-guard.toml text eol=lf
.githooks/privacy-guard.sha256 text eol=lf
```

`core.hooksPath` is a setting of each clone, not of the repository, so every new clone needs
`git config core.hooksPath .githooks` once (or run the installer again).

Installer options:

- `--workflow private` or `--workflow public` also adds `.github/workflows/visibility-guard.yml`
  (see [the Action](#github-action-visibility-guard)).
- `--force` replaces an existing `core.hooksPath` (from any git config file), hooks in
  `.git/hooks`, hook files you've edited, or an existing workflow.
- `--uninstall` turns the hooks off for that clone (it unsets `core.hooksPath` if it is
  `.githooks`). The files stay where they are; remove them with `git rm -r .githooks`.

Every check runs before anything is written, so a refusal leaves the repository as it was.
Without `--force`, the installer won't replace a different `core.hooksPath`, won't override
one set in your global, system or included git config, won't switch off hooks you already
have in `.git/hooks` (setting `core.hooksPath` makes git ignore that folder), and won't
overwrite a hook file that has changed since it was installed. Even with `--force`, it
never writes through a symbolic link or a Windows junction, whether that is the file itself
or a folder on the way to it (`.githooks`, `.github`, `.github/workflows`), and it refuses a
`core.hooksPath` set in a worktree's own config or in `GIT_CONFIG_*` environment variables,
because those override the repository's setting. Afterwards it checks that git really uses
`.githooks`. To update the guard later, run the installer again: copies it installed
unchanged are updated, and your config is kept. New default rules then have to be copied
into your config by hand.

### Other hook managers

The installer doesn't merge with other hook setups; it only refuses to replace them without
`--force`. If you use one, wire the guard in by hand:

- **husky** sets `core.hooksPath` itself. Copy the guard's files into `.githooks` as usual,
  but don't run `install.py`; call the scanner from husky's hook scripts instead:
  `python3 .githooks/privacy_guard.py staged` in `pre-commit`,
  `python3 .githooks/privacy_guard.py commit-msg -- "$1"` in `commit-msg`, and
  `python3 .githooks/privacy_guard.py push -- "$@"` in `pre-push` (it reads git's pre-push
  input on stdin). On Windows, use `python` or `py` if `python3` isn't on your `PATH`.
- **Other hook managers** (the pre-commit framework, lefthook and so on) aren't covered
  here: each passes arguments and input to hooks in its own way.
- **Git LFS:** `git lfs install` writes its own `pre-push`, `post-checkout`, `post-commit`
  and `post-merge` hooks into `.git/hooks`, which `core.hooksPath` hides. Add a line such as
  `git lfs pre-push "$@"` to `.githooks/pre-push` before the guard's own command, and copy
  the other LFS hooks into `.githooks` (the installer will then ask for `--force` next time,
  because the file has changed).

## Configure

Everything lives in `.githooks/privacy-guard.toml`, with comments. The hooks read it as it is
staged (pre-commit and commit-msg) or committed (pre-push), so an edit you haven't staged or
committed can't weaken them by accident; stage or commit your changes for them to apply.
Common changes:

- **One false alarm on a personal detail:** add `privacy-guard:allow=<rule-id>` to that
  line, in a comment, for example `privacy-guard:allow=public-ipv4`. Several ids can be
  separated by commas (no spaces). A bare `privacy-guard:allow` hides every personal rule on
  the line. Markers never hide secrets and have no effect in commit or tag messages. A
  marker written any other way (spaces, capitals, quotes, an unknown rule id) does nothing,
  and the guard prints a warning saying so.
- **A secret-shaped value that isn't a secret, or any value that's fine everywhere:** add a
  pattern to `[allowlist] values`, where it is visible in review. It is matched against the
  value found (the username in a path, the password in a URL, the digits of a phone
  number), for example `'^198\.51\.100\.7$'`.
- **An old commit you accept as it is** (already public, say): add its id to
  `[allowlist] commits`. Its findings are then left out of push and history scans.
- **A folder that shouldn't be scanned:** add a pattern to `[allowlist] paths`, for example
  `'^docs/screenshots/'`. File-name rules still apply there.
- **Block everything, including warnings:** set `strict = true`.
- **Your own example values:** add them to a rule's `examples` list. Like the built-in ones,
  they're ignored unless `report_examples = true`.
- **A rule you don't want:** delete it or comment it out.
- **A new rule:**

  ```toml
  [[rules]]
  id = "internal-hostname"
  category = "personal"
  description = "an internal hostname"
  regex = '\b[a-z0-9-]+\.corp\.example\.net\b'
  severity = "warn"
  ```

Rules can also use `ignore_before` (skip a match when the text just before it matches) and
`paths` (only apply to some files); the config's comments explain each key. Secret rules
always block.

Check your edits with `python .githooks/privacy_guard.py check-config`. Unknown keys, broken
patterns, patterns that would match everything and allowlist entries that would match almost
anything (such as `'.'`) are errors, and the hooks block until they're fixed, so a typo can't
quietly switch a check off.

## Run a scan by hand

```sh
python .githooks/privacy_guard.py staged             # what the pre-commit hook runs
python .githooks/privacy_guard.py history            # every commit and annotated tag on every branch and tag
python .githooks/privacy_guard.py history --strict   # the same, with warnings blocking too
```

`--strict` makes every rule block and `--report-examples` reports reserved example values,
without editing the config. Exit status: 0 nothing that blocks (warnings may be printed),
1 possible leaks found, 2 error. When you add the kit to an existing repository, run
`history` once: the hooks only look at new changes.

## GitHub Action: visibility guard

Both modes use `permissions: contents: read` and pin every action to a full commit SHA.
Copy one to `.github/workflows/visibility-guard.yml`, or use `install.py --workflow`.

- **Stay private** (`templates/visibility-guard-private.yml`), for repositories that must
  never be public. It fails loudly on the `public` event, the moment the visibility changes,
  and also on every push and once a week as a backstop. A failed run shows in the Actions
  tab, and GitHub notifies the person whose action started the run (for the weekly run,
  whoever last changed the schedule), depending on their notification settings. It needs no
  checkout and no third-party actions: it asks the GitHub API for the repository's
  visibility, using the workflow's read-only token, and anything other than `private`
  (including `internal`) fails.
- **Going public** (`templates/visibility-guard-public.yml`), for repositories that are
  public or about to be. It checks out the full history (`fetch-depth: 0`) and runs
  `history` on every push and pull request, so it also catches commits made with
  `--no-verify` or on a machine without the hooks. Blocking rules fail the run; warnings
  (phone numbers, postcodes, IP addresses) are listed but don't. To fail on those too, run
  the workflow by hand from the Actions tab with "strict" ticked, or run `history --strict`
  locally (Gate 3 of the [checklist](CHECKLIST.md)). For pull requests it uses the scanner
  and rules from the base branch, so editing them in a pull request doesn't change that
  pull request's result. If the pull request's own config doesn't load with the base
  branch's scanner, the run fails, unless the pull request also changes `privacy_guard.py`
  (an upgrade), when it only warns. It checks that the runner has Python 3.11 or newer
  first. This repository uses it on itself.

## Limits

Please read these before relying on the kit.

- **It complements other tools; it doesn't replace them.** Run a dedicated secret scanner
  such as [gitleaks](https://github.com/gitleaks/gitleaks) alongside it, and turn on GitHub's
  secret scanning with push protection. Those know hundreds of token formats and some can
  check whether a token is live. This kit knows a few dozen patterns, plus the personal
  details they usually skip. Not covered, for example: tokens from most other services
  (Azure, Twilio, SendGrid, Mailgun, Shopify, Square, Heroku, DigitalOcean, Databricks,
  Atlassian, Cloudflare and many more), `Authorization: Bearer` and `Basic` headers,
  connection strings such as `Server=...;Password=...;`, passwords passed as command-line
  options (`--password ...`), unquoted values assigned in code, keys and passwords in
  formats other than those listed above, MAC addresses, hostnames, WSL network paths
  (`\\wsl$\...`), card and bank numbers, national ID numbers and dates of birth.
- **Hooks can be skipped.** `git commit --no-verify` and `git push --no-verify` bypass them,
  a clone without `core.hooksPath` set doesn't run them, and checking out a branch that has
  no `.githooks` folder (an orphan `gh-pages` branch, say) leaves git with no hooks to run.
  The going-public workflow is the backstop.
- **Pattern matching misses things.** For example: secrets that look like ordinary words;
  details inside images, PDFs or encoded text (base64, URL encoding); names and street
  addresses, which have no reliable pattern; anything split across lines or built up from
  pieces. The rules for a value assigned to a name such as `password` skip values with
  spaces (passphrases) and values shorter than 12 characters (8 in config files, Dockerfiles
  and XML elements). Also missed: paths glued to an option (`-I/home/...`, `-v/home/...`),
  Windows UNC paths (`\\server\c$\Users\...`), phone numbers written straight inside
  brackets (`call(07700900123)`), IPv6 addresses followed by a colon, URL passwords with
  percent-encoded non-ASCII characters, and names with several suffixes
  (`db_password_prod_eu`).
- **Commented-out lines are scanned by every rule but one.** `config-secret` (unquoted
  values in YAML, `.properties`, INI, TOML and Compose files) skips them, because commented
  examples are common there. `env-style-secret` still scans `# KEY=value` lines, and so do
  all the other rules, in any file.
- **Binary files get file-name checks only.** A file counts as binary, as in git, when a NUL
  byte appears in its first 8,000 bytes. That includes text saved as UTF-16, which Windows PowerShell
  5.1 writes by default when you redirect output (`>`). Files that `.gitattributes` marks
  `-diff` or `binary` are still scanned if they are really text.
- **False alarms happen.** Numbers can look like phone numbers, postcodes or IDs, and
  four-part version numbers have the same shape as IP addresses (such as `203.0.113.10`)
  where nothing nearby says they are versions. An 18-digit Windows file time can look like
  a Discord ID. These rules only warn by default. A database link such as
  `users@prod.internal` counts as an email address and blocks. <!-- privacy-guard:allow=email -->
  Allowlist false alarms as described above.
- **Some real values are skipped to cut false alarms.** For example: an upper-case postcode
  written without its space and made only of `0-9` and `A-F` (it looks like a colour); a
  postcode whose last part reads like a size or unit (`8GB`, `1TB`, and in lower case `1st`,
  `2px`, `1ns` and similar); a phone-shaped run of powers of two (`256 512 1024`); an
  address whose domain looks like a version or a file name (`name@1.2`, `theme@dark.css`);
  `/home/<name>` in a Dockerfile `WORKDIR` or in a web route (`@GetMapping("/home/...")`,
  `- path: /home/...`, `href="/home/..."`); and a four-part number after `version`, `>=`, an
  image name or Maven coordinates.
- **Discord-style IDs depend on the date.** A 17 to 20-digit number counts as an ID only if
  it decodes to a time before tomorrow, so a big number that passes today could start
  warning later. Round numbers such as `10**18` never count.
- **For commit messages, pre-push and the history scan are the checks to rely on.** The
  commit-msg hook catches most leaks a commit earlier, but it can't see how git was called.
  Without an editor (`git commit -m` or `-F`), it scans `#` lines too, because git keeps
  them. When git opens an editor, it follows `commit.cleanup` and the comment character
  (`core.commentChar`, or `core.commentString` on git 2.45 or newer): it leaves out the
  comment lines git will remove, and the `commit -v` diff below git's exact scissors line.
  A scissors line you paste yourself is scanned past unless git's own diff follows it. The
  remaining gap: a `--cleanup` option on the command line is invisible to hooks, so
  `--cleanup=verbatim` with an editor can let a `#` line through commit-msg (pre-push still
  scans it), and `--cleanup=strip` with `-m` can report a `#` line that git then removes.
- **Names that only describe a secret aren't treated as secrets.** Values assigned to names
  ending in `name`, `ref`, `id`, `type`, `file`, `path`, `url`, `endpoint`, `header`,
  `issuer`, `audience`, `region`, `encoding`, `regex`, `scope`, `hash`, `version` and similar
  are skipped, and so are lower-case kebab-case values in config files that look like
  resource names (`my-tls-secret`), so `secretName: tls-cert` passes, but so does a real value in a field
  called `secret_id`.
- **Only added lines are scanned.** Details already in a file aren't reported until that line
  changes, and `git commit --amend` doesn't rescan lines already in the commit being amended
  (pre-push still sees the whole commit). A file moved with `git mv` is treated as deleted and
  added, so its lines are scanned again. Run the `history` scan once when you adopt the kit.
- **Pushing a new branch or tag asks the remote what it already has.** The pre-push hook
  runs `git ls-remote` (one extra request to the remote; an SSH key that needs a passphrase
  or a touch may ask again) and leaves out commits the remote's current branches and tags
  already contain. Local remote-tracking branches are never trusted for this, because they
  can be out of date (after the remote's URL changes, for example). It asks the URL the push
  goes to, which can differ from the one `git fetch` uses. If the remote can't be asked,
  the new branch is scanned back to its first commit. Pushing an existing branch doesn't
  ask, so merging an already-published branch into it scans that branch's commits again.
  Old findings you accept can go in `[allowlist] commits`.
- **Pushes also check what the pushed trees contain**, not just what each commit changes.
  For every pushed branch or tag that brings new commits, each file name in its tree is
  checked, and so is every line that differs from the remote's current tips (and, for a
  force push, from the tip being replaced). So a file such as `.env`, a deleted secret
  brought back by a merge (`git merge -s ours`, say) or a force push back to a commit that
  still had a secret is caught. A push that brings no new commits isn't scanned, because
  the remote already has everything in it: a new branch or tag at an old commit (one from
  before a secret was deleted, say) goes through, and the history scan is what finds it.
  A file that matches a file-name rule on purpose (a public certificate, say) needs an
  `ignore` entry on that rule.
- **Which config the hooks use.** pre-commit and commit-msg use the staged copy (or the one
  in `HEAD` if it has been removed from the index); pre-push uses the copy in `HEAD`, even
  when you push a different branch. Where git doesn't track the config at all, the file on
  disk is used.
- **Tags:** annotated tags (message and tagger email) and tags that point straight at a file
  are scanned, whichever ref name they are pushed under. A tag that points at a folder (a
  tree) isn't.
- **Merge commits:** only lines that are new in the merge itself are scanned. Lines from the
  merged branches are scanned with the commits that added them.
- **The history scan covers every ref:** branches, tags, remote-tracking branches, notes,
  custom refs such as `refs/backup/*`, and a detached `HEAD`. It skips only the local
  stash, which is never pushed. On GitHub, it can't see refs
  that Actions doesn't fetch, such as `refs/pull/*`: commits from closed pull requests can
  still be served by GitHub even when no branch contains them.
- **`core.hooksPath` replaces `.git/hooks`** and overrides any global `core.hooksPath` for
  that repository. See [Other hook managers](#other-hook-managers).
- **The stay-private workflow is an alarm, not a lock.** It can't change the visibility
  back, and it never looks at the code. The `public` event only runs workflows on the
  default branch, and anyone with admin rights can disable the workflow. GitHub documents
  that it disables scheduled workflows in public repositories after 60 days without
  activity, so don't rely on the weekly run alone (the `public` event still fires).
- **A pull request can still change the going-public workflow itself.** On `pull_request`
  events GitHub runs the workflow file from the pull request, so someone could edit
  `visibility-guard.yml` to skip the base-branch step. Require review of changes to
  `.github/` and `.githooks/` (for example with `CODEOWNERS` and a branch rule).
- **The commit email check assumes GitHub.** For another host, extend
  `allowlist.commit_emails` or set `check_commit_emails = false`.
- **Other people's commits** can fail the history scan: a pull request whose commits carry
  the contributor's own email address, or a `Co-authored-by:` line with an address in a
  commit message. Allowlist the address, or set `check_commit_emails = false`, if you
  accept contributions.
- **Tested on:** Windows 11 with Git for Windows and Python 3.11, 3.12 and 3.13. The CI
  workflow is set up to run the tests on Linux (Python 3.11 to 3.14), macOS and Windows, but
  hasn't run yet. The two GitHub Action modes haven't run on GitHub yet either.

## Privacy and network use

The hooks and scanner run on your machine and only read your repository through `git`.
The one network request is the pre-push hook's `git ls-remote` to the remote you are
pushing to, when you push a new branch or tag; nothing is sent to anyone else. The
stay-private workflow calls the GitHub API to read the repository's visibility. In CI logs, findings show commit ids, file names, line numbers and
rule ids, never the matched text.

## Development

```sh
python -m unittest discover -s tests -v
```

The tests cover every rule with values it must catch and values it must not, and run the
hooks against real commits and pushes in throwaway repositories. Every fake secret or
personal detail is assembled at run time from fragments, so this repository passes its own
hooks without allowlisting `tests/`. Test values are obviously fake or reserved for
examples; `tests/support.py` lists them.

When Dependabot updates the pinned action in `.github/workflows/visibility-guard.yml`, copy
the change to `templates/visibility-guard-public.yml`; a test checks that the two match.

See [CHANGELOG.md](CHANGELOG.md) for changes between versions.

## Licence

MIT. See [LICENSE](LICENSE).
