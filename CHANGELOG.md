# Changelog

## 0.2.0 (unreleased)

The first public release. Before release it went through several rounds of independent
review and testing, and the changes that came out of those rounds are listed under
"Hardening before release" and "Fixed before release".

### Features
- `commit-msg` hook, installed by `install.py`, so a secret or personal detail in a commit
  message is usually caught at commit time rather than at push (pre-push and the history
  scan stay the checks to rely on). Without an editor it scans `#` lines too, because git
  keeps them; when git opens an editor it follows `commit.cleanup` and the comment
  character, and leaves out git's own comment lines and its `commit -v` diff.
- Severity tiers. Secret rules always block. Phone numbers, UK postcodes, public IPv4 and
  IPv6 addresses and Discord-style IDs warn by default; `strict = true` makes every rule
  block.
- `--strict` and `--report-examples` command-line flags. The going-public workflow fails on
  blocking rules on every push and pull request, and has a `strict` input for runs started
  by hand.
- Scoped inline markers: `privacy-guard:allow=<rule-id>[,<rule-id>]`. Markers only ever
  hide personal rules, never secrets, and have no effect in commit or tag messages. A
  malformed marker, an unknown rule id or a marker naming a secret rule has no effect and
  prints a warning.
- `[allowlist] commits`, for old commits whose findings you accept.
- Annotated tags are scanned on push and in the history scan (tag message and tagger email),
  whatever ref name they are pushed under; so are refs and tags (or chains of tags) that
  point at a file.
- New rules: Discord webhook URLs (also versioned `/api/v10/` ones), Telegram bot tokens,
  PyPI tokens, `.npmrc` credentials, unquoted secrets in YAML, `.properties`, INI, TOML and
  Compose files, Dockerfile `ENV`/`ARG` secrets (also `ENV KEY value` and lower-case
  names), secrets in XML elements such as `<password>`, `*.tfvars` and
  `keystore.properties` / `signing.properties` files.
- Rule options `severity`, `ignore_before` and `paths`.
- `install.py --uninstall`, a checksum manifest (`privacy-guard.sha256`) and advice on
  `.gitattributes` line endings for all the guard's files.

### Hardening before release
- The hooks read the config as staged (pre-commit, commit-msg; the copy in `HEAD` if it has
  been removed from the index) or committed in `HEAD` (pre-push), so edits that aren't
  staged or committed are ignored.
- A push counts commits as already on the remote only if the remote's own tips contain
  them: those git reports for the push and, for a new branch or tag, those
  `git ls-remote` reports for the URL the push goes to. Local remote-tracking branches are
  never trusted for this.
- Pushes also check what the pushed trees contain: every file name, and every line that
  differs from the remote tips they build on (and, for a force push, from the tip being
  replaced), so a file or a line brought back by a merge or a rollback is caught.
- Pushes pass revisions to git on standard input and check ancestry in batches, so a
  remote with hundreds of branches and tags works.
- `[allowlist] commits` leaves out only the accepted commit's own findings (by file, rule
  and value), so the same file can't later bring in a different secret under its cover.
- The hook scripts pass `--` before git's arguments, and the binary check looks at the
  first 8,000 bytes of each file, as git does.
- Files marked `-diff` or `binary` in `.gitattributes` are scanned when they are really text.
- `[allowlist] values` are matched against the value found, not the whole match.
- Allowlist entries that would match almost anything (such as `'.'`, `'/'`, `'.{4}'`,
  `'[0-9]{2}'` or `'@'`) are rejected.
- Findings list blocking secrets first, then other blocking findings, then warnings.
- The history scan covers every ref (custom `refs/*` and notes included) except the local
  stash, and ignores `git replace` substitutions.
- The going-public workflow runs the base branch's scanner and rules on pull requests, fails
  if the pull request's own config doesn't load (it only warns when the pull request also
  upgrades `privacy_guard.py`), and checks for Python 3.11 or newer. The workflow file
  itself still comes from the pull request; see the README's Limits. The stay-private
  workflow checks the `visibility` field, so `internal` repositories count as not private.
- Fewer false alarms: CSS colours, version numbers (including `<AssemblyVersion>`) and
  object identifiers, web routes such as `/home/...` and `/Users/...` in router, `fetch`,
  `href` and `<Link to>` calls, systemd unit names, round numbers, local development
  database URLs, signed decimals read as phone numbers, `sk-` CSS class names, trailing
  punctuation after a placeholder path, and config keys that only describe a secret
  (`secretName`, `secretKeyRef`, `..._FILE`, `..._path`, `...endpoint`, `...encoder`,
  `...issuer`, `...audience`, `...region`, `...encoding`, `...regex`, `...scope`, `...hash`,
  `...version` and similar) or whose value is a file path or a kebab-case resource name.
  Checked against a corpus of 43 noisy snippets, now a regression test: `sk-` class names
  in `clsx()` and similar helpers; route declarations (`@GetMapping`, Flask and Django
  routes, React Router objects, ingress `- path:`, `href=`/`to=` on their own line);
  Dockerfile `WORKDIR` and common container usernames; `@2x` assets, `npm:pkg@version`,
  `theme@dark.css` and one-letter `X@W`; postcodes with letters Royal Mail never uses, sizes
  and ordinals (`M1 8GB`, `Q1 1st`) and bare hex colours; versions after `appVersion`, an
  image name, Maven coordinates or a spaced `>=`, and object identifiers; quoted 10-digit
  IDs, dates and runs of powers of two (`256 512 1024`) read as phone numbers.
- More formats recognised: percent-encoded and empty-user URL passwords, secrets containing
  `$`, `<` or `>`, escaped quotes, backticks, Python `b"..."` and `r"..."` strings, suffixed
  names (`api_key_prod`, `secretValue`, `apiKeyLive`), `aws.secret.access.key`, config values
  with `#`, `,` or `;`, email addresses after `/`, hyphenated UK phone numbers, lower-case,
  mixed-case and non-breaking-space postcodes, upper-case `.ENV` and `.NPMRC` files, and
  Git Bash, Cygwin, file-URL and Java-properties Windows paths. `.env.<name>.example` files
  are treated as examples.
- `install.py` decodes git's output as UTF-8, ignores line endings when comparing files,
  refuses to overwrite hooks edited since they were installed, refuses to override a
  `core.hooksPath` from any other git config file without `--force`, never writes through a
  symbolic link or Windows junction (also in the folders on the way, such as `.github`),
  refuses a `core.hooksPath` set in a worktree's config or the environment and checks the
  effective value afterwards, accepts a trailing `\` in `core.hooksPath`, writes
  `privacy-guard.sha256` with Unix line endings, reports wrong file types without a
  traceback, leaves an identical workflow alone, ignores dot files in `.git/hooks`, and
  makes every check before writing anything.

### Fixed before release
- A commit message containing the byte 0x1e no longer stops the history and push scans.
- A line with a lone carriage return (old Mac line endings) is split into lines before
  scanning.
- A byte order mark at the start of a file no longer hides its first line from rules that
  look at the start of a line.
- A NUL byte in a removed line no longer makes the whole file count as binary, and a NUL
  byte late in a file no longer drops lines already scanned.
- A signature-like line inside a tag message no longer hides the rest of the message. Only
  the base64 body of a well-formed signature block at the very end is skipped; its header
  lines are scanned.
- An annotated tag pointing at a file, directly or through other tags, is no longer
  skipped on push or in the history scan.
- A force push back to an older commit is compared with the commit it replaces, so a
  secret removed since is caught.
- Pushing to a remote with many refs no longer fails on a long command line.
- The commit-msg hook no longer blocks on git's own comment lines with `commit -v -v`,
  `commit.cleanup = scissors`, a multi-character `core.commentString`, or untracked file
  names in git's status comments; and no longer misses text git keeps after a pasted
  scissors line or with `commit.cleanup = verbatim`.
- A byte order mark at the start of a commit message is ignored, and
  `privacy-guard:allow` inside a longer word (`not-privacy-guard:allow`) is no longer a
  marker.
- Allowlist patterns that only limit the length (such as `'.{10}'`) are rejected as too
  broad.
- `version = true` in the config is rejected, and config errors no longer show the full path.
- Email addresses at the top-level domains reserved for testing (`.test`, `.example`,
  `.invalid`, `.localhost`) count as examples, like `example.com`.
