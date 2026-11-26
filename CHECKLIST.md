# Ready to publish?

A checklist for the moments before your code leaves your machine. The hooks and workflow in
this kit check some of it for you; the rest needs a person. Work through the gate that
matches what you're about to do. If any box isn't ticked, you're not ready yet.

## Gate 1: before you commit

Anything you commit is hard to take back. It stays in the history, in every clone and in
every backup, even after a later commit deletes it.

- [ ] Stage files by name (`git add path/to/file`), then read `git diff --cached`. Avoid
      `git add .` and `git add -A`: they pick up stray files.
- [ ] Nothing secret is staged: API keys, tokens, passwords, private keys, `.env` files,
      Terraform state or credentials files. *(The pre-commit hook checks this.)*
- [ ] No personal details are staged: your name, email address, home-folder paths, phone
      numbers, address or postcode, IP addresses or account IDs. Look hardest at sample
      data, test fixtures, screenshots, logs and generated reports, because that's where
      real data slips in. Use values reserved for examples instead: `example.com`
      addresses, the documentation IP ranges `192.0.2.0/24` and `2001:db8::/32`, phone
      numbers reserved for fiction (North America's `555-0100` to `555-0199`, or the UK's
      `07700 900000` to `07700 900999`; many countries have their own), the UK placeholder
      postcode `ZZ99 9ZZ` and plainly made-up names. *(The hook checks the common patterns,
      not names or screenshots, and lets these reserved values through.)*
- [ ] `.gitignore` covers environment files (`.env*`), virtual environments, caches, build
      output and local data folders. Check with `git status --ignored`.
- [ ] The commit email is the one you mean to publish. On GitHub that's usually your
      `noreply` address (`git config user.email`). *(The hook checks this.)*
- [ ] The tests pass, or the commit message says the work is unfinished.

## Gate 2: before you push or create a repository

Everything in Gate 1, plus:

- [ ] Scan the whole history, not just the latest version:
      `python .githooks/privacy_guard.py history`, and a dedicated secret scanner such as
      gitleaks if you have one. Read the warnings as well as the blocking findings.
      *(The pre-push hook scans the commits and tags being pushed.)*
- [ ] Every commit's author and committer email is one you're happy to publish:
      `git log --all --format="%h %ae %ce"`. Check tag messages and tagger emails too.
- [ ] Read every commit message you're about to push: `git log origin/main..HEAD`, or the
      whole log for a new repository.
- [ ] Clone the repository into a temporary folder, set it up using only the README, and
      run the tests. This catches files that exist only on your machine and steps the
      README leaves out.
- [ ] Create the repository as **private** first, and look it over on GitHub (files,
      README, commit list) before anything else.
- [ ] Turn on secret scanning and push protection in the repository's security settings.
- [ ] If the repository must never be public, add the stay-private visibility guard.

## Gate 3: before you make a repository public

Everything above, plus:

**Privacy**

- [ ] No personal details anywhere: code, docs, examples, test data, issue templates,
      commit authors and commit messages.
- [ ] `python .githooks/privacy_guard.py history --strict` passes, so warnings count too.
      Allowlist what turns out to be harmless.
- [ ] The README says what data the tool sends where (which services, APIs or AI providers
      see what), or says that it sends nothing.

**Security**

- [ ] `SECURITY.md` explains how to report a vulnerability privately, for example through
      GitHub's private vulnerability reporting (turn it on in the security settings).
- [ ] Workflows use least-privilege `permissions:` and pin actions to full commit SHAs.
- [ ] Dependencies are pinned and have no known vulnerabilities (Dependabot alerts,
      `pip-audit`, `npm audit`).
- [ ] Nothing runs or downloads anything unexpectedly, and any network calls are documented.
- [ ] The going-public visibility guard (the full-history scan) passes on GitHub.

**Does it actually work?**

- [ ] You've tried it on real inputs, not just test data, and you're happy with the output.
- [ ] The README matches what the tool does today, including its limits and what hasn't
      been tested.
- [ ] Someone else could install and run it from the README alone.

When every box is ticked, change the visibility yourself: **Settings → General → Danger
Zone → Change visibility**.

## If something leaks anyway

1. Revoke or rotate the secret first. Deleting it from the history doesn't undo the leak:
   assume it was copied as soon as it was pushed.
2. Then remove it from the history (for example with `git filter-repo`), force-push, and
   ask the hosting service's support team to clear cached copies if the repository was
   public.
