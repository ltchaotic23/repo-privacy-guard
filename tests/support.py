"""Shared helpers for the tests.

Every fake secret and personal detail is assembled at run time from fragments that don't
match any rule on their own. That way this repository's own hooks (and GitHub push
protection) don't flag the test files, and no allowlist entry for tests/ is needed.

Test data uses values reserved for examples, which the default config ignores. Tests that
need them reported use STRICT, the default config with settings.report_examples = true:
  - phone numbers from Ofcom's drama ranges (07700 900xxx, 020 7946 0xxx) and North
    America's fictional 555-0100 to 555-0199
  - example.com, example.net and example.org addresses
  - documentation IP ranges (192.0.2.x, 198.51.100.x, 203.0.113.x, 2001:db8::)
  - the placeholder postcode ZZ99 9ZZ and the username "exampleuser"
  - fake tokens that are obviously fake, and AWS's own documentation example keys
The one exception is in test_rules.PublicAddresses: checking that a genuinely public IP
address counts as public needs one, so it uses AS112 addresses, which are reserved by
IANA for a public DNS sink service (RFC 7534, RFC 7535) and belong to no one.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / ".githooks"
sys.path.insert(0, str(HOOKS))

import privacy_guard as pg  # noqa: E402

CONFIG = pg.load_config(HOOKS / "privacy-guard.toml")
STRICT = dataclasses.replace(CONFIG, report_examples=True)


def j(*parts: str) -> str:
    """Join fragments into one fake value."""
    return "".join(parts)


def snowflake(year: int) -> str:
    """A Discord-style ID created at the start of the given year."""
    ms = int(datetime(year, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)
    return str(((ms - pg.DISCORD_EPOCH_MS) << 22) | 0x2A5)


FAKE_GITHUB_TOKEN = j("gh", "p_", "A1b2" * 9)
FAKE_HOME_PATH = j("C:", "\\Users\\", "exampleuser", "\\Documents\\notes.txt")
FAKE_EMAIL = j("exampleuser", "@", "example.com")
FAKE_PHONE = j("+44 7700 ", "900123")
NOREPLY = "test-user@users.noreply.github.com"


def rule_ids(text: str, cfg: pg.Config = CONFIG, path: str | None = None) -> set[str]:
    return {rule.id for rule in pg.find_rules(text, cfg, path)}


def file_rule_ids(path: str, cfg: pg.Config = CONFIG) -> set[str]:
    return {rule.id for rule in pg.find_file_rules(path, cfg)}


class GitSandbox:
    """A throwaway git repository, isolated from the user's own git config."""

    def __init__(self, name: str = "work") -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="privacy-guard-test-"))
        empty = self.tmp / "empty-gitconfig"
        empty.write_text("")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update({
            "GIT_CONFIG_GLOBAL": str(empty),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "PRIVACY_GUARD_DEBUG": "",
        })
        self.global_config = empty
        self.repo = self.tmp / name
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Test User")
        self.git("config", "user.email", NOREPLY)
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")
        self.git("config", "core.autocrlf", "false")

    def run(self, *args: str, cwd: Path | None = None, stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(list(args), cwd=cwd or self.repo, env=self.env, input=stdin,
                              capture_output=True, text=True, encoding="utf-8", errors="replace")

    def git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        proc = self.run("git", *args)
        if check and proc.returncode != 0:
            raise AssertionError(f"git {' '.join(args)} failed:\n{proc.stdout}\n{proc.stderr}")
        return proc

    def install(self, *extra: str) -> subprocess.CompletedProcess:
        return self.run(sys.executable, str(ROOT / "install.py"), str(self.repo), *extra)

    def report_examples(self) -> None:
        """Make the installed config report reserved example values, as STRICT does."""
        self.edit_config("report_examples = false", "report_examples = true")

    def edit_config(self, old: str, new: str) -> None:
        config = self.repo / ".githooks" / "privacy-guard.toml"
        text = config.read_text(encoding="utf-8")
        assert old in text, old
        config.write_text(text.replace(old, new, 1), encoding="utf-8")

    def commit_guard(self) -> None:
        """Commit the installed guard, so the hooks read their config from git."""
        self.git("add", "--", ".githooks")
        # --no-verify: the config's own comments mention reserved example values.
        self.git("commit", "-q", "--no-verify", "-m", "add the guard")

    def history(self) -> subprocess.CompletedProcess:
        return self.run(sys.executable, str(self.repo / ".githooks" / "privacy_guard.py"), "history")

    def write(self, name: str, text: str) -> None:
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))

    def commit(self, name: str, text: str, message: str = "change", *flags: str) -> subprocess.CompletedProcess:
        self.write(name, text)
        self.git("add", "--", name)
        return self.git("commit", "-q", "-m", message, *flags, check=False)

    def bare_remote(self) -> Path:
        remote = self.tmp / "remote.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)],
                       env=self.env, check=True, capture_output=True)
        self.git("remote", "add", "origin", str(remote))
        return remote

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    def cleanup(self) -> None:
        def unlock(func, path, _exc):  # git marks objects read-only on Windows
            os.chmod(path, 0o700)
            func(path)
        if sys.version_info >= (3, 12):
            shutil.rmtree(self.tmp, onexc=unlock)
        else:
            shutil.rmtree(self.tmp, onerror=unlock)


FAKES = (FAKE_GITHUB_TOKEN, FAKE_HOME_PATH, FAKE_EMAIL, FAKE_PHONE, "exampleuser")


class HookTestCase(unittest.TestCase):
    """A sandbox with the guard installed. The test data is reserved example values, so
    these sandboxes report examples."""

    def setUp(self) -> None:
        self.box = GitSandbox()
        self.addCleanup(self.box.cleanup)
        result = self.box.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.box.report_examples()

    def assert_no_values(self, proc) -> None:
        output = proc.stdout + proc.stderr
        for value in FAKES:
            self.assertNotIn(value, output, "the guard must never print matched text")
