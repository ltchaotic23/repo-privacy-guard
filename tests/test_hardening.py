"""Hardening found in the second review round: inline markers, commit messages, pushes,
tags, diff parsing and the command-line flags."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import (CONFIG, FAKE_EMAIL, FAKE_GITHUB_TOKEN, NOREPLY, STRICT, HookTestCase, j, pg,
                     rule_ids)

HOME = j("C:", "\\Users\\", "exampleuser", "\\notes.txt")
TOKEN_LINE = j('TOKEN = "', FAKE_GITHUB_TOKEN, '"\n')


def scan_lines(lines: list[str], cfg: pg.Config = STRICT, path: str = "notes.md") -> list[pg.Finding]:
    events = [pg.LineEvent("", path, n, text) for n, text in enumerate(lines, 1)]
    return pg.scan_events(events, cfg)


class InlineMarkers(unittest.TestCase):
    def test_malformed_markers_have_no_effect(self) -> None:
        for marker in ("privacy-guard:allow = home-path-windows", "privacy-guard:allow= home-path-windows",
                       "privacy-guard:allow=Home-Path-Windows", "privacy-guard:allow=<rule-id>",
                       "privacy-guard:allow=", "privacy-guard:allowlist", "privacy-guard:allow='email'"):
            with self.subTest(marker=marker):
                self.assertIn("home-path-windows", rule_ids(f"{HOME} {FAKE_EMAIL} # {marker}", STRICT))
                self.assertIn("email", rule_ids(f"{HOME} {FAKE_EMAIL} # {marker}", STRICT))

    def test_well_formed_markers_still_work(self) -> None:
        line = f"{HOME} {FAKE_EMAIL}"
        self.assertEqual(rule_ids(line + " <!-- privacy-guard:allow=home-path-windows -->", STRICT), {"email"})
        self.assertEqual(rule_ids(line + " /* privacy-guard:allow */", STRICT), set())

    def test_markers_never_hide_secrets(self) -> None:
        for marker in ("privacy-guard:allow", "privacy-guard:allow=github-token",
                       "privacy-guard:allow=github-token,secret-assignment"):
            with self.subTest(marker=marker):
                self.assertIn("github-token", rule_ids(f"{TOKEN_LINE.strip()}  # {marker}", STRICT))

    def test_problem_markers_print_a_warning(self) -> None:
        cases = {
            "privacy-guard:allow= email": "malformed",
            "privacy-guard:allow=e-mail": "unknown rule",
            "privacy-guard:allow=github-token": "can't hide secret",
        }
        for marker, words in cases.items():
            with self.subTest(marker=marker):
                findings = scan_lines([f"{FAKE_EMAIL} {TOKEN_LINE.strip()} # {marker}"])
                notes = [f for f in findings if f.rule_id == "inline-marker"]
                self.assertEqual(len(notes), 1)
                self.assertEqual(notes[0].severity, "warn")
                self.assertIn(words, notes[0].description)

    def test_no_warning_when_the_line_has_no_findings(self) -> None:
        findings = scan_lines(["Use `privacy-guard:allow=<rule-id>` on the line."])
        self.assertEqual(findings, [])

    def test_markers_are_ignored_in_messages(self) -> None:
        found = {f.rule_id for f in pg.scan_message(
            j("temp: ", FAKE_GITHUB_TOKEN, " privacy-guard:allow=github-token\n",
              FAKE_EMAIL, " privacy-guard:allow"), STRICT, "commit message")}
        self.assertTrue({"github-token", "email"} <= found)


class DiffParsing(unittest.TestCase):
    def test_nul_in_a_deleted_line_does_not_hide_added_lines(self) -> None:
        diff = ("diff --git a/app.cfg b/app.cfg\nindex 1..2 100644\n--- a/app.cfg\n+++ b/app.cfg\n"
                "@@ -1 +1 @@\n-old\x00header\n+" + TOKEN_LINE)
        added = [e for e in pg.parse_diff(diff.splitlines(keepends=True)) if isinstance(e, pg.LineEvent)]
        self.assertEqual([e.text for e in added], [TOKEN_LINE.strip()])

    def test_byte_order_mark_on_line_one_is_ignored(self) -> None:
        diff = ("diff --git a/config.yaml b/config.yaml\nnew file mode 100644\nindex 0..1\n"
                "--- /dev/null\n+++ b/config.yaml\n@@ -0,0 +1 @@\n+\ufeffapi_key: " + "FakeSecret" + "123456\n")
        events = list(pg.parse_diff(diff.splitlines(keepends=True)))
        found = {f.rule_id for f in pg.scan_events(events, STRICT)}
        self.assertIn("config-secret", found)


class CommandLine(HookTestCase):
    def guard(self, *args: str):
        return self.box.run(sys.executable, str(self.box.repo / ".githooks" / "privacy_guard.py"), *args)

    def test_strict_flag_makes_warnings_block(self) -> None:
        self.box.edit_config("report_examples = true", "report_examples = false")
        self.box.commit("contact.txt", j("Phone: +44 7700 ", "900123\n"), "contact", "--no-verify")
        self.assertEqual(self.guard("history").returncode, 0)
        self.assertEqual(self.guard("history", "--report-examples").returncode, 0)
        self.assertEqual(self.guard("history", "--report-examples", "--strict").returncode, 1)


class CommitMessagesFailClosed(HookTestCase):
    def test_hash_lines_kept_by_dash_m_are_scanned(self) -> None:
        proc = self.box.commit("a.txt", "a\n", j("# Release notes\n# Token: ", FAKE_GITHUB_TOKEN))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_text_below_scissors_in_a_message_file_is_scanned(self) -> None:
        message = self.box.repo / "message.txt"
        message.write_text(j("Add the parser\n\n# ------------------------ >8 ------------------------\n",
                             "token: ", FAKE_GITHUB_TOKEN, "\n"), encoding="utf-8")
        self.box.write("a.txt", "a\n")
        self.box.git("add", "a.txt")
        proc = self.box.git("commit", "-q", "-F", str(message), check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_marker_in_a_message_does_not_hide_a_secret_from_history(self) -> None:
        self.box.commit("README.md", "start\n", "start")
        self.box.git("commit", "-q", "--allow-empty", "--no-verify", "-m",
                     j("Tidy up\n\ntemp: ", FAKE_GITHUB_TOKEN, " privacy-guard:allow=github-token"))
        proc = self.box.history()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("commit message line 3", proc.stderr)

    def test_verbose_editor_commit_can_remove_a_secret(self) -> None:
        self.box.commit("app.py", TOKEN_LINE, "add", "--no-verify")
        self.box.write("app.py", "TOKEN = None\n")
        self.box.git("add", "app.py")
        self.box.env["GIT_EDITOR"] = "true"   # an editor that leaves the message as it is
        proc = self.box.git("commit", "-q", "-v", "-e", "-m", "Remove the token", check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)


class PushAndTags(HookTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.remote = self.box.bare_remote()
        self.assertEqual(self.box.commit("README.md", "# Demo\n", "first").returncode, 0)

    def push(self, *args: str):
        return self.box.git("push", "-q", "origin", *args, check=False)

    def test_new_branch_and_tag_skip_commits_the_remote_has(self) -> None:
        self.box.git("config", "user.email", FAKE_EMAIL)
        self.box.commit("legacy.txt", "legacy\n", "legacy", "--no-verify")
        self.box.git("config", "user.email", NOREPLY)
        self.box.commit("old.py", TOKEN_LINE, "old token", "--no-verify")
        self.assertEqual(self.box.git("push", "-q", "--no-verify", "origin", "main").returncode, 0)
        self.box.git("switch", "-q", "-c", "feature")
        self.assertEqual(self.box.commit("feature.txt", "clean\n", "feature").returncode, 0)
        proc = self.push("feature")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.box.git("tag", "v1.0.0")
        proc = self.push("v1.0.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_new_branch_is_checked_against_the_push_url(self) -> None:
        # The fetch URL has the commit, the push URL doesn't: only the push URL counts.
        self.box.commit("old.py", TOKEN_LINE, "old token", "--no-verify")
        self.assertEqual(self.box.git("push", "-q", "--no-verify", "origin", "main").returncode, 0)
        push_only = self.box.tmp / "push-only.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(push_only)],
                       env=self.box.env, check=True, capture_output=True)
        self.box.git("remote", "set-url", "--push", "origin", str(push_only))
        self.box.git("switch", "-q", "-c", "feature")
        self.assertEqual(self.box.commit("feature.txt", "clean\n", "feature").returncode, 0)
        proc = self.push("feature")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_accepted_commit_is_accepted_on_push(self) -> None:
        self.box.commit_guard()
        self.assertEqual(self.box.git("push", "-q", "--no-verify", "origin", "main").returncode, 0)
        self.box.commit("app.py", TOKEN_LINE, "token", "--no-verify")
        accepted = self.box.head()
        self.box.edit_config("commits = []", f"commits = ['{accepted}']")
        self.box.git("add", ".githooks/privacy-guard.toml")
        self.box.git("commit", "-q", "--no-verify", "-m", "accept")
        proc = self.push("main")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_allowlisted_commit_is_accepted(self) -> None:
        self.box.commit("old.py", TOKEN_LINE, "old token", "--no-verify")
        accepted = self.box.head()
        self.box.commit("old.py", "TOKEN = None\n", "remove", "--no-verify")
        self.assertEqual(self.box.history().returncode, 1)
        self.box.edit_config("commits = []", f"commits = ['{accepted}']")
        proc = self.box.history()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_content_resurrected_by_merge_ours_is_blocked(self) -> None:
        self.box.commit("app.py", TOKEN_LINE, "add secret", "--no-verify")
        with_secret = self.box.head()
        self.box.commit("app.py", 'TOKEN = os.environ["TOKEN"]\n', "remove secret")
        self.assertEqual(self.box.git("push", "-q", "--no-verify", "origin", "main").returncode, 0)
        self.box.git("switch", "-q", "-c", "side", with_secret)
        self.box.git("merge", "-q", "-s", "ours", "main", "-m", "merge")
        self.box.git("switch", "-q", "main")
        self.box.git("merge", "-q", "--ff-only", "side")
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)
        self.assert_no_values(proc)

    def test_annotated_tag_pushed_by_sha(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        self.box.git("tag", "-a", "v1.0", "-m", j("token ", FAKE_GITHUB_TOKEN))
        sha = self.box.git("rev-parse", "v1.0").stdout.strip()
        proc = self.push(f"{sha}:refs/tags/release-v1.0")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("tag release-v1.0 message", proc.stderr)

    def test_fake_signature_header_does_not_hide_a_tag_message(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        self.box.git("tag", "-a", "v2.0", "-m",
                     j("Release v2.0\n\n-----BEGIN PGP SIGNATURE-----\n", FAKE_GITHUB_TOKEN))
        proc = self.push("v2.0")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_tag_pointing_at_a_blob(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        blob = self.box.run("git", "hash-object", "-w", "--stdin", stdin=TOKEN_LINE).stdout.strip()
        self.box.git("tag", "blobtag", blob)
        proc = self.push("blobtag")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_bom_on_line_one_is_scanned(self) -> None:
        (self.box.repo / "config.yaml").write_bytes(
            b"\xef\xbb\xbfapi_key: " + j("FakeSecret", "Value123456").encode() + b"\n")
        self.box.git("add", "config.yaml")
        proc = self.box.git("commit", "-q", "-m", "config", check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("config-secret", proc.stderr)


class ConfigLoading(HookTestCase):
    def test_config_removed_from_the_index_falls_back_to_head(self) -> None:
        self.box.commit_guard()
        self.box.git("rm", "-q", "--cached", ".githooks/privacy-guard.toml")
        self.box.edit_config("paths = []", "paths = ['^app[.]py$']")
        proc = self.box.commit("app.py", TOKEN_LINE)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_unreadable_config_message_does_not_show_the_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "secret-folder-name" / "privacy-guard.toml"
            folder.mkdir(parents=True)   # a folder where the file should be
            with self.assertRaises(pg.ConfigError) as caught:
                pg.load_config(folder)
            self.assertNotIn("secret-folder-name", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
