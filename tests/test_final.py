"""Hardening from the final review round: tags on files, many remote refs, force-push
rollbacks, signature blocks, binary detection, accepted commits, hook arguments, and
commit messages written through an editor."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
import unittest

from support import (CONFIG, FAKE_EMAIL, FAKE_GITHUB_TOKEN, ROOT, STRICT, HookTestCase, j, pg,
                     rule_ids)

TOKEN_LINE = j('TOKEN = "', FAKE_GITHUB_TOKEN, '"\n')
OTHER_TOKEN = j("gh", "p_", "B2c3" * 9)
CUT = "# ------------------------ >8 ------------------------"


def git_version(box) -> tuple[int, ...]:
    text = box.git("version").stdout.split()[2]
    return tuple(int(part) for part in text.split(".")[:2] if part.isdigit())


class Tags(HookTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.box.bare_remote()
        self.assertEqual(self.box.commit("README.md", "# Demo\n", "first").returncode, 0)
        self.assertEqual(self.box.git("push", "-q", "origin", "main", check=False).returncode, 0)
        self.blob = self.box.run("git", "hash-object", "-w", "--stdin", stdin=TOKEN_LINE).stdout.strip()

    def test_annotated_tag_on_a_blob_is_scanned_on_push(self) -> None:
        self.box.git("tag", "-a", "v-blob", "-m", "Harmless", self.blob)
        proc = self.box.git("push", "-q", "origin", "v-blob", check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_tag_chain_ending_in_a_blob_is_scanned(self) -> None:
        self.box.git("tag", "-a", "v-blob", "-m", "Harmless", self.blob)
        self.box.git("tag", "-a", "v-nested", "-m", "Also harmless", "v-blob")
        proc = self.box.git("push", "-q", "origin", "v-nested", check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_annotated_tag_on_a_blob_is_scanned_in_history(self) -> None:
        self.box.git("tag", "-a", "v-blob", "-m", "Harmless", self.blob)
        proc = self.box.history()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("github-token", proc.stderr)

    def test_accepted_tag_is_left_out(self) -> None:
        self.box.git("tag", "-a", "v1.0", "-m", j("token ", FAKE_GITHUB_TOKEN))
        self.assertEqual(self.box.history().returncode, 1)
        tag = self.box.git("rev-parse", "v1.0").stdout.strip()
        self.box.edit_config("commits = []", f"commits = ['{tag}']")
        proc = self.box.history()
        self.assertEqual(proc.returncode, 0, proc.stderr)


class Pushes(HookTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.box.bare_remote()

    def push(self, *args: str):
        return self.box.git("push", "-q", *args, check=False)

    def test_force_push_rollback_to_a_secret_is_blocked(self) -> None:
        self.box.commit("app.py", TOKEN_LINE, "B secret", "--no-verify")
        with_secret = self.box.head()
        self.box.commit("app.py", 'TOKEN = os.environ["TOKEN"]\n', "C clean", "--no-verify")
        self.assertEqual(self.push("--no-verify", "origin", "main").returncode, 0)
        self.box.git("reset", "-q", "--hard", with_secret)
        proc = self.push("--force", "origin", "main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_many_remote_refs(self) -> None:
        # 900 commits and tags made in one go with fast-import, then a clean new branch.
        self.box.commit("README.md", "# Demo\n", "first", "--no-verify")
        stream = []
        for n in range(900):
            message = f"c{n}"
            stream.append(f"commit refs/heads/main\ncommitter Test <test@users.noreply.github.com> "
                          f"{1700000000 + n} +0000\ndata {len(message)}\n{message}\n")
            if n == 0:
                stream.append("from refs/heads/main^0\n")
            stream.append(f"\nreset refs/tags/t{n}\nfrom refs/heads/main\n\n")
        # Bytes, so that Windows doesn't turn the newlines into CRLF.
        proc = subprocess.run(["git", "fast-import", "--quiet"], cwd=self.box.repo, env=self.box.env,
                              input="".join(stream).encode(), capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
        self.assertEqual(self.push("--no-verify", "origin", "main", "--tags").returncode, 0)
        self.box.git("switch", "-q", "-c", "feature")
        self.box.git("reset", "-q", "--hard", "main")
        self.assertEqual(self.box.commit("feature.txt", "clean\n", "feature").returncode, 0)
        proc = self.push("origin", "feature")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_accepted_commit_suppresses_only_its_own_value(self) -> None:
        self.box.commit_guard()
        self.box.commit("app.py", TOKEN_LINE, "accepted token", "--no-verify")
        accepted = self.box.head()
        self.box.edit_config("commits = []", f"commits = ['{accepted}']")
        self.box.git("add", ".githooks/privacy-guard.toml")
        self.box.git("commit", "-q", "--no-verify", "-m", "accept")
        accept_commit = self.box.head()
        self.box.commit("app.py", "TOKEN = None\n", "remove", "--no-verify")
        self.assertEqual(self.push("--no-verify", "origin", "main").returncode, 0)
        self.box.git("switch", "-q", "-c", "side", accept_commit)
        self.box.commit("app.py", j('TOKEN = "', OTHER_TOKEN, '"\n'), "other token", "--no-verify")
        self.assertEqual(self.push("--no-verify", "origin", "side").returncode, 0)
        self.box.git("merge", "-q", "-s", "ours", "main", "-m", "merge")
        self.box.git("switch", "-q", "main")
        self.box.git("merge", "-q", "--ff-only", "side")
        proc = self.push("origin", "main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)


class History(HookTestCase):
    def test_custom_refs_are_scanned(self) -> None:
        self.box.commit("README.md", "# Demo\n", "first")
        self.box.commit("app.py", TOKEN_LINE, "leak", "--no-verify")
        self.box.git("update-ref", "refs/custom/kept", "HEAD")
        self.box.git("reset", "-q", "--hard", "HEAD~1")
        proc = self.box.history()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("github-token", proc.stderr)


class Signatures(unittest.TestCase):
    BODY = "iQEzBAABCAAdFiEEabcdefghijklmnopqrstuvwxyz0123456789ABCD\n=XyZ1"

    def test_well_formed_block_body_is_skipped_but_headers_are_scanned(self) -> None:
        message = j("Release\n\n-----BEGIN PGP SIGNATURE-----\nComment: ", FAKE_GITHUB_TOKEN,
                    "\n\n", self.BODY, "\n-----END PGP SIGNATURE-----\n")
        kept = pg.strip_signature(message)
        self.assertIn(FAKE_GITHUB_TOKEN, kept)
        self.assertNotIn("iQEzBAAB", kept)

    def test_block_without_a_blank_line_after_headers_is_not_skipped(self) -> None:
        message = j("Release\n\n-----BEGIN PGP SIGNATURE-----\nVersion: ", FAKE_EMAIL,
                    "\nAKIA", "IOSFODNN7EXAMPLE\n-----END PGP SIGNATURE-----\n")
        found = {f.rule_id for f in pg.scan_message(pg.strip_signature(message), STRICT, "tag")}
        self.assertTrue({"email", "aws-access-key-id"} <= found)


class BinaryDetection(unittest.TestCase):
    HEADER = "diff --git a/app.txt b/app.txt\nindex 1111111..2222222 100644\n--- a/app.txt\n+++ b/app.txt\n"

    def added(self, diff: str, is_binary=None) -> list[str]:
        events = pg.parse_diff(diff.splitlines(keepends=True), is_binary)
        return [e.text for e in events if isinstance(e, pg.LineEvent)]

    def test_late_nul_in_another_hunk_keeps_earlier_lines(self) -> None:
        diff = self.HEADER + "@@ -6,0 +6 @@\n+" + TOKEN_LINE + "@@ -182,0 +183 @@\n+late\x00byte\n"
        self.assertIn(TOKEN_LINE.strip(), self.added(diff, lambda blob: False))

    def test_nul_beyond_the_first_bytes_of_a_long_line(self) -> None:
        line = TOKEN_LINE.strip() + "x" * 9990 + "\x00" + "y" * 2000
        diff = self.HEADER + "@@ -0,0 +1 @@\n+" + line + "\n"
        self.assertEqual(len(self.added(diff)), 1)

    def test_blob_check_decides_when_available(self) -> None:
        diff = self.HEADER + "@@ -0,0 +1 @@\n+" + TOKEN_LINE
        self.assertEqual(self.added(diff, lambda blob: True), [])
        self.assertEqual(len(self.added(diff, lambda blob: False)), 1)


class SmallFixes(unittest.TestCase):
    def test_hook_shims_end_options_before_arguments(self) -> None:
        self.assertIn('push -- "$@"', (ROOT / ".githooks" / "pre-push").read_text(encoding="utf-8"))
        self.assertIn('commit-msg -- "$1"', (ROOT / ".githooks" / "commit-msg").read_text(encoding="utf-8"))

    def test_byte_order_mark_in_a_message(self) -> None:
        found = {f.rule_id for f in pg.scan_message(j("\ufeffAPI_KEY=", "abc123def456ghi789"), STRICT, "m")}
        self.assertIn("env-style-secret", found)

    def test_marker_needs_a_left_boundary(self) -> None:
        self.assertIn("email", rule_ids(j(FAKE_EMAIL, " # not-privacy-guard:allow"), STRICT))

    def test_length_based_allowlist_patterns_are_too_broad(self) -> None:
        for key, pattern in (("values", ".{10}"), ("values", "[A-Za-z0-9]{8}"), ("paths", ".{14}"),
                             ("commit_emails", "@.{5,}")):
            with self.subTest(key=key, pattern=pattern):
                data = {"version": 1, "allowlist": {key: [pattern]}, "rules": [
                    {"id": "demo", "category": "secret", "description": "demo", "regex": "demo-[0-9]+"}]}
                with self.assertRaisesRegex(pg.ConfigError, "matches almost anything"):
                    pg.parse_config(data)


class CommitMessagesThroughAnEditor(HookTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.box.env["GIT_EDITOR"] = "true"   # an editor that leaves the message as it is
        self.assertEqual(self.box.commit("README.md", "# Demo\n", "first").returncode, 0)

    def stage_change(self) -> None:
        self.box.write("README.md", "# Demo\n\nMore text.\n")
        self.box.git("add", "README.md")

    def editor_commit(self, *args: str):
        return self.box.git("commit", "-q", "-e", *args, check=False)

    def test_double_verbose_commit_is_not_blocked(self) -> None:
        self.stage_change()
        self.box.write("notes.txt", "unstaged\n")
        self.box.git("add", "notes.txt")
        self.box.git("commit", "-q", "--no-verify", "-m", "notes")
        self.box.write("README.md", "# Demo\n\nEven more text.\n")
        self.box.git("add", "README.md")
        self.box.write("notes.txt", "changed but not staged\n")
        proc = self.editor_commit("-v", "-v", "-m", "Update the readme")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_scissors_cleanup_with_verbose_is_not_blocked(self) -> None:
        self.box.git("config", "commit.cleanup", "scissors")
        self.stage_change()
        proc = self.editor_commit("-v", "-m", "Update the readme")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_two_character_comment_string(self) -> None:
        if git_version(self.box) < (2, 45):
            self.skipTest("core.commentString needs git 2.45 or newer")
        self.box.git("config", "core.commentString", "//")
        self.stage_change()
        self.box.write(j("export-", FAKE_EMAIL, ".csv"), "untracked\n")
        proc = self.editor_commit("-v", "-m", "Update the readme")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_untracked_file_names_in_git_comments_are_not_blocked(self) -> None:
        self.stage_change()
        self.box.write(j("export-", FAKE_EMAIL, ".csv"), "untracked\n")
        proc = self.editor_commit("-m", "Update the readme")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_pasted_scissors_block_in_a_plain_editor_commit_is_scanned(self) -> None:
        self.stage_change()
        message = self.box.repo / "message.txt"
        message.write_text(j("Update the readme\n", CUT, "\n# Do not modify or remove the line above.\n",
                             "# Everything below it will be ignored.\n",
                             "diff --git a/other.txt b/other.txt\n", TOKEN_LINE), encoding="utf-8")
        proc = self.editor_commit("-F", str(message))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)

    def test_verbatim_cleanup_scans_comment_lines(self) -> None:
        self.box.git("config", "commit.cleanup", "verbatim")
        self.stage_change()
        message = self.box.repo / "message.txt"
        message.write_text(j("Update the readme\n# token: ", FAKE_GITHUB_TOKEN, "\n"), encoding="utf-8")
        proc = self.editor_commit("-F", str(message))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)


if __name__ == "__main__":
    unittest.main()
