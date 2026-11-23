"""End to end: real git commits and pushes in throwaway repositories, with the hooks installed."""

from __future__ import annotations

import sys
import unittest

from support import (CONFIG, FAKE_EMAIL, FAKE_GITHUB_TOKEN, FAKE_HOME_PATH, FAKE_PHONE, NOREPLY,
                     ROOT, GitSandbox, HookTestCase, j, pg)


class PreCommit(HookTestCase):
    def test_blocks_a_fake_token(self) -> None:
        proc = self.box.commit("app.py", j('TOKEN = "', FAKE_GITHUB_TOKEN, '"\n'))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("app.py:1", proc.stderr)
        self.assertIn("github-token", proc.stderr)
        self.assert_no_values(proc)
        self.assertNotEqual(self.box.git("rev-parse", "--verify", "HEAD", check=False).returncode, 0)

    def test_blocks_a_fake_home_path(self) -> None:
        proc = self.box.commit("notes/setup.md", j("line one\n", "log file: ", FAKE_HOME_PATH, "\n"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("notes/setup.md:2", proc.stderr)
        self.assertIn("home-path-windows", proc.stderr)
        self.assert_no_values(proc)

    def test_blocks_an_empty_env_file(self) -> None:
        proc = self.box.commit(".env", "")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("env-file", proc.stderr)

    def test_allows_a_clean_change(self) -> None:
        proc = self.box.commit("README.md", "# Demo\n\nNothing personal here.\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, "")

    def test_only_added_lines_are_scanned(self) -> None:
        self.box.commit("old.txt", j(FAKE_EMAIL, "\nkeep\n"), "seed", "--no-verify")
        proc = self.box.commit("old.txt", "keep\n", "remove the address")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_inline_allow_marker(self) -> None:
        proc = self.box.commit("doc.md", j("Contact ", FAKE_EMAIL, " <!-- privacy-guard:allow -->\n"))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_blocks_a_non_noreply_author_email(self) -> None:
        self.box.git("config", "user.email", FAKE_EMAIL)
        proc = self.box.commit("README.md", "hello\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("commit-email", proc.stderr)
        self.assert_no_values(proc)

    def test_missing_config_fails_closed(self) -> None:
        (self.box.repo / ".githooks" / "privacy-guard.toml").unlink()
        proc = self.box.commit("README.md", "hello\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("config", proc.stderr)

    def test_commit_all_uses_the_temporary_index(self) -> None:
        self.box.commit("app.py", "x = 1\n", "seed")
        self.box.write("app.py", j("x = 1\nhome = '", FAKE_HOME_PATH, "'\n"))
        proc = self.box.git("commit", "-q", "-a", "-m", "edit", check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("app.py:2", proc.stderr)

    def test_warnings_do_not_block(self) -> None:
        proc = self.box.commit("contact.txt", j("Phone: ", FAKE_PHONE, "\n"))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("phone-international", proc.stderr)
        self.assertIn("warning", proc.stderr.lower())
        self.assert_no_values(proc)

    def test_strict_makes_warnings_block(self) -> None:
        self.box.edit_config("strict = false", "strict = true")
        proc = self.box.commit("contact.txt", j("Phone: ", FAKE_PHONE, "\n"))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("phone-international", proc.stderr)


class CommitMessage(HookTestCase):
    def test_secret_in_commit_message_is_blocked(self) -> None:
        proc = self.box.commit("a.txt", "a\n", j("Rotate ", FAKE_GITHUB_TOKEN))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("commit message line 1", proc.stderr)
        self.assertIn("github-token", proc.stderr)
        self.assert_no_values(proc)

    def test_clean_message_passes(self) -> None:
        proc = self.box.commit("a.txt", "a\n", "Add the parser")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_comment_lines_are_scanned(self) -> None:
        # git keeps '#' lines for `commit -m` and `-F`, and then sets GIT_EDITOR to ":".
        message = self.box.repo / "message.txt"
        message.write_text(j("Add the parser\n\n# Author: ", FAKE_EMAIL, "\n"), encoding="utf-8")
        self.box.env["GIT_EDITOR"] = ":"
        proc = self.box.run(sys.executable, str(self.box.repo / ".githooks" / "privacy_guard.py"),
                            "commit-msg", str(message))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("email", proc.stderr)

    def test_editor_scissors_section_is_left_out(self) -> None:
        # With an editor and `commit -v`, git cuts its diff below the scissors line. The
        # diff names a staged file, as git's own diff would.
        self.box.write("notes.txt", "notes\n")
        self.box.git("add", "notes.txt")
        message = self.box.repo / "message.txt"
        message.write_text(j("Add the parser\n",
                             "# ------------------------ >8 ------------------------\n",
                             "# Do not modify or remove the line above.\n",
                             "# Everything below it will be ignored.\n",
                             "diff --git a/notes.txt b/notes.txt\n",
                             "-home = '", FAKE_HOME_PATH, "'\n"), encoding="utf-8")
        self.box.env["GIT_EDITOR"] = "vi"
        proc = self.box.run(sys.executable, str(self.box.repo / ".githooks" / "privacy_guard.py"),
                            "commit-msg", str(message))
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_scissors_line_without_a_diff_is_not_a_cut(self) -> None:
        message = self.box.repo / "message.txt"
        message.write_text(j("Add the parser\n",
                             "# ------------------------ >8 ------------------------\n",
                             "home = '", FAKE_HOME_PATH, "'\n"), encoding="utf-8")
        self.box.env["GIT_EDITOR"] = "vi"
        proc = self.box.run(sys.executable, str(self.box.repo / ".githooks" / "privacy_guard.py"),
                            "commit-msg", str(message))
        self.assertNotEqual(proc.returncode, 0)


class PrePush(HookTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.box.bare_remote()
        self.assertEqual(self.box.commit("README.md", "# Demo\n", "first").returncode, 0)

    def push(self, *args: str):
        return self.box.git("push", "-q", "origin", *args, check=False)

    def test_clean_push(self) -> None:
        proc = self.push("main")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_secret_added_then_removed_is_still_blocked(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        self.box.commit("app.py", j('TOKEN = "', FAKE_GITHUB_TOKEN, '"\n'), "add", "--no-verify")
        bad = self.box.head()
        self.box.commit("app.py", "TOKEN = None\n", "remove", "--no-verify")
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(bad[:12], proc.stderr)
        self.assertIn("github-token", proc.stderr)
        self.assert_no_values(proc)

    def test_new_branch_scans_unpushed_commits(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        self.box.git("switch", "-q", "-c", "feature")
        self.box.commit("paths.txt", j(FAKE_HOME_PATH, "\n"), "paths", "--no-verify")
        proc = self.push("feature")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("home-path-windows", proc.stderr)

    def test_first_push_of_a_new_repository_scans_everything(self) -> None:
        self.box.commit("contact.txt", j(FAKE_EMAIL, "\n"), "contact", "--no-verify")
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("email", proc.stderr)

    def test_commits_already_on_the_remote_are_not_rescanned(self) -> None:
        self.box.commit("contact.txt", j(FAKE_EMAIL, "\n"), "contact", "--no-verify")
        self.assertEqual(self.box.git("push", "-q", "--no-verify", "origin", "main").returncode, 0)
        self.box.commit("more.txt", "fine\n", "more")
        proc = self.push("main")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_personal_detail_in_commit_message(self) -> None:
        self.box.commit("a.txt", "a\n", j("Write to ", FAKE_EMAIL), "--no-verify")
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("commit message line 1", proc.stderr)
        self.assert_no_values(proc)

    def test_annotated_tag_message_is_scanned(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        self.box.git("tag", "-a", "v1.0", "-m", j("Release. Contact ", FAKE_EMAIL))
        proc = self.push("v1.0")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("tag v1.0 message line 1", proc.stderr)
        self.assert_no_values(proc)

    def test_tagger_email_is_checked(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        self.box.git("config", "user.email", FAKE_EMAIL)
        self.box.git("tag", "-a", "v2.0", "-m", "Release")
        self.box.git("config", "user.email", NOREPLY)
        proc = self.push("v2.0")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("tagger email", proc.stderr)
        self.assert_no_values(proc)

    def test_non_noreply_author_in_history(self) -> None:
        self.box.git("config", "user.email", FAKE_EMAIL)
        self.box.commit("a.txt", "a\n", "change", "--no-verify")
        self.box.git("config", "user.email", NOREPLY)
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("author and committer email", proc.stderr)
        self.assert_no_values(proc)

    def test_secret_added_by_a_merge_commit(self) -> None:
        self.box.git("switch", "-q", "-c", "side")
        self.box.commit("side.txt", "side\n", "side")
        self.box.git("switch", "-q", "main")
        self.box.commit("main.txt", "main\n", "main")
        self.box.git("merge", "-q", "--no-ff", "--no-verify", "-m", "merge", "side")
        self.box.write("merged.txt", j(FAKE_EMAIL, "\n"))
        self.box.git("add", "merged.txt")
        self.box.git("commit", "-q", "--amend", "--no-edit", "--no-verify")
        merge = self.box.head()
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(f"{merge[:12]} merged.txt:1", proc.stderr)

    def test_deleting_a_remote_branch_is_allowed(self) -> None:
        self.assertEqual(self.push("main").returncode, 0)
        self.assertEqual(self.push("main:old").returncode, 0)
        proc = self.push("--delete", "old")
        self.assertEqual(proc.returncode, 0, proc.stderr)


class History(HookTestCase):
    def history(self):
        return self.box.history()

    def test_scans_annotated_tags(self) -> None:
        self.box.commit("README.md", "# Demo\n", "first")
        self.box.git("tag", "-a", "v1.0", "-m", j("Contact ", FAKE_EMAIL))
        proc = self.history()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("tag v1.0 message line 1", proc.stderr)

    def test_ignores_the_local_stash(self) -> None:
        self.box.commit("README.md", "# Demo\n", "first")
        self.box.write("README.md", j("# Demo\ntoken = '", FAKE_GITHUB_TOKEN, "'\n"))
        self.box.git("stash", "push", "-q")
        proc = self.history()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_clean_history(self) -> None:
        self.box.commit("README.md", "# Demo\n", "first")
        proc = self.history()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("found nothing", proc.stdout)

    def test_finds_a_secret_buried_in_history(self) -> None:
        self.box.commit("README.md", "# Demo\n", "first")
        self.box.commit("cfg.py", j('KEY = "', FAKE_GITHUB_TOKEN, '"\n'), "oops", "--no-verify")
        bad = self.box.head()
        self.box.commit("cfg.py", "KEY = None\n", "fix", "--no-verify")
        self.box.git("switch", "-q", "-c", "other")
        self.box.commit("x.txt", "x\n", "other")
        proc = self.history()
        self.assertEqual(proc.returncode, 1)
        self.assertIn(f"{bad[:12]} cfg.py:1", proc.stderr)
        self.assert_no_values(proc)

    def test_empty_repository(self) -> None:
        proc = self.history()
        self.assertEqual(proc.returncode, 0, proc.stderr)


class DefaultConfig(unittest.TestCase):
    """With the config as shipped, reserved example values pass and secrets don't."""

    def setUp(self) -> None:
        self.box = GitSandbox()
        self.addCleanup(self.box.cleanup)
        self.assertEqual(self.box.install().returncode, 0)

    def test_reserved_examples_pass(self) -> None:
        sample = j("Name: Example User\nEmail: ", FAKE_EMAIL, "\nPhone: ", FAKE_PHONE,
                   "\nPostcode: ZZ99", " 9ZZ\nServer: 203.0", ".113.7\nLogs: ", FAKE_HOME_PATH, "\n")
        proc = self.box.commit("docs/sample.md", sample)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_fake_token_is_still_blocked(self) -> None:
        proc = self.box.commit("app.py", j('TOKEN = "', FAKE_GITHUB_TOKEN, '"\n'))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)
        self.assertNotIn(FAKE_GITHUB_TOKEN, proc.stdout + proc.stderr)


class OwnRepository(unittest.TestCase):
    def test_this_repository_passes_its_own_rules(self) -> None:
        """Every tracked or new file in this kit, scanned line by line with its own config."""
        problems = []
        for path in sorted(ROOT.rglob("*")):
            rel = path.relative_to(ROOT).as_posix()
            if not path.is_file() or rel.startswith(".git/") or "__pycache__" in rel:
                continue
            for rule in pg.find_file_rules(rel, CONFIG):
                problems.append(f"{rel}: {rule.id}")
            text = path.read_text(encoding="utf-8", errors="replace")
            for number, line in enumerate(text.splitlines(), 1):
                for rule in pg.find_rules(line, CONFIG, rel):
                    problems.append(f"{rel}:{number}: {rule.id}")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
