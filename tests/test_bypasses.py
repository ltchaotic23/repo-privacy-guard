"""Ways a leak could slip past the guard without anyone noticing. Each must be blocked."""

from __future__ import annotations

import subprocess
import unittest

from support import FAKE_GITHUB_TOKEN, HookTestCase, j

TOKEN_LINE = j('TOKEN = "', FAKE_GITHUB_TOKEN, '"\n')


class PushBypasses(HookTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.remote = self.box.bare_remote()
        self.assertEqual(self.box.commit("README.md", "# Demo\n", "first").returncode, 0)

    def push(self, *args: str):
        return self.box.git("push", "-q", "origin", *args, check=False)

    def new_bare(self, name: str):
        path = self.box.tmp / name
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(path)],
                       env=self.box.env, check=True, capture_output=True)
        return path

    def test_stale_remote_refs_after_url_change(self) -> None:
        # The old remote already has the commit, so origin/main points at it. After the URL
        # changes to an empty repository, that stale ref must not hide the commit.
        self.assertEqual(self.push("main").returncode, 0)
        self.box.commit("app.py", TOKEN_LINE, "add app", "--no-verify")
        self.assertEqual(self.box.git("push", "-q", "--no-verify", "origin", "main").returncode, 0)
        empty = self.new_bare("second.git")
        self.box.git("remote", "set-url", "origin", str(empty))
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)
        landed = self.box.run("git", "--git-dir", str(empty), "for-each-ref").stdout
        self.assertEqual(landed.strip(), "", "nothing may reach the new remote")

    def test_merge_ours_cannot_resurrect_a_removed_file(self) -> None:
        self.box.write(".env", "A=1\n")
        self.box.git("add", ".env")
        self.box.git("commit", "-q", "--no-verify", "-m", "add env")
        with_env = self.box.head()
        self.assertEqual(self.box.git("push", "-q", "--no-verify", "origin", "main").returncode, 0)
        self.box.git("rm", "-q", ".env")
        self.box.git("commit", "-q", "-m", "remove env")
        self.assertEqual(self.push("main").returncode, 0)
        self.box.git("switch", "-q", "-c", "side", with_env)
        self.assertEqual(self.box.commit("f1.txt", "unrelated\n", "f1").returncode, 0)
        self.box.git("merge", "-q", "-s", "ours", "main", "-m", "merge")
        self.box.git("switch", "-q", "main")
        self.box.git("merge", "-q", "--ff-only", "side")
        self.assertTrue((self.box.repo / ".env").exists())
        proc = self.push("main")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("env-file", proc.stderr)


class ConfigTampering(HookTestCase):
    """The hooks use the config as staged (pre-commit) or committed (pre-push), so an
    edit that hasn't been staged or committed can't switch a check off by accident."""

    WEAKEN = ("paths = []", "paths = ['^app[.]py$']")

    def setUp(self) -> None:
        super().setUp()
        self.box.commit_guard()

    def test_unstaged_config_edit_is_ignored_by_pre_commit(self) -> None:
        self.box.edit_config(*self.WEAKEN)
        proc = self.box.commit("app.py", TOKEN_LINE)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)
        self.assertIn("staged copy", proc.stderr)

    def test_staged_config_edit_applies(self) -> None:
        self.box.edit_config(*self.WEAKEN)
        self.box.git("add", ".githooks/privacy-guard.toml")
        proc = self.box.commit("app.py", TOKEN_LINE)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_uncommitted_config_edit_is_ignored_by_pre_push(self) -> None:
        self.box.bare_remote()
        self.box.edit_config(*self.WEAKEN)
        self.box.commit("app.py", TOKEN_LINE, "add app", "--no-verify")
        proc = self.box.git("push", "-q", "origin", "main", check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("github-token", proc.stderr)


class HiddenContent(HookTestCase):
    def test_git_replace_does_not_hide_commits(self) -> None:
        self.box.commit("README.md", "start\n", "start")
        self.box.commit("app.py", TOKEN_LINE, "leak", "--no-verify")
        leak = self.box.head()
        self.box.git("rm", "-q", "app.py")
        self.box.git("commit", "-q", "--no-verify", "-m", "remove")
        self.assertEqual(self.box.history().returncode, 1)
        tree = self.box.git("rev-parse", "HEAD~2^{tree}").stdout.strip()
        parent = self.box.git("rev-parse", "HEAD~2").stdout.strip()
        clean = self.box.git("commit-tree", tree, "-p", parent, "-m", "clean").stdout.strip()
        self.box.git("replace", leak, clean)
        proc = self.box.history()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn(leak[:12], proc.stderr)

    def test_gitattributes_diff_does_not_hide_contents(self) -> None:
        self.assertEqual(self.box.commit(".gitattributes", "*.json -diff\n", "attrs").returncode, 0)
        proc = self.box.commit("data.json", j('{"token": "', FAKE_GITHUB_TOKEN, '"}\n'))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("data.json:1", proc.stderr)

    def test_gitattributes_binary_does_not_hide_contents_from_history(self) -> None:
        self.box.commit(".gitattributes", "*.dat binary\n", "attrs")
        self.box.commit("notes.dat", TOKEN_LINE, "notes", "--no-verify")
        proc = self.box.history()
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("notes.dat:1", proc.stderr)

    def test_real_binary_contents_are_not_scanned(self) -> None:
        path = self.box.repo / "image.png"
        path.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + TOKEN_LINE.encode() + b"\x00\xff" * 64)
        self.box.git("add", "image.png")
        proc = self.box.git("commit", "-q", "-m", "image", check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
