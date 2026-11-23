"""The installer: copies the guard, keeps the user's config and edits, and changes nothing
until every check has passed."""

from __future__ import annotations

import hashlib
import os
import sys
import unittest

from support import ROOT, GitSandbox

HOOKS = ("pre-commit", "pre-push", "commit-msg")


class Installer(unittest.TestCase):
    def setUp(self) -> None:
        self.box = GitSandbox()
        self.addCleanup(self.box.cleanup)

    def hooks_path(self) -> str:
        return self.box.git("config", "--get", "core.hooksPath", check=False).stdout.strip()

    def guard(self, name: str):
        return self.box.repo / ".githooks" / name

    def test_fresh_install(self) -> None:
        proc = self.box.install()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in (*HOOKS, "privacy_guard.py", "privacy-guard.toml", "privacy-guard.sha256"):
            self.assertTrue(self.guard(name).is_file(), name)
        self.assertEqual(self.hooks_path(), ".githooks")
        self.assertIn("git add --chmod=+x .githooks/pre-commit .githooks/pre-push .githooks/commit-msg",
                      proc.stdout)

    def test_reinstall_keeps_the_users_config(self) -> None:
        self.box.install()
        config = self.guard("privacy-guard.toml")
        edited = config.read_text(encoding="utf-8").replace("paths = []", "paths = ['^docs/']")
        config.write_text(edited, encoding="utf-8")
        proc = self.box.install()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Kept your existing", proc.stdout)
        self.assertEqual(config.read_text(encoding="utf-8"), edited)

    def test_refuses_to_replace_another_hooks_path(self) -> None:
        self.box.git("config", "core.hooksPath", "other-hooks")
        proc = self.box.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--force", proc.stderr)
        self.assertEqual(self.hooks_path(), "other-hooks")
        self.assertEqual(self.box.install("--force").returncode, 0)
        self.assertEqual(self.hooks_path(), ".githooks")

    def test_refuses_to_override_a_global_hooks_path(self) -> None:
        self.box.global_config.write_text("[core]\n\thooksPath = /shared/hooks\n", encoding="utf-8")
        proc = self.box.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("core.hooksPath is set in your global git config", proc.stderr)
        self.assertEqual(self.box.install("--force").returncode, 0)

    def test_refuses_to_hide_existing_hooks(self) -> None:
        hook = self.box.repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\nexit 0\n")
        proc = self.box.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("pre-commit", proc.stderr)
        self.assertEqual(self.hooks_path(), "")

    def test_refuses_to_overwrite_someone_elses_hook_file(self) -> None:
        self.box.write(".githooks/pre-commit", "#!/bin/sh\necho mine\n")
        proc = self.box.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("has been changed", proc.stderr)

    def test_edited_hook_is_not_overwritten_without_force(self) -> None:
        self.assertEqual(self.box.install().returncode, 0)
        hook = self.guard("pre-commit")
        edited = hook.read_text(encoding="utf-8") + "echo my own step\n"
        hook.write_text(edited, encoding="utf-8")
        proc = self.box.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("has been changed", proc.stderr)
        self.assertEqual(hook.read_text(encoding="utf-8"), edited)
        self.assertEqual(self.box.install("--force").returncode, 0)
        self.assertNotEqual(hook.read_text(encoding="utf-8"), edited)

    def test_unedited_copy_from_an_older_version_is_updated(self) -> None:
        self.assertEqual(self.box.install().returncode, 0)
        hook = self.guard("pre-commit")
        older = b"#!/bin/sh\n# repo-privacy-guard (an older version)\nexit 0\n"
        hook.write_bytes(older)
        manifest = self.guard("privacy-guard.sha256")
        lines = [line for line in manifest.read_text(encoding="utf-8").splitlines()
                 if not line.endswith("  pre-commit")]
        lines.append(f"{hashlib.sha256(older).hexdigest()}  pre-commit")
        manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
        proc = self.box.install()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Updated .githooks/pre-commit", proc.stdout)
        self.assertEqual(hook.read_bytes(), (ROOT / ".githooks" / "pre-commit").read_bytes())

    def test_nothing_is_written_when_a_check_fails(self) -> None:
        self.box.write(".github/workflows/visibility-guard.yml", "name: mine\n")
        proc = self.box.install("--workflow", "public")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("already exists", proc.stderr)
        self.assertFalse((self.box.repo / ".githooks").exists())
        self.assertEqual(self.hooks_path(), "")

    def test_broken_existing_config_is_reported_before_writing(self) -> None:
        self.box.write(".githooks/privacy-guard.toml", "version = 1\nrulez = []\n")
        proc = self.box.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("rulez", proc.stderr)
        self.assertFalse(self.guard("privacy_guard.py").exists())

    def test_adds_a_workflow(self) -> None:
        for mode in ("private", "public"):
            with self.subTest(mode=mode):
                proc = self.box.install("--workflow", mode, "--force")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                installed = self.box.repo / ".github" / "workflows" / "visibility-guard.yml"
                template = ROOT / "templates" / f"visibility-guard-{mode}.yml"
                self.assertEqual(installed.read_bytes(), template.read_bytes())

    def test_line_ending_advice(self) -> None:
        names = (*HOOKS, "privacy_guard.py", "privacy-guard.toml", "privacy-guard.sha256")
        proc = self.box.install()
        for name in names:
            self.assertIn(f".githooks/{name} text eol=lf", proc.stdout)
        self.box.write(".gitattributes", "".join(f".githooks/{h} text eol=lf\n" for h in names))
        proc = self.box.install()
        self.assertNotIn("eol=lf", proc.stdout)

    def test_reinstall_after_a_windows_line_ending_checkout(self) -> None:
        self.assertEqual(self.box.install().returncode, 0)
        self.box.git("add", ".githooks")
        self.box.git("commit", "-q", "--no-verify", "-m", "add the guard")
        self.box.git("config", "core.autocrlf", "true")
        for name in ("privacy_guard.py", "privacy-guard.toml", "pre-commit"):
            self.guard(name).unlink()
        self.box.git("checkout", "--", ".githooks")
        self.assertIn(b"\r\n", self.guard("privacy_guard.py").read_bytes())
        proc = self.box.install()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_dot_files_in_the_hooks_folder_are_not_hooks(self) -> None:
        (self.box.repo / ".git" / "hooks" / ".DS_Store").write_bytes(b"\x00")
        proc = self.box.install()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_hooks_path_included_from_another_file_needs_force(self) -> None:
        extra = self.box.tmp / "extra.gitconfig"
        extra.write_text("[core]\n\thooksPath = /shared/hooks\n", encoding="utf-8")
        self.box.global_config.write_text(f"[include]\n\tpath = {extra.as_posix()}\n", encoding="utf-8")
        proc = self.box.install()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("core.hooksPath", proc.stderr)

    def test_identical_workflow_is_left_alone(self) -> None:
        self.assertEqual(self.box.install("--workflow", "public").returncode, 0)
        proc = self.box.install("--workflow", "public")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("Added .github/workflows", proc.stdout)

    def test_trailing_slash_hooks_path_can_be_uninstalled(self) -> None:
        self.assertEqual(self.box.install().returncode, 0)
        self.box.git("config", "core.hooksPath", ".githooks/")
        proc = self.box.install("--uninstall")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.hooks_path(), "")

    def test_uninstall_rejects_other_options(self) -> None:
        proc = self.box.install("--uninstall", "--workflow", "public")
        self.assertNotEqual(proc.returncode, 0)

    def test_symlinked_workflow_folder_is_refused(self) -> None:
        outside = self.box.tmp / "outside"
        outside.mkdir()
        (self.box.repo / ".github").mkdir()
        try:
            os.symlink(outside, self.box.repo / ".github" / "workflows", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("this system can't create symbolic links")
        proc = self.box.install("--workflow", "public", "--force")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "junctions are a Windows feature")
    def test_junction_in_the_way_is_refused(self) -> None:
        # Unlike symbolic links, junctions need no special rights on Windows.
        import subprocess
        outside = self.box.tmp / "outside"
        outside.mkdir()
        for link in (self.box.repo / ".github", self.box.repo / ".githooks"):
            with self.subTest(link=link.name):
                made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)],
                                      capture_output=True)
                if made.returncode != 0:
                    self.skipTest("couldn't create a junction")
                proc = self.box.install("--workflow", "public", "--force")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("junction", proc.stderr)
                self.assertEqual(list(outside.iterdir()), [])
                os.rmdir(link)

    def test_worktree_scoped_hooks_path_is_refused(self) -> None:
        self.box.git("config", "extensions.worktreeConfig", "true")
        self.box.git("config", "--worktree", "core.hooksPath", "custom-hooks")
        proc = self.box.install("--force")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("worktree", proc.stderr)
        effective = self.box.git("config", "--get", "core.hooksPath").stdout.strip()
        self.assertEqual(effective, "custom-hooks")

    def test_trailing_backslash_hooks_path(self) -> None:
        self.assertEqual(self.box.install().returncode, 0)
        self.box.git("config", "core.hooksPath", ".githooks\\")
        self.assertEqual(self.box.install().returncode, 0)
        self.box.git("config", "core.hooksPath", ".githooks\\")
        self.assertEqual(self.box.install("--uninstall").returncode, 0)
        self.assertEqual(self.hooks_path(), "")

    def test_manifest_uses_unix_line_endings(self) -> None:
        self.assertEqual(self.box.install().returncode, 0)
        self.assertNotIn(b"\r\n", self.guard("privacy-guard.sha256").read_bytes())

    def test_wrong_file_type_gives_a_clean_error(self) -> None:
        self.guard("pre-commit").mkdir(parents=True)
        proc = self.box.install("--force")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("install.py:", proc.stderr)
        self.assertNotIn("Traceback", proc.stderr)

    def test_symlinked_hook_file_is_refused(self) -> None:
        outside = self.box.tmp / "outside.txt"
        outside.write_text("keep me\n", encoding="utf-8")
        (self.box.repo / ".githooks").mkdir()
        try:
            os.symlink(outside, self.guard("pre-commit"))
        except (OSError, NotImplementedError):
            self.skipTest("this system can't create symbolic links")
        proc = self.box.install("--force")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("symbolic link", proc.stderr)
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep me\n")

    def test_uninstall(self) -> None:
        self.assertEqual(self.box.install().returncode, 0)
        proc = self.box.install("--uninstall")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.hooks_path(), "")
        self.assertIn("still in .githooks", proc.stdout)
        self.assertTrue(self.guard("privacy_guard.py").exists(), "uninstall must not delete files")

    def test_uninstall_leaves_another_hooks_path_alone(self) -> None:
        self.box.git("config", "core.hooksPath", "other-hooks")
        proc = self.box.install("--uninstall")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.hooks_path(), "other-hooks")

    def test_not_a_repository(self) -> None:
        proc = self.box.run(sys.executable, str(ROOT / "install.py"), str(self.box.tmp))
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not inside a git working tree", proc.stderr)


class NonAsciiPath(unittest.TestCase):
    def test_install_with_a_non_ascii_repository_path(self) -> None:
        box = GitSandbox(name="wörk-тест")
        self.addCleanup(box.cleanup)
        box.env["PYTHONUTF8"] = "0"
        box.env.pop("PYTHONIOENCODING", None)
        proc = box.install()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(box.git("config", "--get", "core.hooksPath").stdout.strip(), ".githooks")


if __name__ == "__main__":
    unittest.main()
