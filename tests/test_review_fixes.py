"""Regression tests for the pre-release review fix round (items 1 to 7)."""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from support import CONFIG, FAKE_EMAIL, FAKE_GITHUB_TOKEN, FAKE_HOME_PATH, ROOT, STRICT, GitSandbox, j, pg, rule_ids

ZERO = "0" * 40
TOKEN_LINE = j('TOKEN = "', FAKE_GITHUB_TOKEN, '"\n')
OTHER_TOKEN = j("gh", "p_", "FAKE", "C3d4" * 8)
FAKE_SECRET = j("Ab1Cd2Ef3", "FAKE", "Gh4Ij5Kl")
CUT = "# ------------------------ >8 ------------------------"


def _load_installer():
    spec = importlib.util.spec_from_file_location("install_mod", ROOT / "install.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class BlobSnifferGitlinks(unittest.TestCase):
    """Item 1: 160000 gitlinks must never desynchronise BlobSniffer or crash it."""

    def setUp(self) -> None:
        self.box = GitSandbox()
        self.addCleanup(self.box.cleanup)

    def _guard(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        return self.box.run(sys.executable, str(ROOT / ".githooks" / "privacy_guard.py"), *args, stdin=stdin)

    def test_gitlink_cannot_hide_secret_in_staged_push_or_history(self) -> None:
        self.box.write("init.txt", "ok\n")
        self.box.git("add", "init.txt")
        self.box.git("commit", "-q", "-m", "init")
        c0 = self.box.head()
        raw_c0 = subprocess.run(["git", "cat-file", "commit", c0], cwd=self.box.repo,
                                env=self.box.env, capture_output=True, check=True).stdout
        extra_lines = len(raw_c0.splitlines()) + 1

        # Control without the gitlink: staged secret is blocked.
        self.box.write("z_secret.py", TOKEN_LINE)
        self.box.git("add", "z_secret.py")
        self.assertEqual(self._guard("staged").returncode, 1)

        # With a local-commit gitlink and distinct binary blobs, it must still block everywhere.
        self.box.git("update-index", "--add", "--cacheinfo", f"160000,{c0},a_sub")
        for n in range(extra_lines):
            (self.box.repo / f"b_{n:02d}.dat").write_bytes(f"\x89PNG\x00distinct-{n}\n".encode())
            self.box.git("add", f"b_{n:02d}.dat")

        staged = self._guard("staged")
        self.assertEqual(staged.returncode, 1, staged.stderr)
        self.assertIn("github-token", staged.stderr)

        self.box.git("commit", "-q", "-m", "add bundle")
        tip = self.box.head()
        push = self._guard("push", "--", "origin", "origin",
                           stdin=f"refs/heads/main {tip} refs/heads/main {c0}\n")
        self.assertEqual(push.returncode, 1, push.stderr)
        self.assertIn("github-token", push.stderr)

        hist = self._guard("history")
        self.assertEqual(hist.returncode, 1, hist.stderr)
        self.assertIn("github-token", hist.stderr)

    def test_gitlink_commit_message_does_not_crash_sniffer(self) -> None:
        self.box.write("init.txt", "ok\n")
        self.box.git("add", "init.txt")
        self.box.git("commit", "-q", "-m", "parse blob crash\n")
        c0 = self.box.head()
        self.box.git("update-index", "--add", "--cacheinfo", f"160000,{c0},a_sub")
        for n in range(8):
            self.box.write(f"f_{n}.txt", f"clean {n}\n")
            self.box.git("add", f"f_{n}.txt")
        staged = self._guard("staged")
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.box.git("commit", "-q", "-m", "clean bundle")
        hist = self._guard("history")
        self.assertEqual(hist.returncode, 0, hist.stderr)

    def test_missing_submodule_commit_is_handled(self) -> None:
        missing_sha = "deadbeef" * 5
        self.box.git("update-index", "--add", "--cacheinfo", f"160000,{missing_sha},ext_sub")
        self.box.write("clean.py", "x = 1\n")
        self.box.git("add", "clean.py")
        self.assertEqual(self._guard("staged").returncode, 0)
        self.box.write("z_secret.py", TOKEN_LINE)
        self.box.git("add", "z_secret.py")
        staged = self._guard("staged")
        self.assertEqual(staged.returncode, 1, staged.stderr)
        self.assertIn("github-token", staged.stderr)


class FalseAlarmsAndManifests(unittest.TestCase):
    """Item 2: K8s reference keys, manifests/lockfiles, Compose defaults, JSX and routes."""

    def test_k8s_helm_reference_keys_are_skipped_but_real_secrets_block(self) -> None:
        quiet = [
            "  existingSecret: postgres-prod-v1",
            "  tlsSecret: wildcard-prod-2026",
            "  pullSecret: ghcr-registry-1",
            "  secretKey: database-url-v1",
            "  passwordKey: postgres-admin-v1",
            "  dbSecretName: app-db-2026",
            "  authSecretRef: oauth-ref-2026",
            "  tokenKeyRef: jwt-signing-v1",
        ]
        for line in quiet:
            with self.subTest(line=line):
                self.assertEqual(rule_ids(line, CONFIG, "k8s/values.yaml"), set())
        # Arbitrary kebab-case values on actual secret keys still block, and snake_case secret_key blocks.
        self.assertIn("config-secret", rule_ids(j("  db_password: ", "horse-staple-99"), CONFIG, "k8s/values.yaml"))
        self.assertIn("config-secret", rule_ids(j("secret_key = ", "a1b2c3d4e5f6g7h8"), CONFIG, "settings.ini"))

    def test_manifests_and_lockfiles_skip_generic_rules_but_keep_prefix_rules(self) -> None:
        manifests = (
            "package.json", "web/package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            "pyproject.toml", "poetry.lock", "uv.lock", "Cargo.toml", "Cargo.lock",
        )
        for path in manifests:
            with self.subTest(path=path):
                generic = j('auth_token = "', FAKE_SECRET, '"')
                self.assertEqual(rule_ids(generic, CONFIG, path), set())
                self.assertIn("github-token", rule_ids(j('url = "', FAKE_GITHUB_TOKEN, '"'), CONFIG, path))
                self.assertIn("aws-access-key-id", rule_ids(j("AKIA", "IOSFODNN7EXAMPLE"), CONFIG, path))
                self.assertIn("private-key", rule_ids(j("-----BEGIN ", "PRIVATE KEY-----"), CONFIG, path))
                self.assertIn("url-credentials", rule_ids(j("https://u:", "s3cretPass", "@git.example.com/r"), CONFIG, path))

    def test_url_credentials_local_equal_defaults(self) -> None:
        for creds in ("postgres:postgres", "guest:guest", "root:root", "mysql:mysql"):
            url = j("tcp://", creds, "@service.internal:5432/db")
            self.assertEqual(rule_ids(url, CONFIG), set(), creds)
        self.assertIn("url-credentials", rule_ids(j("postgres://admin:", "postgres", "@db.internal:5432/db"), CONFIG))
        self.assertIn("url-credentials", rule_ids(j("postgres://alice:", "alice", "@db.internal:5432/db"), CONFIG))

    def test_jsx_wide_window_and_sk_classes(self) -> None:
        sk = j("sk-", "button-primary-v2-2026")
        pad = "flex items-center justify-center rounded-md px-4 py-2 text-sm font-medium shadow-sm border " * 2
        self.assertEqual(rule_ids(f'<button className="{pad}{sk}">', CONFIG, "App.tsx"), set())
        self.assertEqual(rule_ids(f'cn("flex items-center {sk}")', CONFIG, "App.tsx"), set())
        self.assertEqual(rule_ids(f"className={{`flex {sk}`}}", CONFIG, "App.tsx"), set())
        long_tag = "<Link " + 'data-x="1234567890" ' * 16 + j('to="/home/', 'dashboard">')
        self.assertEqual(rule_ids(long_tag, STRICT, "Nav.tsx"), set())
        # Real sk- API keys in ordinary strings still block.
        self.assertIn("openai-style-key", rule_ids(j('hdr = "Bearer sk-proj-', 'Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8"'), CONFIG, "a.py"))

    def test_windows_home_path_skips_lowercase_web_routes(self) -> None:
        self.assertEqual(rule_ids('fetch("/m/users/profile")', STRICT, "api.ts"), set())
        self.assertEqual(rule_ids('router.get("/i/users/12345", h)', STRICT, "routes.ts"), set())
        self.assertIn("home-path-windows", rule_ids(j("cd /c/Users/", "exampleuser/app"), STRICT))
        self.assertIn("home-path-windows", rule_ids(j("c:/users/", "exampleuser/app"), STRICT))
        self.assertIn("home-path-windows", rule_ids(j("/mnt/c/users/", "exampleuser/app"), STRICT))


class MergedFeatureBranchPush(unittest.TestCase):
    """Item 3: merging main into a branch started at an old tag must not rescan v1.0..main."""

    def test_feature_branch_merging_main_is_not_blocked_by_older_tag_boundary(self) -> None:
        box = GitSandbox()
        self.addCleanup(box.cleanup)
        box.write("README.md", "# App\n")
        box.git("add", "README.md")
        box.git("commit", "-q", "-m", "v1.0")
        c1 = box.head()
        box.write("CREDITS.md", j("Maintainer: ", FAKE_EMAIL, "\n"))
        box.git("add", "CREDITS.md")
        box.git("commit", "-q", "-m", "credits on main")
        c2 = box.head()
        box.git("switch", "-q", "-c", "feature", c1)
        box.write("feature.py", "x = 1\n")
        box.git("add", "feature.py")
        box.git("commit", "-q", "-m", "clean feature")
        box.git("merge", "-q", "main", "-m", "merge main")
        tip = box.head()
        with mock.patch.object(pg, "_remote_tips", return_value=[c1, c2]):
            findings = pg.scan_push(box.repo, STRICT, f"refs/heads/feature {tip} refs/heads/feature {ZERO}\n", "origin")
        self.assertEqual(findings, [])

    def test_force_push_rollback_still_blocks_with_older_tag_present(self) -> None:
        box = GitSandbox()
        self.addCleanup(box.cleanup)
        box.write("app.py", TOKEN_LINE)
        box.git("add", "app.py")
        box.git("commit", "-q", "-m", "with secret")
        c1 = box.head()
        box.write("app.py", "TOKEN = None\n")
        box.git("add", "app.py")
        box.git("commit", "-q", "-m", "clean")
        c2 = box.head()
        findings = pg.scan_push(box.repo, STRICT, f"refs/heads/main {c1} refs/heads/main {c2}\n", "origin")
        self.assertTrue(any(f.rule_id == "github-token" for f in findings))


class TypedAssignmentsAndAngleBrackets(unittest.TestCase):
    """Item 4: typed secret assignments and anchored <...> placeholders."""

    def test_typed_secret_assignments_are_caught(self) -> None:
        cases = [
            ("app/config.py", j('API_KEY: str = "', FAKE_SECRET, '"')),
            ("app/config.py", j('password: Final[str] = "', FAKE_SECRET, '"')),
            ("src/auth.ts", j('export const apiKey: string = "', FAKE_SECRET, '";')),
            ("src/lib.rs", j('const SECRET_TOKEN: &str = "', FAKE_SECRET, '";')),
            ("Auth.kt", j('val dbPassword: String = "', FAKE_SECRET, '"')),
        ]
        for path, line in cases:
            with self.subTest(path=path, line=line):
                self.assertIn("secret-assignment", rule_ids(line, CONFIG, path))
        self.assertEqual(rule_ids(j('api_key_name: str = "', 'prod-api-key-2026"'), CONFIG, "a.py"), set())

    def test_angle_brackets_inside_password_do_not_hide_it(self) -> None:
        self.assertIn("secret-assignment", rule_ids(j('password = "', "aB3<x9>FAKE2pQ8z", '"'), CONFIG, "a.py"))
        self.assertEqual(rule_ids(j('password = "', "<db-password-2>", '"'), CONFIG, "a.py"), set())


class BroadAllowlistProbes(unittest.TestCase):
    """Item 5: long broad allowlist patterns are rejected."""

    def test_longer_broad_patterns_are_rejected(self) -> None:
        for pat in (".{27}", ".{36}", ".{64}", "[A-Za-z0-9_-]{15}"):
            with self.subTest(pattern=pat):
                data = {
                    "version": 1,
                    "allowlist": {"values": [pat]},
                    "rules": [{"id": "demo", "category": "secret", "description": "d", "regex": "demo-[0-9]+"}],
                }
                with self.assertRaisesRegex(pg.ConfigError, "matches almost anything"):
                    pg.parse_config(data)


class CommitMessageVerboseDiff(unittest.TestCase):
    """Item 6: mnemonic/noprefix headers, root --amend -v, and strict diff-only validation."""

    def test_mnemonic_and_noprefix_verbose_diffs_do_not_block_secret_removal(self) -> None:
        box = GitSandbox()
        self.addCleanup(box.cleanup)
        box.write("app.py", TOKEN_LINE)
        box.git("add", "app.py")
        box.git("commit", "-q", "-m", "init")
        box.write("app.py", "TOKEN = None\n")
        box.git("add", "app.py")
        for flag in ("diff.mnemonicPrefix", "diff.noprefix"):
            with self.subTest(flag=flag):
                diff_txt = box.run("git", "-c", f"{flag}=true", "diff", "--cached").stdout
                msg = box.tmp / f"msg_{flag}.txt"
                msg.write_text(f"Remove token\n{CUT}\n# c1\n# c2\n{diff_txt}", encoding="utf-8")
                ctx = pg.message_context(box.repo, editor=True)
                self.assertEqual(pg.scan_message_file(msg, STRICT, True, box.repo, ctx), [])

    def test_root_commit_amend_verbose_diff_uses_root_paths(self) -> None:
        box = GitSandbox()
        self.addCleanup(box.cleanup)
        box.write("notes.md", j("Path: ", FAKE_HOME_PATH, "\n"))
        box.write("README.md", "v1\n")
        box.git("add", "notes.md", "README.md")
        box.git("commit", "-q", "-m", "root")
        box.write("README.md", "v2\n")
        box.git("add", "README.md")
        empty_tree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
        diff_txt = box.git("diff", "--cached", empty_tree).stdout
        msg = box.tmp / "root_amend.txt"
        msg.write_text(f"Amend root\n{CUT}\n# c1\n# c2\n{diff_txt}", encoding="utf-8")
        ctx = pg.message_context(box.repo, editor=True)
        self.assertEqual(pg.scan_message_file(msg, STRICT, True, box.repo, ctx), [])

    def test_prose_after_staged_diff_header_below_scissors_is_scanned(self) -> None:
        box = GitSandbox()
        self.addCleanup(box.cleanup)
        box.write("README.md", "v1\n")
        box.git("add", "README.md")
        box.git("commit", "-q", "-m", "init")
        box.write("README.md", "v2\n")
        box.git("add", "README.md")
        msg = box.tmp / "pasted.txt"
        msg.write_text(j("Subject\n\n", CUT, "\n# a\n# b\ndiff --git a/README.md b/README.md\n", TOKEN_LINE),
                       encoding="utf-8")
        ctx = pg.message_context(box.repo, editor=True)
        found = {f.rule_id for f in pg.scan_message_file(msg, STRICT, True, box.repo, ctx)}
        self.assertIn("github-token", found)


class SmallerHardening(unittest.TestCase):
    """Item 7: same-line accepted commits, control-char escaping in report(), and hardlink-safe install."""

    def test_accepted_commit_cannot_hide_second_secret_on_same_line(self) -> None:
        box = GitSandbox()
        self.addCleanup(box.cleanup)
        box.write("data.json", j('{"old": "', FAKE_GITHUB_TOKEN, '"}\n'))
        box.git("add", "data.json")
        box.git("commit", "-q", "-m", "accepted")
        acc = box.head()
        box.write("data.json", "{}\n")
        box.git("add", "data.json")
        box.git("commit", "-q", "-m", "clean")
        main_clean = box.head()
        box.git("switch", "-q", "-c", "side", acc)
        box.write("data.json", j('{"old": "', FAKE_GITHUB_TOKEN, '", "new": "', OTHER_TOKEN, '"}\n'))
        box.git("add", "data.json")
        box.git("commit", "-q", "-m", "side")
        side_sha = box.head()
        box.git("merge", "-q", "-s", "ours", "main", "-m", "merge")
        box.git("switch", "-q", "main")
        box.git("merge", "-q", "--ff-only", "side")
        tip = box.head()
        cfg_acc = dataclasses.replace(STRICT, accepted_commits=(acc,))
        refs = f"refs/heads/main {tip} refs/heads/main {main_clean}\nrefs/heads/side {side_sha} refs/heads/side {side_sha}\n"
        findings = pg.scan_push(box.repo, cfg_acc, refs, "origin")
        self.assertTrue(any(f.rule_id == "github-token" for f in findings))

    def test_report_escapes_control_characters_in_filenames(self) -> None:
        buf = io.StringIO()
        crafted = "sub\n::error title=Spoof::injected\r\x1b[31m/.env"
        with contextlib.redirect_stderr(buf):
            pg.report([pg.Finding(crafted, "env-file", "secret", "desc")], "commit", CONFIG, "privacy-guard.toml")
        out = buf.getvalue()
        self.assertFalse(any(ln.startswith("::error") for ln in out.splitlines()))
        self.assertNotIn("\x1b", out)
        self.assertIn(r"\n::error", out)

    def test_installer_writes_atomically_and_refuses_hardlinks(self) -> None:
        inst = _load_installer()
        box = GitSandbox()
        self.addCleanup(box.cleanup)
        target_hook = box.repo / ".githooks" / "privacy-guard.sha256"
        target_hook.parent.mkdir(parents=True, exist_ok=True)
        target_hook.write_text("old\n", encoding="utf-8")
        real_stat = Path.stat

        class FakeStat:
            def __init__(self, orig):
                self._orig = orig
                self.st_nlink = 2
            def __getattr__(self, name):
                return getattr(self._orig, name)

        def patched_stat(self_path: Path, *a, **kw):
            st = real_stat(self_path, *a, **kw)
            return FakeStat(st) if self_path == target_hook else st

        with mock.patch.object(Path, "stat", patched_stat):
            with self.assertRaisesRegex(inst.InstallError, "hard link"):
                inst.refuse_links(box.repo, [target_hook])


if __name__ == "__main__":
    unittest.main()
