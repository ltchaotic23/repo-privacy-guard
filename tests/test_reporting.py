"""What the guard reports, in what order, and what an allowlist entry can hide."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from support import CONFIG, FAKE_EMAIL, FAKE_GITHUB_TOKEN, STRICT, HookTestCase, j, pg, rule_ids

HOME = j("C:", "\\Users\\", "exampleuser")


def strict_with(**allowlist) -> pg.Config:
    """The default rules, reporting examples, with an extra [allowlist]."""
    text = (pg.DEFAULT_CONFIG).read_text(encoding="utf-8")
    text = text.replace("report_examples = false", "report_examples = true")
    for key, values in allowlist.items():
        old = {"paths": "paths = []", "values": "values = []"}[key]
        text = text.replace(old, f"{key} = {values!r}", 1)
    return pg.load_config_text(text, "test config")


def stderr_of(func, *args) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stderr(buffer):
        func(*args)
    return buffer.getvalue()


class Ordering(unittest.TestCase):
    def test_secrets_are_listed_before_personal_findings(self) -> None:
        findings = [pg.Finding(f"data.csv:{n}", "email", "personal", "an email address")
                    for n in range(1, 60)]
        findings.append(pg.Finding("app.py:9", "github-token", "secret", "a GitHub token"))
        output = stderr_of(pg.report, findings, "commit", CONFIG, "privacy-guard.toml")
        self.assertIn("app.py:9", output)
        self.assertLess(output.index("app.py:9"), output.index("data.csv:1"))

    def test_warnings_are_listed_after_blocking_findings(self) -> None:
        findings = [pg.Finding("a.txt:1", "uk-postcode", "personal", "a UK postcode", severity="warn"),
                    pg.Finding("b.txt:1", "email", "personal", "an email address")]
        output = stderr_of(pg.report, findings, "commit", CONFIG, "privacy-guard.toml")
        self.assertLess(output.index("b.txt:1"), output.index("a.txt:1"))
        self.assertIn("warning", output.lower())


class AllowlistValues(unittest.TestCase):
    def test_values_are_matched_against_the_found_value(self) -> None:
        cfg = strict_with(values=["^exampleuser$"])
        self.assertNotIn("home-path-windows", rule_ids(HOME, cfg))

    def test_values_see_the_digits_of_phone_numbers(self) -> None:
        cfg = strict_with(values=["^07700900123$"])
        self.assertNotIn("phone-uk", rule_ids(j("07700 900 ", "123"), cfg))

    def test_values_cannot_hide_a_secret_by_its_surroundings(self) -> None:
        cfg = strict_with(values=["^password ="])
        line = j('password = "', "Tr0ub4dor", "AndMore1", '"')
        self.assertIn("secret-assignment", rule_ids(line, cfg))


class InlineAllow(unittest.TestCase):
    def test_scoped_marker_hides_only_the_named_rule(self) -> None:
        line = j(HOME, " ", FAKE_EMAIL)
        self.assertEqual(rule_ids(line + " # privacy-guard:allow=home-path-windows", STRICT), {"email"})
        self.assertEqual(rule_ids(line + " # privacy-guard:allow=home-path-windows,email", STRICT), set())

    def test_bare_marker_never_hides_a_secret(self) -> None:
        line = j('home = "', HOME, '"; token = "', FAKE_GITHUB_TOKEN, '"  # privacy-guard:allow')
        found = rule_ids(line, STRICT)
        self.assertIn("github-token", found)
        self.assertNotIn("home-path-windows", found)

    def test_scoped_marker_cannot_hide_a_secret_rule(self) -> None:
        line = j('token = "', FAKE_GITHUB_TOKEN, '"  # privacy-guard:allow=github-token,secret-assignment')
        self.assertEqual(rule_ids(line, STRICT), {"github-token", "secret-assignment"})


class ConfigMessages(unittest.TestCase):
    def test_version_must_be_an_integer(self) -> None:
        with self.assertRaisesRegex(pg.ConfigError, "'version' must be 1"):
            pg.parse_config({"version": True, "rules": [
                {"id": "demo", "category": "secret", "description": "demo", "regex": "demo-[0-9]+"}]})

    def test_missing_config_message_does_not_show_the_full_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nested" / "privacy-guard.toml"
            with self.assertRaises(pg.ConfigError) as caught:
                pg.load_config(missing)
            self.assertNotIn(str(Path(tmp)), str(caught.exception))


class MessageSetting(unittest.TestCase):
    def test_commit_msg_respects_scan_commit_messages(self) -> None:
        import dataclasses
        with tempfile.TemporaryDirectory() as tmp:
            message = Path(tmp) / "COMMIT_EDITMSG"
            message.write_text(j("Rotate ", FAKE_GITHUB_TOKEN, "\n"), encoding="utf-8")
            self.assertEqual({f.rule_id for f in pg.scan_message_file(message, STRICT)}, {"github-token"})
            off = dataclasses.replace(STRICT, scan_commit_messages=False)
            self.assertEqual(pg.scan_message_file(message, off), [])


class RecordSeparator(HookTestCase):
    def test_record_separator_in_a_commit_message(self) -> None:
        self.box.commit("README.md", "start\n", "start")
        self.box.git("commit", "-q", "--allow-empty", "--no-verify", "-m", "message\x1ewith a separator")
        proc = self.box.history()
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
