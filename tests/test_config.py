"""The config loader refuses anything it doesn't understand, so a typo can't switch a check off."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from support import CONFIG, HOOKS, STRICT, j, pg, rule_ids

MINIMAL = {
    "version": 1,
    "rules": [{"id": "demo", "category": "secret", "description": "a demo", "regex": "demo-[0-9]{4}"}],
}


def parse(data: dict) -> pg.Config:
    return pg.parse_config(data)


def with_change(change) -> dict:
    data = copy.deepcopy(MINIMAL)
    change(data)
    return data


class Loading(unittest.TestCase):
    def test_default_config_loads(self) -> None:
        self.assertGreater(len(CONFIG.rules), 20)
        self.assertGreater(len(CONFIG.file_rules), 3)
        self.assertEqual(CONFIG.inline_marker, "privacy-guard:allow")

    def test_minimal_config_loads(self) -> None:
        cfg = parse(MINIMAL)
        self.assertEqual([r.id for r in cfg.rules], ["demo"])
        self.assertTrue(cfg.check_commit_emails)

    def test_missing_file(self) -> None:
        with self.assertRaisesRegex(pg.ConfigError, "not found"):
            pg.load_config(HOOKS / "no-such-file.toml")

    def test_byte_order_mark_is_accepted(self) -> None:
        text = (HOOKS / "privacy-guard.toml").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "with-bom.toml"
            path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
            self.assertEqual(len(pg.load_config(path).rules), len(CONFIG.rules))

    def test_invalid_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.toml"
            path.write_text("version = [", encoding="utf-8")
            with self.assertRaisesRegex(pg.ConfigError, "not valid TOML"):
                pg.load_config(path)


class Refusals(unittest.TestCase):
    def check(self, change, message: str) -> None:
        with self.assertRaisesRegex(pg.ConfigError, message):
            parse(with_change(change))

    def test_unknown_top_level_key(self) -> None:
        self.check(lambda d: d.update(rulez=[]), "unknown key 'rulez'")

    def test_misspelt_rule_key(self) -> None:
        self.check(lambda d: d["rules"][0].update(regx="x"), "unknown key 'regx'")

    def test_misspelt_setting(self) -> None:
        self.check(lambda d: d.update(settings={"check_commit_email": True}), "unknown key")

    def test_wrong_version(self) -> None:
        self.check(lambda d: d.update(version=2), "'version' must be 1")
        self.check(lambda d: d.pop("version"), "'version' must be 1")

    def test_bad_regex_names_the_rule(self) -> None:
        self.check(lambda d: d["rules"][0].update(regex="(unclosed"), "'demo' regex: invalid")

    def test_allowlist_pattern_matching_almost_anything(self) -> None:
        self.check(lambda d: d.update(allowlist={"paths": ["."]}), "matches almost anything")
        self.check(lambda d: d.update(allowlist={"values": ["\\w"]}), "matches almost anything")
        self.check(lambda d: d.update(allowlist={"commit_emails": ["[^@]"]}), "matches almost anything")
        self.check(lambda d: d["rules"][0].update(ignore=["[a-z0-9]"]), "matches almost anything")

    def test_short_broad_allowlist_patterns(self) -> None:
        for key, pattern in (("paths", "/"), ("paths", "\\."), ("paths", ".{4}"), ("values", ".{4}"),
                             ("values", "[0-9]{2}"), ("commit_emails", "@")):
            with self.subTest(key=key, pattern=pattern):
                self.check(lambda d: d.update(allowlist={key: [pattern]}), "matches almost anything")

    def test_allowlisted_commits_must_be_commit_ids(self) -> None:
        self.check(lambda d: d.update(allowlist={"commits": ["main"]}), "commit id")
        self.check(lambda d: d.update(allowlist={"commits": ["abc12"]}), "commit id")
        parse(with_change(lambda d: d.update(allowlist={"commits": ["0123456789ab"]})))

    def test_specific_allowlist_patterns_are_fine(self) -> None:
        parse(with_change(lambda d: d.update(allowlist={
            "paths": ["^docs/fixtures/", "\\.lock$"], "values": ["^demo-0000$"]})))

    def test_pattern_matching_empty_text(self) -> None:
        self.check(lambda d: d["rules"][0].update(ignore=[".*"]), "matches empty text")
        self.check(lambda d: d.update(allowlist={"values": ["x?"]}), "matches empty text")

    def test_duplicate_id(self) -> None:
        self.check(lambda d: d["rules"].append(dict(d["rules"][0])), "duplicate id 'demo'")

    def test_bad_category(self) -> None:
        self.check(lambda d: d["rules"][0].update(category="pii"), "category must be")

    def test_bad_id(self) -> None:
        self.check(lambda d: d["rules"][0].update(id="Bad Id"), "id 'Bad Id'")

    def test_unknown_check(self) -> None:
        self.check(lambda d: d["rules"][0].update(check="luhn"), "unknown check 'luhn'")

    def test_unknown_normalise(self) -> None:
        self.check(lambda d: d["rules"][0].update(normalise="lowercase"), "normalise must be")

    def test_missing_regex(self) -> None:
        self.check(lambda d: d["rules"][0].pop("regex"), "missing 'regex'")

    def test_wrong_types(self) -> None:
        self.check(lambda d: d["rules"][0].update(ignore="x"), "must be a list of strings")
        self.check(lambda d: d.update(settings={"check_commit_emails": "yes"}), "true or false")
        self.check(lambda d: d.update(rules={"id": "x"}), r"\[\[rules\]\]")

    def test_no_rules_at_all(self) -> None:
        with self.assertRaisesRegex(pg.ConfigError, "no \\[\\[rules\\]\\]"):
            parse({"version": 1})


class Allowlisting(unittest.TestCase):
    def test_inline_marker(self) -> None:
        line = j("C:", "\\Users\\", "exampleuser")
        self.assertIn("home-path-windows", rule_ids(line, STRICT))
        self.assertEqual(rule_ids(line + "  # privacy-guard:allow", STRICT), set())

    def test_examples_are_ignored_unless_reported(self) -> None:
        def config(report: bool) -> pg.Config:
            return parse(with_change(lambda d: (
                d["rules"][0].update(examples=["^demo-0000$"]),
                d.update(settings={"report_examples": report}))))
        self.assertEqual(rule_ids("demo-0000", config(False)), set())
        self.assertEqual(rule_ids("demo-0000", config(True)), {"demo"})
        self.assertEqual(rule_ids("demo-1234", config(False)), {"demo"})

    def test_normalise_digits(self) -> None:
        cfg = parse(with_change(lambda d: d["rules"][0].update(
            regex="tel [0-9 -]{5,}", normalise="digits", ignore=["^5550100$"])))
        self.assertEqual(rule_ids("tel 555-0100", cfg), set())
        self.assertEqual(rule_ids("tel 555 0101", cfg), {"demo"})

    def test_inline_marker_can_be_turned_off(self) -> None:
        cfg = parse(with_change(lambda d: d.update(settings={"inline_allow_marker": ""})))
        self.assertEqual(rule_ids("demo-1234 privacy-guard:allow", cfg), {"demo"})

    def test_global_value_allowlist(self) -> None:
        cfg = parse(with_change(lambda d: d.update(allowlist={"values": ["^demo-0000$"]})))
        self.assertEqual(rule_ids("demo-0000", cfg), set())
        self.assertEqual(rule_ids("demo-1234", cfg), {"demo"})

    def test_rule_ignore_sees_value_group(self) -> None:
        cfg = parse(with_change(lambda d: d["rules"][0].update(
            regex="user=(?P<value>[a-z]+)", ignore=["^guest$"])))
        self.assertEqual(rule_ids("user=guest", cfg), set())
        self.assertEqual(rule_ids("user=alex", cfg), {"demo"})

    def test_skipped_paths_still_get_file_name_checks(self) -> None:
        cfg = parse(with_change(lambda d: (
            d.update(allowlist={"paths": ["^fixtures/"]}),
            d.update(files=[{"id": "env", "category": "secret", "description": "env",
                             "path": "\\.env$"}]))))
        events = [pg.LineEvent("", "fixtures/a.txt", 1, "demo-1234"),
                  pg.LineEvent("", "src/a.txt", 1, "demo-1234"),
                  pg.FileEvent("", "fixtures/.env")]
        found = {(f.where, f.rule_id) for f in pg.scan_events(events, cfg)}
        self.assertEqual(found, {("src/a.txt:1", "demo"), ("fixtures/.env", "env")})

    def test_commit_email_allowlist(self) -> None:
        self.assertTrue(pg.email_allowed("12345+someone@users.noreply.github.com", CONFIG))
        self.assertTrue(pg.email_allowed("noreply@github.com", CONFIG))
        self.assertFalse(pg.email_allowed(j("exampleuser", "@", "example.com"), CONFIG))
        self.assertFalse(pg.email_allowed("", CONFIG))


if __name__ == "__main__":
    unittest.main()
