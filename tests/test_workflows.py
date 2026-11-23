"""The GitHub workflows and templates follow least privilege and pin every action."""

from __future__ import annotations

import re
import unittest

from support import ROOT

WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml")) + sorted((ROOT / "templates").glob("*.yml"))


def run_blocks(text: str) -> list[str]:
    """The bodies of `run: |` blocks, found by indentation."""
    blocks, lines = [], text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)(?:- )?run: \|", line)
        if not match:
            continue
        indent = len(match.group(1))
        body = []
        for following in lines[index + 1:]:
            if following.strip() and len(following) - len(following.lstrip()) <= indent:
                break
            body.append(following)
        blocks.append("\n".join(body))
    return blocks


class Workflows(unittest.TestCase):
    def test_found_them(self) -> None:
        names = {p.name for p in WORKFLOWS}
        self.assertTrue({"ci.yml", "visibility-guard.yml", "visibility-guard-private.yml",
                         "visibility-guard-public.yml"} <= names)

    def test_actions_are_pinned_to_full_commit_ids(self) -> None:
        for path in WORKFLOWS:
            for line in path.read_text(encoding="utf-8").splitlines():
                if "uses:" in line:
                    with self.subTest(file=path.name, line=line.strip()):
                        self.assertRegex(line, r"uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v\d")

    def test_least_privilege_permissions(self) -> None:
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=path.name):
                self.assertRegex(text, r"(?m)^permissions:\n  contents: read\n\n")
                self.assertNotIn("write", text.split("jobs:")[0])
                self.assertNotRegex(text, r"(?m)^[ ]+permissions:", "no job-level permissions")

    def test_no_expressions_inside_shell_scripts(self) -> None:
        for path in WORKFLOWS:
            for block in run_blocks(path.read_text(encoding="utf-8")):
                with self.subTest(file=path.name):
                    self.assertNotIn("${{", block)

    def test_checkout_does_not_keep_credentials(self) -> None:
        for path in WORKFLOWS:
            text = path.read_text(encoding="utf-8")
            if "actions/checkout@" in text:
                with self.subTest(file=path.name):
                    self.assertEqual(text.count("actions/checkout@"), text.count("persist-credentials: false"))

    def test_history_scan_gets_full_history(self) -> None:
        text = (ROOT / "templates" / "visibility-guard-public.yml").read_text(encoding="utf-8")
        self.assertIn("fetch-depth: 0", text)
        self.assertIn("privacy_guard.py\" history $flags", text)

    def test_strict_is_an_opt_in_input(self) -> None:
        text = (ROOT / "templates" / "visibility-guard-public.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^      strict:$")
        self.assertIn("STRICT: ${{ inputs.strict }}", text)
        self.assertIn('if [ "$STRICT" = "true" ]; then flags=--strict; fi', text)

    def test_python_version_is_checked(self) -> None:
        text = (ROOT / "templates" / "visibility-guard-public.yml").read_text(encoding="utf-8")
        self.assertIn("sys.version_info < (3, 11)", text)

    def test_pull_request_config_is_checked_by_the_base_scanner(self) -> None:
        text = (ROOT / "templates" / "visibility-guard-public.yml").read_text(encoding="utf-8")
        self.assertIn('check-config --config .githooks/privacy-guard.toml', text)
        self.assertIn('git diff --quiet "origin/$BASE_REF"...HEAD -- .githooks/privacy_guard.py', text)

    def test_readme_has_the_real_clone_url(self) -> None:
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("<owner>", text)
        self.assertNotIn("pass_filenames", text)

    def test_private_mode_checks_visibility(self) -> None:
        text = (ROOT / "templates" / "visibility-guard-private.yml").read_text(encoding="utf-8")
        self.assertIn("--jq .visibility", text)

    def test_private_mode_fails_on_public_event(self) -> None:
        text = (ROOT / "templates" / "visibility-guard-private.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^  public:$")
        self.assertRegex(text, r"(?m)^  schedule:$")
        self.assertIn('[ "$EVENT_NAME" = "public" ]', text)

    def test_this_repository_uses_the_public_template(self) -> None:
        live = (ROOT / ".github" / "workflows" / "visibility-guard.yml").read_text(encoding="utf-8")
        template = (ROOT / "templates" / "visibility-guard-public.yml").read_text(encoding="utf-8")
        self.assertEqual(live, template, "update templates/ when the live workflow changes (or vice versa)")


if __name__ == "__main__":
    unittest.main()
