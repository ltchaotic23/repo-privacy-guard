"""Reading git's diff output: which files and which added lines get scanned."""

from __future__ import annotations

import unittest

from support import pg

M = pg.COMMIT_MARK


def events(text: str) -> list:
    return list(pg.parse_diff(text.splitlines(keepends=True)))


def added(text: str) -> list[tuple[str, int, str]]:
    return [(e.path, e.lineno, e.text) for e in events(text) if isinstance(e, pg.LineEvent)]


def files(text: str) -> list[str]:
    return [e.path for e in events(text) if isinstance(e, pg.FileEvent)]


SIMPLE = """\
diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -3,0 +4,2 @@ def main():
+first = 1
++++ not a header, just a line starting with ++
@@ -10 +12 @@
-old
+new
"""


class Unified(unittest.TestCase):
    def test_added_lines_and_numbers(self) -> None:
        self.assertEqual(added(SIMPLE), [
            ("src/app.py", 4, "first = 1"),
            ("src/app.py", 5, "+++ not a header, just a line starting with ++"),
            ("src/app.py", 12, "new"),
        ])
        self.assertEqual(files(SIMPLE), ["src/app.py"])

    def test_deleted_file_is_not_reported(self) -> None:
        text = ("diff --git a/.env b/.env\ndeleted file mode 100644\nindex 1..0\n"
                "--- a/.env\n+++ /dev/null\n@@ -1 +0,0 @@\n-SECRET=1\n")
        self.assertEqual(events(text), [])

    def test_empty_new_file_is_reported(self) -> None:
        text = "diff --git a/.env b/.env\nnew file mode 100644\nindex 0000000..e69de29\n"
        self.assertEqual(files(text), [".env"])

    def test_binary_file_is_reported_by_name(self) -> None:
        text = ("diff --git a/key.p12 b/key.p12\nnew file mode 100644\nindex 0..1\n"
                "Binary files /dev/null and b/key.p12 differ\n")
        self.assertEqual(files(text), ["key.p12"])

    def test_name_with_spaces(self) -> None:
        text = "diff --git a/my notes b/old.txt b/my notes b/old.txt\nnew file mode 100644\n"
        self.assertEqual(files(text), ["my notes b/old.txt"])

    def test_quoted_name(self) -> None:
        text = 'diff --git "a/tab\\there\\303\\251.txt" "b/tab\\there\\303\\251.txt"\nnew file mode 100644\n'
        self.assertEqual(files(text), ["tab\thereé.txt"])

    def test_commit_marker_sets_commit(self) -> None:
        text = f"{M}abc123\n" + SIMPLE + f"\n{M}def456\n" + SIMPLE
        commits = [e.commit for e in events(text) if isinstance(e, pg.LineEvent)]
        self.assertEqual(commits, ["abc123"] * 3 + ["def456"] * 3)

    def test_crlf_output(self) -> None:
        self.assertEqual(added(SIMPLE.replace("\n", "\r\n"))[0], ("src/app.py", 4, "first = 1"))

    def test_unreadable_header_fails_closed(self) -> None:
        with self.assertRaises(pg.GitError):
            events("diff --git nonsense\n")


class Combined(unittest.TestCase):
    MERGE = f"""\
{M}0123abcd
diff --cc config.py
index 1111111,2222222..3333333
--- a/config.py
+++ b/config.py
@@@ -1,1 -1,1 +1,3 @@@
 +from_ours = 1
+ from_theirs = 2
++new_in_merge = 3
- removed = 4
"""

    def test_only_lines_new_in_the_merge_count(self) -> None:
        self.assertEqual(added(self.MERGE), [("config.py", 3, "new_in_merge = 3")])
        self.assertEqual(files(self.MERGE), ["config.py"])


if __name__ == "__main__":
    unittest.main()
