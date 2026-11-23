"""Crafted input must not make the patterns slow (catastrophic backtracking)."""

from __future__ import annotations

import time
import unittest

from support import CONFIG, pg

SIZE = 100_000
LIMIT_SECONDS = 2.0

ADVERSARIAL = {
    "letters": "a" * SIZE,
    "digits": "1" * SIZE,
    "dotted": "a." * (SIZE // 2),
    "dotted digits": "1." * (SIZE // 2),
    "colons": "a:" * (SIZE // 2),
    "at signs": "a@" * (SIZE // 2),
    "pluses": "+1 " * (SIZE // 3),
    "key headers": "-----BEGIN " * (SIZE // 11),
    "sk prefixes": "sk-" * (SIZE // 3),
    "windows paths": "C:\\Users\\" * (SIZE // 9),
    "url schemes": "a://" * (SIZE // 4),
    "assignments": "token=" * (SIZE // 6),
    "jwt-ish": "eyJ" + "a" * SIZE,
    "postcode-ish": "AB1 " * (SIZE // 4),
}


ADVERSARIAL.update({
    "yaml keys": "password:" * (SIZE // 9),
    "list items": "- " * (SIZE // 2),
    "npm auth": ":_auth=" * (SIZE // 7),
    "url users": "redis://:" * (SIZE // 9),
    "home routes": 'get("/home/' * (SIZE // 11),
    "telegram-ish": "123456789:AA" * (SIZE // 12),
})

# Paths that switch on the rules limited to certain files.
PATHS = (None, "config/app.yaml", ".npmrc")


class Performance(unittest.TestCase):
    def test_crafted_lines_are_fast(self) -> None:
        for name, line in ADVERSARIAL.items():
            for path in PATHS:
                with self.subTest(input=name, path=path):
                    start = time.perf_counter()
                    pg.find_rules(line, CONFIG, path)
                    self.assertLess(time.perf_counter() - start, LIMIT_SECONDS)


if __name__ == "__main__":
    unittest.main()
