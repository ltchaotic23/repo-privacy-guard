#!/usr/bin/env python3
"""repo-privacy-guard: stop commits and pushes that add secrets or personal details.

Standard library only; needs Python 3.11 or newer. The rules and allowlists live in
privacy-guard.toml beside this file. Findings name the file, line and rule, never the
matched text, so the output is safe to paste into an issue or show in a CI log.

Usage:
  privacy_guard.py staged              scan the added lines of staged changes (pre-commit)
  privacy_guard.py commit-msg FILE     scan a commit message (commit-msg)
  privacy_guard.py push REMOTE [URL]   scan the commits and tags about to be pushed; git
                                       passes the refs on stdin (pre-push)
  privacy_guard.py history             scan every commit and annotated tag on every branch,
                                       tag and remote-tracking branch
  privacy_guard.py check-config        check the config file and exit

Options: --strict (every rule blocks), --report-examples (report reserved example values
too), --config PATH.

Exit status: 0 nothing that blocks (warnings may be printed), 1 possible leaks found,
2 error. The hooks block on 1 and 2.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import ipaddress
import threading
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

if sys.version_info < (3, 11):  # pragma: no cover - the hook shims check this too
    sys.stderr.write("privacy-guard: Python 3.11 or newer is required.\n")
    raise SystemExit(2)

import tomllib  # noqa: E402  (needs the version check above)

__version__ = "0.2.0"

DEFAULT_CONFIG = Path(__file__).resolve().with_name("privacy-guard.toml")
CATEGORIES = ("secret", "personal")
SEVERITIES = ("block", "warn")
NORMALISE = ("", "digits")
MAX_REPORTED = 50
BEFORE_WINDOW = 64        # characters before a match that `ignore_before` patterns see
BINARY_SNIFF = 8000       # like git: a NUL byte in the first 8000 bytes means binary
DISCORD_EPOCH_MS = 1_420_070_400_000
_GLOBAL_UNICAST_V6 = ipaddress.IPv6Network((0x2000 << 112, 3))  # addresses starting 001...
_SHA_RE = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
COMMIT_MARK = "\x00commit "  # starts each commit in the diff stream (see --format below)

# Settings that make git's output predictable whatever the user's own config says.
# --no-replace-objects: `git replace` must not swap in a cleaned-up copy of a commit.
GIT = [
    "git", "--no-replace-objects",
    "-c", "core.quotepath=false",
    "-c", "color.ui=never",
    "-c", "diff.noprefix=false",
    "-c", "diff.mnemonicPrefix=false",
    "-c", "diff.relative=false",
    "-c", "log.showSignature=false",
    "-c", "log.mailmap=false",
    "-c", "i18n.logOutputEncoding=UTF-8",
]
# --text: scan files even when .gitattributes marks them -diff or binary. Real binary
# files are still skipped, by looking for NUL bytes the way git does (see parse_diff).
DIFF_OPTIONS = [
    "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--text",
    "-U0", "--src-prefix=a/", "--dst-prefix=b/",
]


class ConfigError(Exception):
    """The config file is missing or invalid."""


class GitError(Exception):
    """A git command failed or printed something unexpected."""


# --------------------------------------------------------------------------- checks
# Extra tests a rule can ask for with `check = "..."`, applied to the matched text
# (or to its `value` group). They cut false alarms that a regular expression can't.
# The second argument is settings.report_examples.

_DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def _public_ip(text: str, report_examples: bool = False) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if report_examples and any(ip in net for net in _DOCUMENTATION_NETWORKS):
        return True
    if isinstance(ip, ipaddress.IPv6Address):
        return ip in _GLOBAL_UNICAST_V6 and ip.is_global
    return ip.is_global and not ip.is_multicast and not ip.is_reserved


def _phone(text: str, report_examples: bool = False) -> bool:
    digits = re.sub(r"[^0-9]", "", text)
    if len(set(digits)) <= 1 or re.search(r"([ . -])\1", text):
        return False
    # Signed decimals (+51.50735), round numbers (+1000000000), timestamps (+2026-11-22 ...),
    # bare 10-digit strings with no separators (IDs) and lists of powers of two
    # ("256 512 1024") are not phone numbers.
    if re.fullmatch(r"\+[0-9]+\.[0-9]+", text) or "00000" in digits:
        return False
    if re.match(r"\+?[0-9]{4}-[0-9]{2}-[0-9]{2}", text):
        return False
    if len(digits) == 10 and re.fullmatch(r"[0-9]+", text):
        return False
    groups = [int(group) for group in re.findall(r"[0-9]+", text)]
    if len(groups) >= 3 and all(group >= 2 and group & (group - 1) == 0 for group in groups):
        return False
    longest = 15 if text.startswith("+") else 11
    return 10 <= len(digits) <= longest


def _snowflake(text: str, report_examples: bool = False) -> bool:
    # Round numbers (10**18), powers of two (2**60) and runs such as 1234567890... are not IDs.
    if text.endswith("000000") or text in "12345678901234567890" * 2:
        return False
    try:
        number = int(text)
        created_ms = (number >> 22) + DISCORD_EPOCH_MS
    except ValueError:
        return False
    if number & (number - 1) == 0:
        return False
    return DISCORD_EPOCH_MS <= created_ms <= time.time() * 1000 + 86_400_000


def _letters_and_digits(text: str, report_examples: bool = False) -> bool:
    return any(c.isalpha() for c in text) and any(c.isdigit() for c in text)


CHECKS: dict[str, Callable[[str, bool], bool]] = {
    "public_ip": _public_ip,
    "phone": _phone,
    "snowflake": _snowflake,
    "letters_and_digits": _letters_and_digits,
}


# --------------------------------------------------------------------------- config

@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    description: str
    regex: re.Pattern[str]
    ignore: tuple[re.Pattern[str], ...] = ()
    check: str = ""
    examples: tuple[re.Pattern[str], ...] = ()
    normalise: str = ""
    severity: str = "block"
    ignore_before: tuple[re.Pattern[str], ...] = ()
    paths: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True)
class FileRule:
    id: str
    category: str
    description: str
    path: re.Pattern[str]
    ignore: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True)
class Config:
    rules: tuple[Rule, ...]
    file_rules: tuple[FileRule, ...]
    skip_paths: tuple[re.Pattern[str], ...] = ()
    ignore_values: tuple[re.Pattern[str], ...] = ()
    commit_emails: tuple[re.Pattern[str], ...] = ()
    inline_marker: str = ""
    check_commit_emails: bool = True
    scan_commit_messages: bool = True
    report_examples: bool = False
    strict: bool = False
    accepted_commits: tuple[str, ...] = ()


_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_COMMIT_ID_RE = re.compile(r"[0-9a-f]{7,64}")
# Made-up values that no sensible allowlist entry should match: words, paths, numbers and
# email addresses. An entry that matches three or more of them (such as '.', '/', '\w',
# '[0-9]{2}' or '@') would switch a check off almost entirely.
_PROBES = ("qzx", "XJV", "849", "k-9", "vq/zz.y", "a.b", "Ww_3", "j k", "src/app.py",
           "docs/notes.md", ".env", "x12", "2026-1", "Zq8xW2mN4vB6cX1kL9pR3tY7uH5jG0fD",
           "src/components/forms/x.tsx", "q" "@w.ee", "zz" "@x.io", "lo" "@mn.op",
           "someone" "@longdomain.example", "ab" "@mailhost.test")  # split: not email-shaped


def load_config(path: Path | str) -> Config:
    """Read and check a config file. Anything unexpected is an error, never ignored."""
    path = Path(path)
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path.name}") from None
    except OSError as exc:  # the message names the error only, never the full path
        raise ConfigError(f"cannot read {path.name}: {exc.strerror or type(exc).__name__}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"cannot read {path.name}: it is not UTF-8 text") from None
    return load_config_text(text, path.name)


def load_config_text(text: str, name: str) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{name} is not valid TOML: {exc}") from None
    return parse_config(data)


def _keys(table: object, allowed: set[str], where: str) -> dict:
    if not isinstance(table, dict):
        raise ConfigError(f"{where} must be a table")
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(
            f"{where}: unknown key {', '.join(repr(k) for k in unknown)} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )
    return table


def _string(table: dict, key: str, where: str, *, required: bool = True) -> str:
    if key not in table:
        if required:
            raise ConfigError(f"{where}: missing {key!r}")
        return ""
    value = table[key]
    if not isinstance(value, str):
        raise ConfigError(f"{where}: {key!r} must be a string")
    return value


def _flag(table: dict, key: str, where: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}: {key!r} must be true or false")
    return value


def _compile(pattern: str, where: str, *, allowlist: bool = False) -> re.Pattern[str]:
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ConfigError(f"{where}: invalid regular expression ({exc})") from None
    if compiled.search("") is not None:
        raise ConfigError(f"{where}: the pattern matches empty text, so it would match everything")
    if allowlist and sum(1 for probe in _PROBES if compiled.search(probe)) >= 3:
        raise ConfigError(f"{where}: the pattern matches almost anything, so it would switch "
                          "the check off; make it more specific (for example anchor it with ^ and $)")
    return compiled


def _patterns(table: dict, key: str, where: str, *, allowlist: bool = True) -> tuple[re.Pattern[str], ...]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{where}: {key!r} must be a list of strings")
    return tuple(_compile(v, f"{where} {key}[{i}]", allowlist=allowlist) for i, v in enumerate(value))


def _list_of_tables(data: dict, key: str) -> list:
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ConfigError(f"{key!r} must be written as [[{key}]] tables")
    return value


RULE_KEYS = {"id", "category", "description", "regex", "ignore", "check", "examples",
             "normalise", "severity", "ignore_before", "paths"}


def parse_config(data: dict) -> Config:
    _keys(data, {"version", "settings", "allowlist", "files", "rules"}, "config")
    version = data.get("version")
    if type(version) is not int or version != 1:
        raise ConfigError("config: 'version' must be 1")
    settings = _keys(data.get("settings", {}), {
        "inline_allow_marker", "check_commit_emails", "scan_commit_messages",
        "report_examples", "strict"}, "[settings]")
    allow = _keys(data.get("allowlist", {}), {"paths", "values", "commit_emails", "commits"},
                  "[allowlist]")
    commits = allow.get("commits", [])
    if not isinstance(commits, list) or not all(
            isinstance(c, str) and _COMMIT_ID_RE.fullmatch(c) for c in commits):
        raise ConfigError("[allowlist]: 'commits' must be a list of commit ids "
                          "(7 to 64 lower-case hex characters)")

    seen: set[str] = set()

    def header(table: object, kind: str, number: int, allowed: set[str]) -> tuple[dict, str, str, str]:
        table = _keys(table, allowed, f"[[{kind}]] #{number}")
        rule_id = _string(table, "id", f"[[{kind}]] #{number}")
        if not _ID_RE.fullmatch(rule_id):
            raise ConfigError(f"[[{kind}]] #{number}: id {rule_id!r} must use a-z, 0-9 and '-'")
        if rule_id in seen:
            raise ConfigError(f"[[{kind}]] #{number}: duplicate id {rule_id!r}")
        seen.add(rule_id)
        where = f"[[{kind}]] {rule_id!r}"
        category = _string(table, "category", where)
        if category not in CATEGORIES:
            raise ConfigError(f"{where}: category must be one of {', '.join(CATEGORIES)}")
        return table, rule_id, category, _string(table, "description", where)

    file_rules = []
    for number, raw in enumerate(_list_of_tables(data, "files"), 1):
        table, rule_id, category, description = header(
            raw, "files", number, {"id", "category", "description", "path", "ignore"})
        where = f"[[files]] {rule_id!r}"
        file_rules.append(FileRule(
            rule_id, category, description,
            _compile(_string(table, "path", where), f"{where} path"),
            _patterns(table, "ignore", where)))

    rules = []
    for number, raw in enumerate(_list_of_tables(data, "rules"), 1):
        table, rule_id, category, description = header(raw, "rules", number, RULE_KEYS)
        where = f"[[rules]] {rule_id!r}"
        check = _string(table, "check", where, required=False)
        if check and check not in CHECKS:
            raise ConfigError(f"{where}: unknown check {check!r} (known: {', '.join(sorted(CHECKS))})")
        normalise = _string(table, "normalise", where, required=False)
        if normalise not in NORMALISE:
            raise ConfigError(f"{where}: normalise must be \"digits\" or left out")
        severity = _string(table, "severity", where, required=False) or "block"
        if severity not in SEVERITIES:
            raise ConfigError(f"{where}: severity must be \"block\" or \"warn\"")
        if category == "secret" and severity != "block":
            raise ConfigError(f"{where}: secret rules always block; severity \"warn\" is "
                              "only for personal rules")
        rules.append(Rule(
            rule_id, category, description,
            _compile(_string(table, "regex", where), f"{where} regex"),
            _patterns(table, "ignore", where), check,
            _patterns(table, "examples", where), normalise, severity,
            _patterns(table, "ignore_before", where),
            _patterns(table, "paths", where, allowlist=False)))

    if not rules and not file_rules:
        raise ConfigError("config has no [[rules]] or [[files]], so it would check nothing")
    return Config(
        rules=tuple(rules),
        file_rules=tuple(file_rules),
        skip_paths=_patterns(allow, "paths", "[allowlist]"),
        ignore_values=_patterns(allow, "values", "[allowlist]"),
        commit_emails=_patterns(allow, "commit_emails", "[allowlist]"),
        inline_marker=_string(settings, "inline_allow_marker", "[settings]", required=False),
        check_commit_emails=_flag(settings, "check_commit_emails", "[settings]", True),
        scan_commit_messages=_flag(settings, "scan_commit_messages", "[settings]", True),
        report_examples=_flag(settings, "report_examples", "[settings]", False),
        strict=_flag(settings, "strict", "[settings]", False),
        accepted_commits=tuple(commits),
    )


# --------------------------------------------------------------------------- matching

def severity_of(rule: Rule, cfg: Config) -> str:
    return "block" if cfg.strict or rule.severity == "block" else "warn"


# What may follow a marker: the end of the line, a space, or the end of a comment or string.
_BARE_END = re.compile(r"""$|[\s`"').\]},;>*/]|-->""")
_SCOPED = re.compile(r"""=([a-z0-9][a-z0-9-]*(?:,[a-z0-9][a-z0-9-]*)*)(?=$|[\s`"').\]};>*/]|-->)""")


@dataclass(frozen=True)
class Markers:
    named: frozenset[str] = frozenset()   # rule ids from well-formed 'marker=id,id'
    bare: bool = False                    # a well-formed bare marker
    malformed: bool = False               # something that looks like a marker but isn't one


def inline_markers(line: str, cfg: Config) -> Markers:
    """Parse the inline markers on a line. Anything not exactly 'marker' or
    'marker=id[,id]' (spaces, capitals, quotes, placeholders, 'allowlist') has no effect."""
    marker = cfg.inline_marker
    if not marker or marker not in line:
        return Markers()
    named: set[str] = set()
    bare = malformed = False
    # A marker must start a word: not-privacy-guard:allow is not a marker.
    for match in re.finditer(r"(?<![A-Za-z0-9_-])" + re.escape(marker), line):
        rest = line[match.end():]
        scoped = _SCOPED.match(rest)
        if scoped:
            named.update(scoped.group(1).split(","))
        elif _BARE_END.match(rest) and not re.match(r"\s*=", rest):
            bare = True
        else:  # including 'marker = id', which must not count as a bare marker
            malformed = True
    return Markers(frozenset(named), bare, malformed)


def find_rules(line: str, cfg: Config, path: str | None = None, *, markers: bool = True) -> list[Rule]:
    """Return the content rules that match one line of text, each at most once.

    `path` is the file the line comes from (None for commit and tag messages); rules with
    `paths` only apply to matching files. An inline marker can hide personal rules on the
    line (a bare marker hides all of them, 'marker=id' only the named ones) but never a
    secret rule: secrets can only be allowed in the config. With markers=False (commit and
    tag messages) markers are ignored.
    """
    return [rule for rule, _ in find_rule_matches(line, cfg, path, markers=markers)]


def find_rule_matches(line: str, cfg: Config, path: str | None = None, *,
                      markers: bool = True) -> list[tuple[Rule, str]]:
    """Like find_rules, with the value each rule found (kept in memory, never printed)."""
    marks = inline_markers(line, cfg) if markers else Markers()
    found = []
    for rule in cfg.rules:
        if rule.paths and (path is None or not any(p.search(path) for p in rule.paths)):
            continue
        if rule.category != "secret" and (marks.bare or rule.id in marks.named):
            continue
        value = _match_value(rule, line, cfg)
        if value is not None:
            found.append((rule, value))
    return found


def marker_problems(line: str, cfg: Config, found: list[Rule]) -> list[str]:
    """Why an inline marker on a line with findings didn't do what it seems to ask."""
    if not found:
        return []
    marks = inline_markers(line, cfg)
    known = {rule.id for rule in cfg.rules}
    secret_ids = {rule.id for rule in found if rule.category == "secret"}
    marker = cfg.inline_marker
    problems = []
    if marks.malformed:
        problems.append(f"a malformed {marker} marker, which has no effect "
                        f"(write {marker} or {marker}=<rule-id>[,<rule-id>])")
    if marks.named - known:
        problems.append(f"{marker} names an unknown rule id, so it has no effect")
    if marks.named & secret_ids:
        problems.append(f"{marker} can't hide secret rules; allowlist them in the config instead")
    return problems


def _match_value(rule: Rule, line: str, cfg: Config) -> str | None:
    """The first value on the line that the rule reports, or None."""
    has_value = "value" in rule.regex.groupindex
    for match in rule.regex.finditer(line):
        if rule.ignore_before:
            before = line[max(0, match.start() - BEFORE_WINDOW):match.start()]
            if any(p.search(before) for p in rule.ignore_before):
                continue
        whole = match.group(0)
        value = match.group("value") if has_value and match.group("value") is not None else whole
        probe = re.sub(r"[^0-9]", "", value) if rule.normalise == "digits" else value
        if any(p.search(probe) for p in rule.ignore):
            continue
        if not cfg.report_examples and any(p.search(probe) for p in rule.examples):
            continue
        if any(p.search(probe) for p in cfg.ignore_values):
            continue
        if rule.check and not CHECKS[rule.check](value, cfg.report_examples):
            continue
        return value
    return None


def fingerprint(value: str) -> str:
    """A short hash of a found value, to tell findings apart without keeping the value."""
    return hashlib.sha256(value.strip().encode("utf-8", "replace")).hexdigest()[:16]


def find_file_rules(path: str, cfg: Config) -> list[FileRule]:
    """Return the file-name rules that match a repo-relative path (forward slashes)."""
    return [r for r in cfg.file_rules
            if r.path.search(path) and not any(p.search(path) for p in r.ignore)]


def email_allowed(email: str, cfg: Config) -> bool:
    return any(p.search(email) for p in cfg.commit_emails)


# --------------------------------------------------------------------------- diff parsing

@dataclass(frozen=True)
class FileEvent:
    """A file that a commit (or the index) adds or changes."""
    commit: str
    path: str


@dataclass(frozen=True)
class LineEvent:
    """A line that a commit (or the index) adds."""
    commit: str
    path: str
    lineno: int
    text: str


@dataclass(frozen=True)
class Finding:
    where: str
    rule_id: str
    category: str
    description: str
    commit: str = ""
    severity: str = "block"
    fingerprint: str = field(default="", compare=False, repr=False)  # hash of the value, never shown


_HUNK_RE = re.compile(r"(@{2,}) (?:-[0-9]+(?:,[0-9]+)? )+\+([0-9]+)(?:,[0-9]+)? @{2,}")
_INDEX_RE = re.compile(r"index [0-9a-f]+(?:,[0-9a-f]+)*\.\.([0-9a-f]+)")


class BlobSniffer:
    """Tells whether a blob is binary the way git does: a NUL byte in its first 8000 bytes.
    Reads blobs through one `git cat-file --batch` process, started on first use."""

    def __init__(self, top: Path) -> None:
        self.top = top
        self.proc: subprocess.Popen | None = None
        self.cache: dict[str, bool] = {}

    def __call__(self, blob: str) -> bool:
        if _is_zero(blob):
            return False
        if blob not in self.cache:
            self.cache[blob] = self._read(blob)
        return self.cache[blob]

    def _read(self, blob: str) -> bool:
        if self.proc is None:
            self.proc = subprocess.Popen([*GIT, "cat-file", "--batch"], cwd=self.top,
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL)
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(f"{blob}\n".encode())
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().decode("ascii", "replace").split()
        if len(header) != 3 or header[1] != "blob":
            return False  # missing (a submodule commit) or not a file
        size = int(header[2])
        data = self.proc.stdout.read(size + 1)  # the content and a newline
        return b"\x00" in data[:min(size, BINARY_SNIFF)]

    def close(self) -> None:
        if self.proc is not None:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait()
            self.proc = None

    def __enter__(self) -> "BlobSniffer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def _take_quoted(text: str) -> tuple[str, str]:
    """Read a C-style quoted name, as git prints unusual file names. Returns (name, rest)."""
    out = bytearray()
    i = 1
    while i < len(text):
        char = text[i]
        if char == '"':
            return out.decode("utf-8", "replace"), text[i + 1:]
        if char == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 2
                continue
            if re.fullmatch(r"[0-7]{3}", text[i + 1:i + 4]):
                out.append(int(text[i + 1:i + 4], 8))
                i += 4
                continue
        out += char.encode("utf-8")
        i += 1
    raise GitError("could not read a quoted file name in git's output")


def _strip(name: str, prefix: str) -> str:
    return name[len(prefix):] if name.startswith(prefix) else name


def _section_path(line: str) -> str:
    """The file name from a 'diff --git' or 'diff --cc' line (renames are turned off)."""
    if line.startswith("diff --git "):
        rest = line[len("diff --git "):]
        if rest.startswith('"'):
            _, rest = _take_quoted(rest)
            rest = rest.lstrip(" ")
            return _strip(_take_quoted(rest)[0] if rest.startswith('"') else rest, "b/")
        half = (len(rest) - 5) // 2  # "a/" + name + " b/" + name
        if half > 0 and rest.startswith("a/") and rest[2 + half:5 + half] == " b/":
            return rest[5 + half:]
        if " b/" in rest:
            return rest.split(" b/", 1)[1]
    for prefix in ("diff --cc ", "diff --combined "):
        if line.startswith(prefix):
            rest = line[len(prefix):]
            return _take_quoted(rest)[0] if rest.startswith('"') else rest
    raise GitError("could not read a file name in git's diff output")


def parse_diff(lines: Iterable[bytes | str],
               is_binary: Callable[[str], bool] | None = None) -> Iterator[FileEvent | LineEvent]:
    """Turn `git diff -U0 --text` / `git log -p -U0 --cc --text` output into file and
    added-line events.

    A commit starts with a line holding COMMIT_MARK and the commit id. Diff body lines
    always start with ' ', '+', '-' or '\\', so they can't be mistaken for it. Merge commits
    use git's combined format, where only lines new in the merge itself (every column '+')
    count as added: the rest came from a parent and is scanned with that parent.

    Because of --text, binary files come through as text too. With `is_binary` (given the
    new blob id from the diff's index line) a file is binary exactly when git would say so:
    a NUL byte in the first 8000 bytes of the file. Without it, the first 8000 bytes of the
    file's added lines are checked instead, and lines are only held back until then, so a
    NUL byte later on never drops a line already passed on.
    """
    commit = ""
    path: str | None = None
    pending = deleted = in_header = False
    parents = 1
    lineno = 0
    held: list[LineEvent] = []   # added lines kept back until the file is known not to be binary
    sniffed = 0
    binary = False
    decided = False              # whether is_binary has settled the question for this file
    for raw in lines:
        line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        line = line.rstrip("\r\n")
        if not line:
            continue
        if line.startswith(COMMIT_MARK) or line.startswith("diff --"):
            if not binary:
                yield from held
            held, sniffed, binary, decided = [], 0, False, False
            if pending and not deleted and path is not None:
                yield FileEvent(commit, path)
            pending = False
            if line.startswith(COMMIT_MARK):
                commit, path, in_header = line[len(COMMIT_MARK):].strip(), None, False
            else:
                path, deleted, in_header, pending = _section_path(line), False, True, True
            continue
        hunk = _HUNK_RE.match(line)
        if hunk and path is not None:
            if pending and not deleted:
                yield FileEvent(commit, path)
            pending = in_header = False
            parents = len(hunk.group(1)) - 1
            lineno = int(hunk.group(2))
            continue
        if in_header:
            if line.startswith("deleted file mode"):
                deleted = True
            index = _INDEX_RE.match(line)
            if index and is_binary is not None:
                binary, decided = is_binary(index.group(1)), True
            continue
        if path is None or line.startswith("\\") or binary:
            continue
        prefix = line[:parents]
        if "-" in prefix:  # removed lines don't count, not even for the binary test
            continue
        if not decided and sniffed < BINARY_SNIFF:
            if "\x00" in line[:BINARY_SNIFF - sniffed]:
                binary, held = True, []
                continue
            sniffed += len(line)
        if prefix == "+" * parents:
            text = line[parents:]
            if lineno == 1 and text.startswith("\ufeff"):  # a byte order mark isn't content
                text = text[1:]
            event = LineEvent(commit, path, lineno, text)
            if not decided and sniffed < BINARY_SNIFF:
                held.append(event)
            else:
                yield from held
                held = []
                yield event
        lineno += 1
    if not binary:
        yield from held
    if pending and not deleted and path is not None:
        yield FileEvent(commit, path)


# --------------------------------------------------------------------------- git

def git(top: Path, args: list[str], stdin: str | None = None) -> bytes:
    proc = subprocess.run([*GIT, *args], cwd=top, capture_output=True,
                          input=stdin.encode() if stdin is not None else None)
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"'git {args[0]}' failed: {detail}")
    return proc.stdout


def _git_ok(top: Path, args: list[str]) -> bool:
    return subprocess.run([*GIT, *args], cwd=top, capture_output=True).returncode == 0


def git_lines(top: Path, args: list[str], stdin: str | None = None) -> Iterator[bytes]:
    """Stream a git command's output line by line, so large histories stay cheap. Long
    lists of revisions go in through `stdin` (with --stdin), never on the command line,
    which Windows limits to about 32,000 characters."""
    with tempfile.TemporaryFile() as err:
        proc = subprocess.Popen([*GIT, *args], cwd=top, stdout=subprocess.PIPE, stderr=err,
                                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL)
        assert proc.stdout is not None
        writer = None
        if stdin is not None:
            def feed() -> None:
                try:
                    proc.stdin.write(stdin.encode())  # type: ignore[union-attr]
                    proc.stdin.close()  # type: ignore[union-attr]
                except OSError:
                    pass
            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
        try:
            yield from proc.stdout
        except BaseException:
            proc.kill()
            proc.wait()
            raise
        proc.stdout.close()
        if writer is not None:
            writer.join()
        if proc.wait() != 0:
            err.seek(0)
            detail = err.read().decode("utf-8", "replace").strip()
            raise GitError(f"'git {args[0]}' failed: {detail}")


def repo_top() -> Path:
    return Path(git(Path.cwd(), ["rev-parse", "--show-toplevel"]).decode("utf-8").strip())


def _is_zero(sha: str) -> bool:
    return set(sha) == {"0"}


def _object_type(top: Path, sha: str) -> str:
    return git(top, ["cat-file", "-t", sha]).decode("ascii", "replace").strip()


def _peel_tags(top: Path, name: str, sha: str) -> tuple[list[tuple[str, str]], str, str]:
    """Follow an annotated tag, and any tags it points to in turn, to the object at the end.
    Returns ([(name, tag id), ...], final object id, final object type)."""
    chain = []
    kind = _object_type(top, sha)
    while kind == "tag" and len(chain) < 20:
        chain.append((name, sha))
        header = git(top, ["cat-file", "tag", sha]).decode("utf-8", "replace").split("\n\n", 1)[0]
        target = re.search(r"^object ([0-9a-f]+)$", header, re.M)
        if not target:
            break
        sha = target.group(1)
        kind = _object_type(top, sha)
    return chain, sha, kind


def _unique(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    return [item for item in items if not (item in seen or seen.add(item))]


@dataclass
class PushPlan:
    revs: list[str] = field(default_factory=list)    # revisions for git log --stdin
    tips: list[str] = field(default_factory=list)    # pushed objects that lead to a commit
    known: list[str] = field(default_factory=list)   # the remote's current tips we have
    updates: list[tuple[str, str]] = field(default_factory=list)  # (pushed tip, remote's old tip)
    tags: list[tuple[str, str]] = field(default_factory=list)     # annotated tag objects
    blobs: list[tuple[str, str]] = field(default_factory=list)    # refs and tags that end at a file
    note: str = ""


def _commits_we_have(top: Path, shas: list[str]) -> list[str]:
    """The ids in `shas` that exist here and lead to a commit (commits and tags of them)."""
    if not shas:
        return []
    proc = subprocess.run([*GIT, "cat-file", "--batch-check=%(objectname) %(objecttype)"],
                          cwd=top, input="".join(f"{s}^{{commit}}\n" for s in shas).encode(),
                          capture_output=True)
    answers = proc.stdout.decode("ascii", "replace").splitlines()  # one line per id, in order
    return [sha for sha, answer in zip(shas, answers) if answer.endswith(" commit")]


def _remote_tips(top: Path, remote: str) -> list[str] | None:
    """The current branch and tag tips at `remote` (the URL the push goes to), asked live
    with `git ls-remote`, or None if it can't be asked (the push is then scanned without
    them). The push URL matters: a remote's fetch URL can point somewhere else."""
    if not remote or remote.startswith("-"):
        return None
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        proc = subprocess.run([*GIT, "ls-remote", "--quiet", remote], cwd=top, capture_output=True,
                              env=env, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    shas = (line.split("\t", 1)[0].strip()
            for line in proc.stdout.decode("utf-8", "replace").splitlines())
    return _unique(sha for sha in shas if _SHA_RE.fullmatch(sha))


def plan_push(top: Path, ref_lines: str, remote: str = "") -> PushPlan:
    """Work out what a push would send, from the lines git gives pre-push.

    Each line is '<local ref> <local sha> <remote ref> <remote sha>'. Deletions are
    skipped. Commits count as already on the remote only if they are reachable from the
    remote's own tips: those git reports for this push, and, when a new branch or tag is
    pushed, those `git ls-remote` reports live (one extra request to the remote). Local
    remote-tracking branches are never trusted: they can be stale, for example after the
    remote's URL changes. Tags, and refs or tags that end at a file, are found by object type.
    """
    plan = PushPlan()
    new_ref = False
    for line in ref_lines.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 4 or not all(_SHA_RE.fullmatch(p) for p in (parts[1], parts[3])):
            raise GitError("unexpected ref line from git pre-push")
        local_ref, local_sha, remote_ref, remote_sha = parts
        if _is_zero(local_sha):
            continue
        new_ref = new_ref or _is_zero(remote_sha)
        name = remote_ref if remote_ref.startswith("refs/") else local_ref
        name = re.sub(r"^refs/(?:tags|heads)/", "", name)
        chain, final, kind = _peel_tags(top, name, local_sha)
        plan.tags.extend(chain)
        if kind == "blob":
            plan.blobs.append((name, final))
        if _git_ok(top, ["cat-file", "-e", f"{local_sha}^{{commit}}"]):
            plan.tips.append(local_sha)
            old = _commits_we_have(top, [remote_sha]) if not _is_zero(remote_sha) else []
            plan.updates.append((local_sha, old[0] if old else ""))
        if not _is_zero(remote_sha):
            plan.known.extend(_commits_we_have(top, [remote_sha]))
    if new_ref and plan.tips:
        live = _remote_tips(top, remote)
        if live is None:
            plan.note = ("privacy-guard: couldn't list the remote's branches, so new branches and "
                         "tags are scanned back to their first commit.")
        else:
            plan.known.extend(_commits_we_have(top, live))
    plan.tips, plan.known = _unique(plan.tips), _unique(plan.known)
    if plan.tips:
        plan.revs = [*plan.tips, *(f"^{sha}" for sha in plan.known)]
    return plan


# Everything under refs/ and HEAD, except the local stash, which is never pushed.
HISTORY_REVISIONS = ["--exclude=refs/stash", "--all"]


def _tree_paths(top: Path, treeish: str) -> list[str]:
    out = git(top, ["ls-tree", "-r", "-z", "--name-only", treeish])
    return [p.decode("utf-8", "replace") for p in out.split(b"\x00") if p]


# --------------------------------------------------------------------------- scanning

def _line_finding(where: str, rule: Rule, cfg: Config, commit: str = "", value: str = "") -> Finding:
    return Finding(where, rule.id, rule.category, rule.description, commit, severity_of(rule, cfg),
                   fingerprint(value) if value else "")


def accepted(commit: str, cfg: Config) -> bool:
    """Whether a commit (or tag object) is listed in [allowlist] commits."""
    return bool(commit) and any(commit.startswith(c) for c in cfg.accepted_commits)


def _marker_finding(where: str, problem: str, commit: str = "") -> Finding:
    return Finding(where, "inline-marker", "marker", problem, commit, "warn")


def scan_events(events: Iterable[FileEvent | LineEvent], cfg: Config) -> list[Finding]:
    findings: list[Finding] = []
    skipped: dict[str, bool] = {}
    for event in events:
        if accepted(event.commit, cfg):
            continue
        short = event.commit[:12]
        if isinstance(event, FileEvent):
            for rule in find_file_rules(event.path, cfg):
                findings.append(Finding(event.path, rule.id, rule.category, rule.description, short))
            continue
        skip = skipped.get(event.path)
        if skip is None:
            skip = skipped[event.path] = any(p.search(event.path) for p in cfg.skip_paths)
        if skip:
            continue
        where = f"{event.path}:{event.lineno}"
        seen: set[str] = set()
        # A lone carriage return (old Mac line endings) is a line break too.
        for piece in event.text.split("\r"):
            matches = find_rule_matches(piece, cfg, event.path)
            for rule, value in matches:
                if rule.id not in seen:
                    seen.add(rule.id)
                    findings.append(_line_finding(where, rule, cfg, short, value))
            for problem in marker_problems(piece, cfg, [rule for rule, _ in matches]):
                findings.append(_marker_finding(where, problem, short))
    return findings


def scan_message(message: str, cfg: Config, label: str, commit: str = "") -> list[Finding]:
    """Scan a commit or tag message. Inline markers have no effect in messages."""
    if message.startswith("\ufeff"):
        message = message[1:]
    findings = []
    for number, text in enumerate(message.splitlines(), 1):
        for rule, value in find_rule_matches(text, cfg, markers=False):
            findings.append(_line_finding(f"{label} line {number}", rule, cfg, commit, value))
    return findings


def _email_finding(who: str, commit: str = "", source: str = "") -> Finding:
    return Finding(f"{who} email{source}", "commit-email", "personal",
                   "an email address that is not in allowlist.commit_emails "
                   "(use your GitHub noreply address)", commit)


def scan_identity(top: Path, cfg: Config) -> list[Finding]:
    """Check the author and committer email the next commit will carry."""
    if not cfg.check_commit_emails:
        return []
    bad = []
    for variable, role in (("GIT_AUTHOR_IDENT", "author"), ("GIT_COMMITTER_IDENT", "committer")):
        ident = git(top, ["var", variable]).decode("utf-8", "replace")
        match = re.search(r"<([^<>]*)>", ident)
        if not email_allowed(match.group(1) if match else "", cfg):
            bad.append(role)
    return [_email_finding(" and ".join(bad), source=" (git config user.email)")] if bad else []


def scan_staged(top: Path, cfg: Config) -> list[Finding]:
    findings = scan_identity(top, cfg)
    with BlobSniffer(top) as sniff:
        diff = git_lines(top, ["diff", "--cached", *DIFF_OPTIONS])
        return findings + scan_events(parse_diff(diff, sniff), cfg)


# --------------------------------------------------------------------------- commit messages

CUT_LINE = "------------------------ >8 ------------------------"
_AUTO_COMMENT_CHARS = "#;@!$%^&|:"


@dataclass(frozen=True)
class MessageContext:
    """What the commit-msg hook knows about how git will clean the message up."""
    editor: bool = False   # git opened an editor (it sets GIT_EDITOR=: for hooks when it won't)
    cleanup: str = ""      # commit.cleanup from the config, or "" when not set
    comment: str = "#"     # the comment string, or "" when git chooses it (core.commentChar=auto)


def _git_version(top: Path) -> tuple[int, int]:
    found = re.search(r"(\d+)\.(\d+)", git(top, ["version"]).decode("ascii", "replace"))
    return (int(found.group(1)), int(found.group(2))) if found else (0, 0)


def message_context(top: Path, editor: bool) -> MessageContext:
    def config(key: str) -> str:
        proc = subprocess.run([*GIT, "config", "--get", key], cwd=top, capture_output=True)
        return proc.stdout.decode("utf-8", "replace").rstrip("\r\n") if proc.returncode == 0 else ""

    comment = config("core.commentString") if _git_version(top) >= (2, 45) else ""
    comment = comment or config("core.commentChar") or "#"
    if comment.lower() == "auto":
        comment = ""
    return MessageContext(editor, config("commit.cleanup").strip().lower(), comment)


def _guess_comment(lines: list[str]) -> str:
    """The comment character git picked for core.commentChar=auto, judged from its template."""
    for line in lines:
        found = re.fullmatch(r"(\S+) " + re.escape(CUT_LINE), line)
        if found:
            return found.group(1)
    for line in reversed(lines):
        if line.strip():
            return line[0] if line[0] in _AUTO_COMMENT_CHARS else "#"
    return "#"


def _changed_paths(top: Path) -> set[str]:
    """Files a `commit -v` diff can show: staged changes (also against HEAD^, for --amend)
    and, for `-v -v`, changes not staged yet."""
    paths: set[str] = set()
    for args in (["diff", "--cached", "--name-only", "-z", "--no-renames"],
                 ["diff", "--cached", "--name-only", "-z", "--no-renames", "HEAD^"],
                 ["diff", "--name-only", "-z", "--no-renames"]):
        proc = subprocess.run([*GIT, *args], cwd=top, capture_output=True)
        if proc.returncode == 0:
            paths.update(p.decode("utf-8", "replace") for p in proc.stdout.split(b"\x00") if p)
    return paths


def _is_verbose_diff(lines: list[str], top: Path | None) -> bool:
    """Whether the text below a cut line is git's own `commit -v` diff: there is a diff,
    and every file it names is one git would show (when that can be checked)."""
    paths = []
    for line in lines:
        if line.startswith("diff --git "):
            try:
                paths.append(_section_path(line))
            except GitError:
                return False
    if not paths:
        return False
    return top is None or set(paths) <= _changed_paths(top)


def scan_message_file(path: Path, cfg: Config, editor: bool = False, top: Path | None = None,
                      context: MessageContext | None = None) -> list[Finding]:
    """Scan a commit message the way git will keep it.

    git's cleanup mode decides what survives: with an editor the default is `strip`, which
    drops comment lines; otherwise (`commit -m`, `-F`) it is `whitespace`, which keeps them.
    `commit.cleanup` in the config changes that, and is respected. A `--cleanup` option on
    the command line can't be seen by a hook (the README lists this).

    Below git's cut line ("# ------------------------ >8 ------------------------" and two
    comment lines), git drops everything in scissors mode or when it added its own `-v`
    diff there. The text is only left out in those cases; a cut line pasted into a message
    by hand, with a diff of files that aren't changed, is scanned like the rest.
    The pre-push hook and the history scan check committed messages again, in full.
    """
    if not cfg.scan_commit_messages:
        return []
    context = context or MessageContext(editor=editor)
    text = Path(path).read_bytes().decode("utf-8", "replace")
    if text.startswith("\ufeff"):
        text = text[1:]
    lines = text.splitlines()
    comment = context.comment or _guess_comment(lines)
    mode = context.cleanup if context.cleanup not in ("", "default") else (
        "strip" if context.editor else "whitespace")
    cut_line = f"{comment} {CUT_LINE}"
    for index, line in enumerate(lines):
        if line == cut_line and all(later.startswith(comment) for later in lines[index + 1:index + 3]) \
                and len(lines) >= index + 3:
            if (mode == "scissors" and context.editor) or _is_verbose_diff(lines[index + 3:], top):
                lines = lines[:index]
            break
    if mode == "strip":
        lines = ["" if line.startswith(comment) else line for line in lines]
    return scan_message("\n".join(lines), cfg, "commit message")


# --------------------------------------------------------------------------- history and pushes

def iter_commits(top: Path, revs: list[str], stdin: str | None = None,
                 extra: tuple[str, ...] = ()) -> Iterator[tuple[str, str, str, str]]:
    """Yield (sha, author email, committer email, message) for each commit in revs."""
    nonce = secrets.token_hex(16)  # a separator no commit message can contain by chance
    out = git(top, ["log", "--no-color", "--no-show-signature", *extra,
                    f"--format=%x00{nonce}%x00%H%x00%ae%x00%ce%x00%B", *revs, "--"], stdin)
    for record in out.decode("utf-8", "replace").split(f"\x00{nonce}\x00")[1:]:
        parts = record.split("\x00", 3)
        if len(parts) != 4:
            raise GitError("unexpected 'git log' output")
        yield parts[0].strip(), parts[1], parts[2], parts[3]


_ARMOUR_HEADER = re.compile(r"[A-Za-z][A-Za-z0-9-]*: .*")
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/]{1,76}={0,2}")
_CHECKSUM_LINE = re.compile(r"=[A-Za-z0-9+/]{4}")


def strip_signature(message: str) -> str:
    """Remove the body of a signature block at the end of a tag message, but only of a
    well-formed one: the last BEGIN line, optional armour headers followed by a blank line
    (PGP), a body of base64 lines only, and a matching END line at the very end. Armour
    header values are kept, so they are scanned; anything not well formed is left in."""
    lines = message.rstrip("\n").split("\n")
    for start in range(len(lines) - 1, -1, -1):
        begin = re.fullmatch(r"-----BEGIN (PGP|SSH) SIGNATURE-----", lines[start])
        if not begin:
            continue
        if len(lines) - start < 3 or lines[-1] != f"-----END {begin.group(1)} SIGNATURE-----":
            return message
        inner = lines[start + 1:-1]
        headers: list[str] = []
        index = 0
        if begin.group(1) == "PGP":
            while index < len(inner) and _ARMOUR_HEADER.fullmatch(inner[index]):
                headers.append(inner[index])
                index += 1
            if headers and (index >= len(inner) or inner[index] != ""):
                return message
            if index < len(inner) and inner[index] == "":
                index += 1
        body = inner[index:]
        if body and all(_BASE64_LINE.fullmatch(line) or _CHECKSUM_LINE.fullmatch(line) for line in body):
            return "\n".join(lines[:start] + headers)
        return message
    return message


def scan_tags(top: Path, cfg: Config, tags: list[tuple[str, str]]) -> list[Finding]:
    """Scan annotated tag objects: the tagger's email and the tag message."""
    findings: list[Finding] = []
    for name, sha in tags:
        if accepted(sha, cfg):
            continue
        raw = git(top, ["cat-file", "tag", sha]).decode("utf-8", "replace")
        header, _, message = raw.partition("\n\n")
        message = strip_signature(message)
        tagger = re.search(r"^tagger [^\n]*<([^<>\n]*)>", header, re.M)
        if cfg.check_commit_emails and tagger and not email_allowed(tagger.group(1), cfg):
            findings.append(_email_finding(f"tag {name} tagger", sha[:12]))
        if cfg.scan_commit_messages:
            findings += scan_message(message, cfg, f"tag {name} message", sha[:12])
    return findings


def scan_blobs(top: Path, cfg: Config, blobs: list[tuple[str, str]]) -> list[Finding]:
    """Scan files that a tag or ref points at directly (`git tag name <blob>`)."""
    findings: list[Finding] = []
    for name, sha in _unique_pairs(blobs):
        data = git(top, ["cat-file", "blob", sha])
        if b"\x00" in data[:BINARY_SNIFF]:
            continue
        text = data.decode("utf-8", "replace").lstrip("\ufeff")
        events = [LineEvent("", f"{name} (a file the ref points at)", n, line)
                  for n, line in enumerate(text.splitlines(), 1)]
        findings += [dataclasses.replace(f, commit=sha[:12]) for f in scan_events(events, cfg)]
    return findings


def _unique_pairs(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[str] = set()
    return [(n, s) for n, s in pairs if not (s in seen or seen.add(s))]


def history_refs(top: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """Annotated tags, and refs or tags that end at a file, anywhere under refs/ (except
    the stash)."""
    out = git(top, ["for-each-ref", "--format=%(objecttype)%00%(objectname)%00%(refname)"]
              ).decode("utf-8", "replace")
    tags: list[tuple[str, str]] = []
    blobs: list[tuple[str, str]] = []
    for line in out.splitlines():
        kind, sha, ref = (line.split("\x00") + ["", ""])[:3]
        if ref == "refs/stash" or kind not in ("tag", "blob"):
            continue
        name = re.sub(r"^refs/(?:tags/|heads/)?", "", ref)
        chain, final, final_kind = _peel_tags(top, name, sha)
        tags.extend(chain)
        if final_kind == "blob":
            blobs.append((name, final))
    return tags, blobs


def scan_revisions(top: Path, cfg: Config, revs: list[str], *, via_stdin: bool = False,
                   no_walk: bool = False) -> list[Finding]:
    """Scan each commit in revs on its own: emails, message and added lines. With
    via_stdin the revisions go to git on standard input, however many there are."""
    if not revs:
        return []
    stdin = "".join(f"{rev}\n" for rev in revs) if via_stdin else None
    args = ["--stdin"] if via_stdin else revs
    extra = ("--no-walk",) if no_walk else ()
    findings: list[Finding] = []
    if cfg.check_commit_emails or cfg.scan_commit_messages:
        for sha, author, committer, message in iter_commits(top, args, stdin, extra):
            if accepted(sha, cfg):
                continue
            short = sha[:12]
            if cfg.check_commit_emails:
                bad = [role for role, email in (("author", author), ("committer", committer))
                       if not email_allowed(email, cfg)]
                if bad:
                    findings.append(_email_finding(" and ".join(bad), short))
            if cfg.scan_commit_messages:
                findings += scan_message(message, cfg, "commit message", short)
    with BlobSniffer(top) as sniff:
        log = git_lines(top, ["log", "--cc", "--no-show-signature", *DIFF_OPTIONS, *extra,
                              "--format=%x00commit %H", *args, "--"], stdin)
        return findings + scan_events(parse_diff(log, sniff), cfg)


def _where_key(finding: Finding) -> tuple[str, str]:
    path = re.sub(r"(?::[0-9]+)?(?: \(in the pushed files\))?$", "", finding.where)
    return path, finding.rule_id


def accepted_keys(top: Path, cfg: Config) -> set[tuple[str, str, str]]:
    """(file, rule, value hash) for what the commits in [allowlist] commits bring in, so the
    tree check doesn't report those exact values again (other values still count)."""
    present = _commits_we_have(top, list(cfg.accepted_commits))
    if not present:
        return set()
    plain = dataclasses.replace(cfg, accepted_commits=())
    found = scan_revisions(top, plain, present, via_stdin=True, no_walk=True)
    return {(*_where_key(f), f.fingerprint) for f in found}


def _is_ancestor(top: Path, older: str, newer: str) -> bool:
    return _git_ok(top, ["merge-base", "--is-ancestor", older, newer])


def scan_pushed_trees(top: Path, cfg: Config, plan: PushPlan, already: list[Finding],
                      suppressed: set[tuple[str, str, str]] = frozenset()) -> list[Finding]:
    """Check what the pushed trees contain, not just what each commit changes.

    A merge such as `git merge -s ours`, or a force-push back to an older commit, can bring
    back a file or a line that was deleted, without any commit adding it again. For each
    pushed tip, the bases are the commits where its new history meets what the remote
    already has (git rev-list --boundary), plus the remote's old tip when a force-push
    moves the branch to something that doesn't contain it. Then:
    - file-name rules run over every file in the pushed tree that isn't in a base;
    - content rules run over the difference between each base and the pushed tip.
    A tip the remote already has in full, pushed without a force, brings nothing new.
    Anything already reported for the same file and rule isn't repeated.
    """
    reported = {_where_key(f) for f in already}
    findings: list[Finding] = []

    def add(finding: Finding) -> None:
        key = _where_key(finding)
        if key not in reported and (*key, finding.fingerprint) not in suppressed:
            reported.add(key)
            findings.append(finding)

    for tip in plan.tips:
        new: list[str] = []
        boundary: list[str] = []
        if plan.known:
            out = git(top, ["rev-list", "--boundary", "--stdin"],
                      "".join(f"{rev}\n" for rev in [tip, *(f"^{k}" for k in plan.known)]))
            for line in out.decode("ascii", "replace").split():
                (boundary if line.startswith("-") else new).append(line.lstrip("-"))
        rolled_back = [old for pushed, old in plan.updates
                       if pushed == tip and old and old != tip and not _is_ancestor(top, old, tip)]
        if plan.known and not new and not rolled_back:
            continue
        bases = _unique([*boundary, *rolled_back])
        on_base = {p for base in bases for p in _tree_paths(top, base)}
        for path in _tree_paths(top, tip):
            if path not in on_base:
                for rule in find_file_rules(path, cfg):
                    add(Finding(f"{path} (in the pushed files)", rule.id, rule.category,
                                rule.description, tip[:12]))
        for base in bases:
            with BlobSniffer(top) as sniff:
                diff = git_lines(top, ["diff", *DIFF_OPTIONS, base, tip, "--"])
                for finding in scan_events(parse_diff(diff, sniff), cfg):
                    if finding.rule_id != "inline-marker":
                        add(dataclasses.replace(finding, where=f"{finding.where} (in the pushed files)",
                                                commit=tip[:12]))
    return findings


def scan_push(top: Path, cfg: Config, ref_lines: str, remote: str = "") -> list[Finding]:
    plan = plan_push(top, ref_lines, remote)
    if plan.note:
        sys.stderr.write(plan.note + "\n")
    findings = scan_revisions(top, cfg, plan.revs, via_stdin=True)
    findings += scan_tags(top, cfg, plan.tags)
    findings += scan_blobs(top, cfg, plan.blobs)
    suppressed = accepted_keys(top, cfg) if cfg.accepted_commits else set()
    return findings + scan_pushed_trees(top, cfg, plan, findings, suppressed)


def scan_history(top: Path, cfg: Config) -> list[Finding]:
    tags, blobs = history_refs(top)
    return (scan_revisions(top, cfg, HISTORY_REVISIONS) + scan_tags(top, cfg, tags)
            + scan_blobs(top, cfg, blobs))


# --------------------------------------------------------------------------- config for hooks

def _relative(path: Path, top: Path) -> str | None:
    try:
        return path.resolve().relative_to(top.resolve()).as_posix()
    except (ValueError, OSError):
        return None


def load_hook_config(top: Path, source: str) -> tuple[Config, str, str]:
    """Load the default config the way a hook should see it.

    source "index": the staged copy (pre-commit, commit-msg), or the copy in HEAD if the
    config has been removed from the index; "head": the copy committed in HEAD (pre-push);
    anything else, or a config git doesn't track at all: the file on disk.
    Returns (config, display name, note); the note says when on-disk edits were ignored.
    """
    rel = _relative(DEFAULT_CONFIG, top)
    name = rel or DEFAULT_CONFIG.name
    if rel and source in ("index", "head"):
        specs = [(f":{rel}", "staged"), (f"HEAD:{rel}", "committed")] if source == "index" \
            else [(f"HEAD:{rel}", "committed")]
        for spec, state in specs:
            proc = subprocess.run([*GIT, "show", spec], cwd=top, capture_output=True)
            if proc.returncode != 0:
                continue
            try:
                text = proc.stdout.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise ConfigError(f"cannot read {name}: it is not UTF-8 text") from None
            note = ""
            try:
                disk = DEFAULT_CONFIG.read_bytes().decode("utf-8-sig", "replace")
            except OSError:
                disk = None
            if disk is None or disk.replace("\r\n", "\n") != text.replace("\r\n", "\n"):
                note = (f"privacy-guard: using the {state} copy of {name}; edits that aren't "
                        f"{state} yet are ignored.")
            return load_config_text(text, name), name, note
    return load_config(DEFAULT_CONFIG), name, ""


# --------------------------------------------------------------------------- output

ACTIONS = {"staged": "commit", "commit-msg": "commit", "push": "push",
           "history": "history scan", "check-config": "config check"}


def _advice(action: str, cfg: Config, config_name: str) -> list[str]:
    allow = f"add an allowlist entry in {config_name}"
    if cfg.inline_marker and action == "commit":
        allow = (f"add '{cfg.inline_marker}=<rule-id>' to the line for a personal detail "
                 f"(secrets can only be allowed in the config), or {allow}")
    allow = f"False alarm? {allow[0].upper()}{allow[1:]}."
    if action == "commit":
        return [
            "Remove the value. Keep secrets in an untracked file or a secret manager.",
            allow,
            "To skip the guard once (not recommended): git commit --no-verify",
        ]
    if action == "push":
        return [
            "Nothing has been pushed. Fix the commits listed above first:",
            "  latest commit: edit the file, stage it, then git commit --amend",
            "  older commits: git rebase -i <commit>~1, mark them 'edit', fix, amend, continue",
            allow,
            "To skip the guard once (not recommended): git push --no-verify",
        ]
    return [
        "Check each finding. Anything real in history needs the history rewritten,",
        "and any real secret should be revoked, because old commits may already be copied.",
        allow,
    ]


def _listing(findings: list[Finding], limit: int) -> list[str]:
    lines = []
    for finding in findings[:limit]:
        where = f"{finding.commit} {finding.where}" if finding.commit else finding.where
        lines.append(f"  {where}")
        lines.append(f"      {finding.category}: {finding.description} [{finding.rule_id}]")
    if len(findings) > limit:
        lines.append(f"  ... and {len(findings) - limit} more")
    return lines


def report(findings: list[Finding], action: str, cfg: Config, config_name: str) -> None:
    """Print blocking findings first (secrets before personal details), then warnings."""
    blocking = sorted((f for f in findings if f.severity == "block"),
                      key=lambda f: 0 if f.category == "secret" else 1)
    warnings = [f for f in findings if f.severity != "block"]
    lines = [""]
    if blocking:
        verb = "found" if action == "history scan" else "blocked"
        count = len(blocking)
        lines += [f"privacy-guard: {action} {verb}: {count} possible leak{'s' if count != 1 else ''} "
                  "(the matched text is never shown)", ""]
        lines += _listing(blocking, MAX_REPORTED)
        lines.append("")
    if warnings:
        count = len(warnings)
        lines += [f"privacy-guard: {count} warning{'s' if count != 1 else ''}, not blocking "
                  "(use --strict, or strict = true in the config, to block these too):", ""]
        lines += _listing(warnings, max(10, MAX_REPORTED - len(blocking)))
        lines.append("")
    if blocking:
        lines += _advice(action, cfg, config_name)
    else:
        lines.append(f"Check them. False alarms can be allowlisted in {config_name}.")
    lines.append("")
    sys.stderr.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(
        prog="privacy_guard.py",
        description="Block commits and pushes that add secrets or personal details.")
    parser.add_argument("mode", choices=tuple(ACTIONS))
    parser.add_argument("args", nargs="*",
                        help="push: the remote's name and URL; commit-msg: the message file")
    parser.add_argument("--config", type=Path, default=None,
                        help="config file (default: privacy-guard.toml beside this script)")
    parser.add_argument("--strict", action="store_true",
                        help="make every rule block, as strict = true in the config does")
    parser.add_argument("--report-examples", action="store_true",
                        help="report reserved example values too, as report_examples = true does")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    action = ACTIONS[args.mode]

    try:
        if args.mode == "check-config":
            path = args.config or DEFAULT_CONFIG
            cfg = load_config(path)
            print(f"privacy-guard: {path.name} is valid ({len(cfg.rules)} content rules, "
                  f"{len(cfg.file_rules)} file-name rules).")
            return 0
        top = repo_top()
        if args.config is not None:
            cfg, name, note = load_config(args.config), args.config.name, ""
        else:
            source = {"staged": "index", "commit-msg": "index", "push": "head"}.get(args.mode, "disk")
            cfg, name, note = load_hook_config(top, source)
        if args.strict or args.report_examples:
            cfg = dataclasses.replace(cfg, strict=cfg.strict or args.strict,
                                      report_examples=cfg.report_examples or args.report_examples)
        if note:
            sys.stderr.write(note + "\n")
        if args.mode == "staged":
            findings = scan_staged(top, cfg)
        elif args.mode == "commit-msg":
            if not args.args:
                raise GitError("commit-msg needs the message file")
            # git sets GIT_EDITOR=: for commit hooks when it won't open an editor.
            editor = os.environ.get("GIT_EDITOR") != ":"
            findings = scan_message_file(Path(args.args[0]), cfg, editor, top,
                                         message_context(top, editor))
        elif args.mode == "push":
            # git passes the remote's name and the URL it is pushing to; ask the URL.
            target = args.args[1] if len(args.args) > 1 else (args.args[0] if args.args else "")
            findings = scan_push(top, cfg, sys.stdin.buffer.read().decode("utf-8", "replace"), target)
        else:
            findings = scan_history(top, cfg)
    except ConfigError as exc:
        sys.stderr.write(f"privacy-guard: {action} blocked: problem with the config: {exc}\n")
        return 2
    except GitError as exc:
        sys.stderr.write(f"privacy-guard: {action} blocked: {exc}\n")
        return 2
    except Exception as exc:  # fail closed, and never echo data from the scan
        if os.environ.get("PRIVACY_GUARD_DEBUG"):
            raise
        sys.stderr.write(f"privacy-guard: {action} blocked by an internal error "
                         f"({type(exc).__name__}). Set PRIVACY_GUARD_DEBUG=1 for details.\n")
        return 2

    if findings:
        report(findings, action, cfg, name)
    if any(f.severity == "block" for f in findings):
        return 1
    if args.mode == "history" and not findings:
        print("privacy-guard: history scan found nothing to report.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
