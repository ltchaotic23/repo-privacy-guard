#!/usr/bin/env python3
"""Install repo-privacy-guard's git hooks in a repository, or turn them off again.

  python install.py [REPO] [--workflow private|public] [--force]
  python install.py [REPO] --uninstall

REPO defaults to the repository you are in. For another repository, the installer copies
the hooks and privacy_guard.py into REPO/.githooks/, adds privacy-guard.toml only if REPO
doesn't have one yet (your edits are kept), records the files' checksums in
privacy-guard.sha256, and runs `git config core.hooksPath .githooks` there. Run inside
this kit, it just turns on the kit's own hooks.

Every check runs before anything is written, so a refusal leaves the repository as it was.

--workflow private  adds .github/workflows/visibility-guard.yml that fails if the
                    repository is ever made public
--workflow public   adds one that scans the whole history on every push and pull request
--force             replace an existing core.hooksPath (local or global), hooks in
                    .git/hooks, edited hook files or an existing workflow
--uninstall         unset core.hooksPath (if it is .githooks); files are left in place
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    sys.exit("install.py: Python 3.11 or newer is required.")

KIT = Path(__file__).resolve().parent
HOOK_DIR = ".githooks"
HOOKS = ("pre-commit", "pre-push", "commit-msg")
SCRIPTS = (*HOOKS, "privacy_guard.py")
CONFIG = "privacy-guard.toml"
MANIFEST = "privacy-guard.sha256"
WORKFLOWS = {
    "private": KIT / "templates" / "visibility-guard-private.yml",
    "public": KIT / "templates" / "visibility-guard-public.yml",
}


class InstallError(Exception):
    pass


def git(repo: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise InstallError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout.strip() if proc.returncode == 0 else ""


def repo_root(path: Path) -> Path:
    if not path.is_dir():
        raise InstallError(f"{path.name or path} is not a folder")
    top = git(path, "rev-parse", "--show-toplevel", check=False)
    if not top:
        raise InstallError("that folder is not inside a git working tree")
    return Path(top).resolve()


def active_hooks(repo: Path) -> list[str]:
    """Hooks in the default hooks folder that core.hooksPath would switch off."""
    hooks = Path(git(repo, "rev-parse", "--git-path", "hooks"))
    hooks = hooks if hooks.is_absolute() else repo / hooks
    if not hooks.is_dir():
        return []
    return sorted(p.name for p in hooks.iterdir()
                  if p.is_file() and not p.name.startswith(".") and not p.name.endswith(".sample"))


def _text_bytes(path: Path) -> bytes:
    """File contents with Windows line endings turned into Unix ones, so a checkout with
    core.autocrlf = true counts as the same file."""
    return path.read_bytes().replace(b"\r\n", b"\n")


def sha256(path: Path) -> str:
    return hashlib.sha256(_text_bytes(path)).hexdigest()


def same_text(a: Path, b: Path) -> bool:
    return _text_bytes(a) == _text_bytes(b)


def read_manifest(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    entries = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        digest, _, name = line.partition("  ")
        if digest and name:
            entries[name.strip()] = digest.strip()
    return entries


def load_scanner():
    spec = importlib.util.spec_from_file_location("privacy_guard_kit", KIT / HOOK_DIR / "privacy_guard.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module  # dataclasses look the module up while it loads
    spec.loader.exec_module(module)
    return module


def make_executable(path: Path) -> None:
    if os.name != "nt":
        path.chmod(path.stat().st_mode | 0o111)


def line_ending_advice(repo: Path) -> list[str]:
    """Hooks checked out with Windows line endings fail under a Linux /bin/sh, and
    differing line endings make the scripts look edited."""
    names = [*SCRIPTS, CONFIG, *([MANIFEST] if (repo / HOOK_DIR / MANIFEST).is_file() else [])]
    missing = [name for name in names
               if git(repo, "check-attr", "eol", "--", f"{HOOK_DIR}/{name}", check=False)
               .rsplit(":", 1)[-1].strip() != "lf"]
    if not missing:
        return []
    return ["", "So the guard's files keep Unix line endings on every machine, add these lines",
            "to .gitattributes and commit it:",
            *[f"  {HOOK_DIR}/{name} text eol=lf" for name in missing]]


def hooks_path_value(text: str) -> str:
    """core.hooksPath without a trailing / or \\ (both mean the same folder)."""
    return text.strip().rstrip("/\\")


def is_link(path: Path) -> bool:
    """A symbolic link, or a Windows junction (a folder link that needs no admin rights)."""
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)   # Python 3.12+
    if isjunction is not None:
        return isjunction(path)
    if os.name == "nt" and path.exists():
        # Python 3.11: a junction resolves somewhere other than its own name.
        return os.path.normcase(path.resolve()) != os.path.normcase(path.parent.resolve() / path.name)
    return False


def refuse_links(repo: Path, paths: list[Path]) -> None:
    """Writing through a symbolic link or junction, in the file's name or in any folder on
    the way to it, would change a file somewhere else."""
    for path in paths:
        parts = path.relative_to(repo).parts
        for depth in range(1, len(parts) + 1):
            step = repo.joinpath(*parts[:depth])
            if is_link(step):
                kind = "folder" if depth < len(parts) else "file or folder"
                raise InstallError(f"{'/'.join(parts[:depth])} is a symbolic link or junction; replace "
                                   f"it with a real {kind} first (the installer never writes "
                                   "through links)")
        if path.exists() and not path.resolve().is_relative_to(repo):
            raise InstallError(f"{'/'.join(parts)} leads outside the repository")


def refuse_wrong_types(paths: list[Path], folders: list[Path], repo: Path) -> None:
    for path in paths:
        if path.exists() and not path.is_file():
            raise InstallError(f"{path.relative_to(repo).as_posix()} is a folder or special file, "
                               "not a file; move it out of the way first")
    for folder in folders:
        if folder.exists() and not folder.is_dir():
            raise InstallError(f"{folder.relative_to(repo).as_posix()} is a file, not a folder; "
                               "move it out of the way first")


def install(target: Path, workflow: str | None, force: bool) -> list[str]:
    repo = repo_root(target)
    dest = repo / HOOK_DIR
    copying = repo != KIT

    # ---- every check first: nothing is written until they have all passed
    effective = git(repo, "config", "--show-scope", "--get", "core.hooksPath", check=False)
    scope, _, value = effective.partition("\t")
    if scope in ("worktree", "command") and hooks_path_value(value) != HOOK_DIR:
        where = ("this worktree's config (config.worktree)" if scope == "worktree"
                 else "GIT_CONFIG_* environment variables or `git -c`")
        undo = ("git config --worktree --unset core.hooksPath" if scope == "worktree"
                else "unset the variable")
        raise InstallError(f"core.hooksPath is set in {where}, which overrides the repository's "
                           f"own setting, so the guard's hooks would never run. Remove it first "
                           f"({undo}), then run the installer again.")
    current = hooks_path_value(git(repo, "config", "--local", "--get", "core.hooksPath", check=False))
    if current and current != HOOK_DIR and not force:
        raise InstallError(f"core.hooksPath is already set to {current!r} here. "
                           "Re-run with --force to replace it (those hooks would stop running).")
    if not current:
        # Any other scope: global, system, worktree, or a file pulled in with [include].
        elsewhere = git(repo, "config", "--show-scope", "--get", "core.hooksPath", check=False)
        if elsewhere and not force:
            scope = elsewhere.split("\t", 1)[0]
            raise InstallError(f"core.hooksPath is set in your {scope} git config, and this "
                               "repository's setting would override it here, so those hooks "
                               "would stop running in this repository. Re-run with --force if "
                               "that's fine.")
        others = active_hooks(repo)
        if others and not force:
            raise InstallError(f"core.hooksPath replaces the hooks in .git/hooks ({', '.join(others)}). "
                               "Re-run with --force if that's fine, or merge them into .githooks.")

    workflow_file = repo / ".github" / "workflows" / "visibility-guard.yml"
    guard_files = [dest / n for n in (*SCRIPTS, CONFIG, MANIFEST)]
    workflow_files = [workflow_file] if workflow else []
    refuse_links(repo, [*guard_files, *workflow_files])
    refuse_wrong_types([*guard_files, *workflow_files],
                       [dest, *(f for wf in workflow_files for f in (wf.parent, wf.parent.parent))], repo)

    plan: list[tuple[Path, Path, str]] = []   # (source, destination, note)
    if copying:
        manifest = read_manifest(dest / MANIFEST)
        for name in SCRIPTS:
            src, dst = KIT / HOOK_DIR / name, dest / name
            if not dst.exists():
                plan.append((src, dst, f"Added {HOOK_DIR}/{name}"))
            elif not same_text(src, dst):
                unedited = manifest.get(name) == sha256(dst)
                if not unedited and not force:
                    raise InstallError(
                        f"{HOOK_DIR}/{name} has been changed since it was installed (or wasn't "
                        "installed by repo-privacy-guard). Re-run with --force to replace it; "
                        "copy your changes somewhere first.")
                plan.append((src, dst, f"Updated {HOOK_DIR}/{name}"))

    scanner = load_scanner()
    config = dest / CONFIG
    try:
        scanner.load_config(config if config.exists() else KIT / HOOK_DIR / CONFIG)
    except scanner.ConfigError as exc:
        raise InstallError(f"{HOOK_DIR}/{CONFIG} doesn't load with this version: {exc}") from None
    if copying and not config.exists():
        plan.append((KIT / HOOK_DIR / CONFIG, config, f"Added {HOOK_DIR}/{CONFIG}"))

    unchanged_workflow = False
    if workflow:
        wf = workflow_file
        if wf.exists() and same_text(WORKFLOWS[workflow], wf):
            unchanged_workflow = True
        else:
            if wf.exists() and not force:
                raise InstallError(".github/workflows/visibility-guard.yml already exists. "
                                   "Re-run with --force to replace it.")
            plan.append((WORKFLOWS[workflow], wf,
                         f"Added .github/workflows/visibility-guard.yml ({workflow} mode)"))

    # ---- write
    notes: list[str] = []
    try:
        for src, dst, note in plan:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
            notes.append(note)
        if unchanged_workflow:
            notes.append(".github/workflows/visibility-guard.yml is already up to date")
        if copying:
            if config.exists() and not any(dst == config for _, dst, _ in plan):
                notes.append(f"Kept your existing {HOOK_DIR}/{CONFIG}")
            (dest / MANIFEST).write_text(
                "".join(f"{sha256(dest / name)}  {name}\n" for name in SCRIPTS),
                encoding="utf-8", newline="\n")
        for name in HOOKS:
            make_executable(dest / name)
    except OSError as exc:
        raise InstallError(f"couldn't write {exc.filename or 'a file'}: {exc.strerror or exc}") from None
    git(repo, "config", "--local", "core.hooksPath", HOOK_DIR)
    # Something with a higher priority (a worktree config, GIT_CONFIG_* variables) would
    # make the setting above do nothing.
    now = hooks_path_value(git(repo, "config", "--get", "core.hooksPath", check=False))
    if now != HOOK_DIR:
        raise InstallError(f"core.hooksPath was set to {HOOK_DIR} in .git/config, but git still "
                           f"uses {now!r} here (check `git config --show-origin --get "
                           "core.hooksPath`), so the hooks won't run yet")
    notes.append(f"Hooks are on for this clone (core.hooksPath={HOOK_DIR}).")
    notes += line_ending_advice(repo)
    return notes


def uninstall(target: Path) -> list[str]:
    repo = repo_root(target)
    current = hooks_path_value(git(repo, "config", "--local", "--get", "core.hooksPath", check=False))
    if current != HOOK_DIR:
        return [f"core.hooksPath isn't {HOOK_DIR} here, so there was nothing to turn off."]
    git(repo, "config", "--local", "--unset", "core.hooksPath")
    return [
        "Turned the hooks off for this clone (unset core.hooksPath).",
        f"The guard's files are still in {HOOK_DIR}/ (and any visibility-guard workflow in",
        ".github/workflows/). To remove them from the repository too:",
        f"  git rm -r {HOOK_DIR}",
    ]


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(description="Install repo-privacy-guard's git hooks.")
    parser.add_argument("repo", nargs="?", default=".", type=Path,
                        help="repository to protect (default: the current one)")
    parser.add_argument("--workflow", choices=sorted(WORKFLOWS),
                        help="also add a visibility-guard GitHub workflow")
    parser.add_argument("--force", action="store_true",
                        help="replace an existing core.hooksPath, hooks, edited hook files or workflow")
    parser.add_argument("--uninstall", action="store_true",
                        help="turn the hooks off for this clone (files are left in place)")
    args = parser.parse_args(argv)
    if args.uninstall and (args.workflow or args.force):
        parser.error("--uninstall can't be combined with --workflow or --force")
    try:
        if args.uninstall:
            print("\n".join(uninstall(args.repo)))
            return 0
        notes = install(args.repo, args.workflow, args.force)
    except InstallError as exc:
        print(f"install.py: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"install.py: {exc.filename or 'a file'}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    print("\n".join(notes))
    if args.repo.resolve() != KIT and repo_root(args.repo) != KIT:
        hooks = " ".join(f"{HOOK_DIR}/{h}" for h in HOOKS)
        print("\nCommit the guard so it travels with the repository (the first line keeps the")
        print("hooks executable on Linux and macOS):")
        print(f"  git add --chmod=+x {hooks}")
        print(f"  git add {HOOK_DIR}/privacy_guard.py {HOOK_DIR}/{CONFIG} {HOOK_DIR}/{MANIFEST}")
    print("Every new clone needs the hooks turned on once:")
    print(f"  git config core.hooksPath {HOOK_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
