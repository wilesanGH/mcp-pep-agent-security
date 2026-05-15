"""
pep/path_normalizer.py — Workspace-aware path normalization (Task 1.1, JISA v8).

Purpose
-------
Resolve paths supplied by the LLM agent into a canonical relative form before
R03 evaluates them. v7's R03 used a literal prefix-match (`workspace/` /
`./workspace/`); the LLM frequently produced semantically-equivalent variants
that R03 rejected as out-of-scope, inflating FPR(task) to ~80%.

Normalization rule (option-b, applied pre-call to every filesystem op)
----------------------------------------------------------------------
Inputs:
  * raw_path: str — value of args["path"] as supplied by the model.
  * workspace_root: Path — absolute path of the workspace directory.
  * cwd: Path — process working directory; used to resolve relative paths.

Algorithm:
  1. Strip leading/trailing whitespace.
  2. Reject paths whose resolution depends on null bytes / control chars.
  3. Resolve to an absolute path:
     - If raw is absolute (starts with `/`), use it as-is.
     - Otherwise, join with `cwd`.
  4. Use Path.resolve(strict=False) to canonicalise (`..` segments and
     symlinks are followed). resolve() materialises symlinks as their final
     filesystem target, which is exactly what we need for symlink-escape
     defence.
  5. If the canonical absolute path is inside `workspace_root`:
       → return policy_path = "workspace/<rel>" (forward slashes, no dot)
  6. Otherwise:
       → return policy_path = the original raw (or its canonical form when
         possible); R03 will then deny it because it does not start with
         "workspace/".

Output (always returned, never raises for normal paths):
    NormalizedPath(
        raw_path:                  str,        # original input
        normalized_abs:            str | None, # canonical absolute path on disk
        normalized_rel:            str | None, # path relative to workspace_root
        policy_path:               str,        # what R03 should match against
        in_workspace:              bool,       # True iff inside workspace_root
        path_normalization_error:  str | None, # set on internal errors
    )

Errors are reported via `path_normalization_error` rather than exceptions; the
enforcer keeps running but R03 evaluates against the original raw path so
malformed input fails closed (i.e. is denied because it does not match
"workspace/").
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class NormalizedPath:
    raw_path: str
    normalized_abs: Optional[str]
    normalized_rel: Optional[str]
    policy_path: str
    in_workspace: bool
    path_normalization_error: Optional[str]

    def to_audit_fields(self) -> dict:
        """Return only the audit-relevant subset for embedding in an audit event."""
        return {
            "raw_path": self.raw_path,
            "normalized_path": self.normalized_rel if self.in_workspace else self.normalized_abs,
            "path_normalization_error": self.path_normalization_error,
        }


# Sentinel returned by Path.resolve() on a path that does not exist.
# We do NOT use strict=True because LLM-driven traces frequently propose
# paths that haven't been created yet (legitimate write_file workflow).


def normalize_workspace_path(
    raw_path: str,
    workspace_root: os.PathLike | str,
    cwd: Optional[os.PathLike | str] = None,
) -> NormalizedPath:
    """
    Normalize a path supplied by the agent for R03 evaluation.

    See module docstring for the algorithm. Never raises for non-malicious input;
    surfaces internal errors via NormalizedPath.path_normalization_error so the
    caller can decide whether to fail open or closed.
    """
    if raw_path is None:
        return NormalizedPath(
            raw_path="",
            normalized_abs=None,
            normalized_rel=None,
            policy_path="",
            in_workspace=False,
            path_normalization_error="path is None",
        )

    raw = str(raw_path).strip()
    if not raw:
        return NormalizedPath(
            raw_path=str(raw_path),
            normalized_abs=None,
            normalized_rel=None,
            policy_path="",
            in_workspace=False,
            path_normalization_error="path is empty after strip",
        )

    # Reject control characters: null bytes, etc. — these can confuse downstream
    # tool implementations and have no legitimate use in workspace paths.
    if "\x00" in raw or any(ord(c) < 0x20 and c != "\t" for c in raw):
        return NormalizedPath(
            raw_path=raw,
            normalized_abs=None,
            normalized_rel=None,
            policy_path=raw,  # let R03 deny on prefix mismatch
            in_workspace=False,
            path_normalization_error="path contains control characters",
        )

    workspace_root = Path(workspace_root)
    cwd = Path(cwd) if cwd is not None else Path.cwd()

    # Step 1: resolve workspace_root to an absolute canonical path.
    # We expect callers to pass an existing directory; if it doesn't exist
    # we still proceed with a best-effort absolute form so callers in tests
    # don't need to materialise the dir.
    try:
        ws_abs = workspace_root.resolve(strict=False)
    except OSError as e:  # pragma: no cover — extremely rare
        return NormalizedPath(
            raw_path=raw,
            normalized_abs=None,
            normalized_rel=None,
            policy_path=raw,
            in_workspace=False,
            path_normalization_error=f"workspace_root resolve failed: {e}",
        )

    # Step 2: build the candidate absolute path.
    # Path("/abs").is_absolute() handles POSIX and Windows-drive paths.
    candidate = Path(raw)
    if not candidate.is_absolute():
        # Two cases for relative input:
        #   (a) "summary.txt" — bare filename with no path separator. The agent
        #       intends a workspace file but didn't prefix workspace/. v7's
        #       R03 rejected these as out-of-scope; v8 normalises bare names
        #       to workspace/<name> before R03 sees them.
        #   (b) "workspace/foo.txt" or "./workspace/foo.txt" or any path with
        #       at least one separator. We resolve relative to cwd; if the
        #       agent meant workspace/, that's already in the path.
        if "/" not in raw and "\\" not in raw:
            candidate = ws_abs / candidate.name
        else:
            candidate = cwd / candidate

    # Step 3: canonicalise. resolve() folds `..` and follows symlinks.
    # strict=False so non-existent leaves don't raise.
    try:
        canonical = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        return NormalizedPath(
            raw_path=raw,
            normalized_abs=None,
            normalized_rel=None,
            policy_path=raw,
            in_workspace=False,
            path_normalization_error=f"candidate resolve failed: {e}",
        )

    # Step 4: workspace membership.
    # Path.is_relative_to(other) is the cleanest API but only Python 3.9+;
    # we use the os.path.commonpath approach which works back to 3.6.
    in_workspace = _is_inside(canonical, ws_abs)

    if in_workspace:
        rel = canonical.relative_to(ws_abs).as_posix()
        # Use forward slashes, no leading dot. Empty rel (the workspace root
        # itself) is rare but allowed; stringify as "workspace/".
        policy_path = "workspace/" + rel if rel else "workspace/"
        return NormalizedPath(
            raw_path=raw,
            normalized_abs=canonical.as_posix(),
            normalized_rel=policy_path,
            policy_path=policy_path,
            in_workspace=True,
            path_normalization_error=None,
        )

    # Out of workspace — preserve the canonical form so audit shows what the
    # path actually pointed to (after `..` and symlink resolution).
    return NormalizedPath(
        raw_path=raw,
        normalized_abs=canonical.as_posix(),
        normalized_rel=None,
        policy_path=canonical.as_posix(),
        in_workspace=False,
        path_normalization_error=None,
    )


def _is_inside(path: Path, root: Path) -> bool:
    """True iff `path` is `root` itself or a descendant. Both should be absolute."""
    try:
        # commonpath raises ValueError if paths are on different drives (Win)
        common = os.path.commonpath([str(path), str(root)])
    except ValueError:
        return False
    return Path(common) == root
