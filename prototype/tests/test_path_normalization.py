"""
tests/test_path_normalization.py — Unit tests for pep.path_normalizer.

Required cases (per Task 1.1 spec):
  1. summary.txt
  2. workspace/summary.txt
  3. workspace-internal absolute path  (/.../workspace/foo.txt)
  4. workspace/../workspace/file
  5. workspace/../../etc/passwd
  6. /.../workspace2/foo                (sibling-named directory; must NOT be inside)
  7. symlink escape                     (a symlink inside workspace/ → outside)

We additionally cover:
  - empty / None / whitespace
  - control characters
  - bare path with trailing whitespace
  - audit-field projection
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Make `prototype/` importable when running tests from the repo root.
_PROTO_ROOT = Path(__file__).resolve().parent.parent
if str(_PROTO_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROTO_ROOT))

from pep.path_normalizer import normalize_workspace_path  # noqa: E402


class PathNormalizationTests(unittest.TestCase):
    """All tests use a temp directory as workspace, with `cwd` = the temp dir's parent.

    This mirrors production: `cwd` is the prototype root, `workspace/` is a
    subdirectory of cwd. Bare filenames and "workspace/foo" both end up at
    "<proto>/workspace/foo".
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.proto_root = Path(self._tmp.name).resolve()
        self.workspace = self.proto_root / "workspace"
        self.workspace.mkdir()
        # Touch a file we can use for symlink tests
        self.outside_file = self.proto_root / "outside.txt"
        self.outside_file.write_text("secret")

    def norm(self, raw):
        return normalize_workspace_path(raw, self.workspace, cwd=self.proto_root)

    # ------------------------------------------------------------------
    # Required case 1: bare filename
    # ------------------------------------------------------------------
    def test_bare_filename_lands_in_workspace(self):
        r = self.norm("summary.txt")
        self.assertTrue(r.in_workspace, f"got {r!r}")
        self.assertEqual(r.policy_path, "workspace/summary.txt")
        self.assertEqual(r.normalized_rel, "workspace/summary.txt")
        self.assertIsNone(r.path_normalization_error)
        # normalized_abs should be the canonical absolute form
        self.assertEqual(Path(r.normalized_abs), self.workspace / "summary.txt")

    # ------------------------------------------------------------------
    # Required case 2: workspace-relative
    # ------------------------------------------------------------------
    def test_workspace_relative(self):
        r = self.norm("workspace/summary.txt")
        self.assertTrue(r.in_workspace)
        self.assertEqual(r.policy_path, "workspace/summary.txt")

    def test_dot_workspace_relative(self):
        # "./workspace/foo.txt" should normalise identically.
        r = self.norm("./workspace/summary.txt")
        self.assertTrue(r.in_workspace)
        self.assertEqual(r.policy_path, "workspace/summary.txt")

    # ------------------------------------------------------------------
    # Required case 3: workspace-internal absolute path
    # ------------------------------------------------------------------
    def test_workspace_internal_absolute(self):
        abs_inside = str(self.workspace / "report.txt")
        r = self.norm(abs_inside)
        self.assertTrue(r.in_workspace, f"got {r!r}")
        self.assertEqual(r.policy_path, "workspace/report.txt")

    # ------------------------------------------------------------------
    # Required case 4: workspace/../workspace/file (round-trip OK)
    # ------------------------------------------------------------------
    def test_dotdot_back_into_workspace_is_allowed(self):
        # The agent occasionally produces "workspace/../workspace/foo".
        # Canonical form is workspace/foo, which IS inside workspace.
        # Path-normalization MUST treat this as legitimate.
        r = self.norm("workspace/../workspace/foo.txt")
        self.assertTrue(r.in_workspace, f"got {r!r}")
        self.assertEqual(r.policy_path, "workspace/foo.txt")

    # ------------------------------------------------------------------
    # Required case 5: workspace/../../etc/passwd (escape — must DENY)
    # ------------------------------------------------------------------
    def test_dotdot_escape_to_etc_passwd_is_outside(self):
        r = self.norm("workspace/../../etc/passwd")
        self.assertFalse(r.in_workspace, f"got {r!r}")
        # policy_path should NOT begin with "workspace/" — R03 will deny it.
        self.assertFalse(
            r.policy_path.startswith("workspace/"),
            f"escape sneaked through: {r.policy_path}",
        )
        self.assertIsNone(r.path_normalization_error)

    def test_absolute_etc_passwd_is_outside(self):
        r = self.norm("/etc/passwd")
        self.assertFalse(r.in_workspace)
        self.assertFalse(r.policy_path.startswith("workspace/"))

    # ------------------------------------------------------------------
    # Required case 6: workspace2/ sibling directory (must NOT be inside workspace)
    # ------------------------------------------------------------------
    def test_sibling_named_directory_is_not_inside(self):
        # Create a sibling `workspace2/` next to `workspace/` to verify the
        # membership test uses path equality, not str.startswith().
        ws2 = self.proto_root / "workspace2"
        ws2.mkdir()
        (ws2 / "foo.txt").write_text("x")
        r = self.norm(str(ws2 / "foo.txt"))
        self.assertFalse(
            r.in_workspace,
            f"workspace2 misclassified as inside workspace: {r!r}",
        )
        self.assertFalse(r.policy_path.startswith("workspace/"))

    # ------------------------------------------------------------------
    # Required case 7: symlink escape
    # ------------------------------------------------------------------
    def test_symlink_inside_workspace_pointing_outside_is_denied(self):
        # An attacker (or careless workspace prep) places a symlink at
        # workspace/escape that points to /tmp/.../outside.txt.
        # R03 must follow the symlink and detect the escape.
        link = self.workspace / "escape"
        link.symlink_to(self.outside_file)
        r = self.norm("workspace/escape")
        self.assertFalse(
            r.in_workspace,
            f"symlink escape leaked through: {r!r}",
        )
        self.assertFalse(r.policy_path.startswith("workspace/"))
        # normalized_abs should reveal the actual target so audit is informative.
        self.assertIn("outside.txt", r.normalized_abs or "")

    def test_symlink_inside_workspace_pointing_inside_is_allowed(self):
        # A symlink that stays inside the workspace is fine.
        target = self.workspace / "real.txt"
        target.write_text("inside-content")
        link = self.workspace / "alias"
        link.symlink_to(target)
        r = self.norm("workspace/alias")
        self.assertTrue(r.in_workspace, f"got {r!r}")
        self.assertEqual(r.policy_path, "workspace/real.txt")

    # ------------------------------------------------------------------
    # Whitespace / empty / None / control chars
    # ------------------------------------------------------------------
    def test_leading_whitespace_is_stripped(self):
        r = self.norm("  workspace/x.txt  ")
        self.assertTrue(r.in_workspace)
        self.assertEqual(r.policy_path, "workspace/x.txt")

    def test_empty_string(self):
        r = self.norm("")
        self.assertFalse(r.in_workspace)
        self.assertEqual(r.policy_path, "")
        self.assertIsNotNone(r.path_normalization_error)

    def test_none(self):
        r = self.norm(None)
        self.assertFalse(r.in_workspace)
        self.assertIsNotNone(r.path_normalization_error)

    def test_null_byte(self):
        r = self.norm("workspace/foo\x00.txt")
        self.assertFalse(r.in_workspace)
        self.assertIsNotNone(r.path_normalization_error)
        # Policy path falls back to the raw form so R03 still denies.
        self.assertNotEqual(r.policy_path, "workspace/foo.txt")

    # ------------------------------------------------------------------
    # Audit-field projection
    # ------------------------------------------------------------------
    def test_to_audit_fields_inside_workspace(self):
        r = self.norm("summary.txt")
        f = r.to_audit_fields()
        self.assertEqual(f["raw_path"], "summary.txt")
        self.assertEqual(f["normalized_path"], "workspace/summary.txt")
        self.assertIsNone(f["path_normalization_error"])

    def test_to_audit_fields_outside_workspace(self):
        r = self.norm("/etc/passwd")
        f = r.to_audit_fields()
        self.assertEqual(f["raw_path"], "/etc/passwd")
        # outside → audit shows canonical absolute form so reviewer sees what
        # the path actually pointed to.
        self.assertTrue(
            f["normalized_path"] is None or f["normalized_path"].startswith("/"),
            f"unexpected normalized_path: {f['normalized_path']!r}",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
