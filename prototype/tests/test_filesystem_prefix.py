"""
tests/test_filesystem_prefix.py — FilesystemTool workspace-prefix consistency.

Verifies the Task 1.1 cleanup fix: the agent-supplied path's leading
``workspace/`` / ``./workspace/`` prefix is stripped before being joined onto
the tool's workspace root, so:

  1. ``write_file("workspace/demo.txt")`` lands at ``<root>/demo.txt``
     (NOT ``<root>/workspace/demo.txt``, the v7 nesting bug).
  2. ``write_file("demo.txt")`` and ``read_file("workspace/demo.txt")``
     read/write the same file (and vice versa), so audit's
     ``normalized_path`` agrees with what the tool actually touched.
  3. ``"workspace/../etc/passwd"`` is still rejected as outside scope.

Without the fix, audit logs claim ``normalized_path: workspace/foo.txt``
while the file is physically at ``<root>/workspace/foo.txt`` — a credibility
gap reviewers will flag in §3.5 ("observable auditing").
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_PROTO_ROOT = Path(__file__).resolve().parent.parent
if str(_PROTO_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROTO_ROOT))

from tools.filesystem import FilesystemTool  # noqa: E402


class FilesystemPrefixTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name).resolve() / "workspace"
        self.fs = FilesystemTool(workspace_dir=str(self.root))

    # ------------------------------------------------------------------
    # Required cleanup case 1: write_file("workspace/demo.txt") lands at <root>/demo.txt
    # ------------------------------------------------------------------
    def test_write_with_workspace_prefix_lands_at_root_not_nested(self):
        msg = self.fs.write_file({"path": "workspace/demo.txt", "content": "hello"})
        self.assertIn("Written", msg)

        flat = self.root / "demo.txt"
        nested = self.root / "workspace" / "demo.txt"
        self.assertTrue(
            flat.exists(),
            f"file should be at <root>/demo.txt; not found. tree={list(self.root.rglob('*'))}",
        )
        self.assertFalse(
            nested.exists(),
            f"nested workspace/workspace/demo.txt should NOT exist; saw {nested}",
        )
        self.assertEqual(flat.read_text(), "hello")

    def test_write_with_dotworkspace_prefix_lands_at_root(self):
        self.fs.write_file({"path": "./workspace/demo.txt", "content": "x"})
        self.assertEqual((self.root / "demo.txt").read_text(), "x")
        self.assertFalse((self.root / "workspace" / "demo.txt").exists())

    # ------------------------------------------------------------------
    # Required cleanup case 2: bare-vs-prefixed forms address the same file
    # ------------------------------------------------------------------
    def test_write_demo_then_read_workspace_demo_returns_same_content(self):
        self.fs.write_file({"path": "demo.txt", "content": "shared"})
        # The agent might later refer to the same file with the workspace/ prefix.
        out = self.fs.read_file({"path": "workspace/demo.txt"})
        self.assertEqual(out, "shared")

    def test_write_workspace_demo_then_read_demo_returns_same_content(self):
        self.fs.write_file({"path": "workspace/demo.txt", "content": "shared-2"})
        out = self.fs.read_file({"path": "demo.txt"})
        self.assertEqual(out, "shared-2")

    # ------------------------------------------------------------------
    # Security regression: escapes still blocked
    # ------------------------------------------------------------------
    def test_dotdot_escape_still_blocked(self):
        # Even after the prefix-strip rule, "workspace/../../etc/passwd" must
        # still be rejected because the resolved target is outside <root>.
        msg = self.fs.write_file({"path": "workspace/../../etc/passwd", "content": "x"})
        self.assertIn("outside workspace scope", msg)

    def test_absolute_outside_root_still_blocked(self):
        msg = self.fs.write_file({"path": "/etc/passwd", "content": "x"})
        self.assertIn("outside workspace scope", msg)

    # ------------------------------------------------------------------
    # PRESET_CONTENTS still match across path forms
    # ------------------------------------------------------------------
    def test_preset_contents_hit_via_bare_form(self):
        # PRESET_CONTENTS is keyed under "workspace/config.txt"; the canonical
        # lookup must still hit when the model supplies a bare filename.
        out_full = self.fs.read_file({"path": "workspace/config.txt"})
        out_bare = self.fs.read_file({"path": "config.txt"})
        self.assertEqual(out_full, out_bare)
        self.assertIn("API_KEY", out_full)

    def test_preset_contents_hit_via_dotworkspace_form(self):
        out_dot = self.fs.read_file({"path": "./workspace/config.txt"})
        self.assertIn("API_KEY", out_dot)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
