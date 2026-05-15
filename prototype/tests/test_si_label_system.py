"""
tests/test_si_label_system.py — JISA v8 two-level SI + legacy normalize.

Task 1.2 deletes the SI:HIGH active level. This test pins the v8 contract:

  * SI exposes only MED and LOW as live constants (no HIGH attribute).
  * SI.normalize() folds legacy "SI:HIGH" → SI.MED, leaves MED/LOW untouched.
  * SI.min() and SI.lt() accept legacy SI:HIGH inputs (so v7 audit logs and
    cached state still parse) and produce the same answer they did in v7
    (MED, since v7 traces always degraded to MED under min()).
  * SI.HIGH attribute access raises AttributeError — guard against any
    reintroduction.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_PROTO_ROOT = Path(__file__).resolve().parent.parent
if str(_PROTO_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROTO_ROOT))

from datatypes import SI  # noqa: E402


class SILabelSystemTests(unittest.TestCase):

    # ------------------------------------------------------------------
    # SI.HIGH must NOT be exposed as a live constant
    # ------------------------------------------------------------------
    def test_si_high_constant_is_gone(self):
        self.assertFalse(hasattr(SI, "HIGH"),
                         "SI.HIGH must not exist in v8 — it was never reachable as a "
                         "trace state and was a documented misfeature in v7. Task 1.2 "
                         "removed it.")

    def test_si_med_and_low_present(self):
        self.assertEqual(SI.MED, "SI:MED")
        self.assertEqual(SI.LOW, "SI:LOW")

    def test_order_dict_only_two_entries(self):
        # Internal but worth pinning so a sloppy reintroduction is caught.
        self.assertEqual(set(SI._ORDER.keys()), {"SI:MED", "SI:LOW"})

    # ------------------------------------------------------------------
    # SI.normalize() — legacy fold
    # ------------------------------------------------------------------
    def test_normalize_legacy_high_to_med(self):
        self.assertEqual(SI.normalize("SI:HIGH"), "SI:MED")

    def test_normalize_med_unchanged(self):
        self.assertEqual(SI.normalize("SI:MED"), "SI:MED")

    def test_normalize_low_unchanged(self):
        self.assertEqual(SI.normalize("SI:LOW"), "SI:LOW")

    # ------------------------------------------------------------------
    # SI.min() — must accept legacy HIGH input without KeyError
    # ------------------------------------------------------------------
    def test_min_legacy_high_with_med_yields_med(self):
        # In v7, min(MED, HIGH) was MED (HIGH > MED in the old ORDER).
        # In v8, HIGH is normalised to MED first, so min(MED, HIGH) == MED still.
        self.assertEqual(SI.min("SI:HIGH", "SI:MED"), "SI:MED")
        self.assertEqual(SI.min("SI:MED", "SI:HIGH"), "SI:MED")

    def test_min_legacy_high_with_low_yields_low(self):
        self.assertEqual(SI.min("SI:HIGH", "SI:LOW"), "SI:LOW")
        self.assertEqual(SI.min("SI:LOW", "SI:HIGH"), "SI:LOW")

    def test_min_med_low_yields_low(self):
        self.assertEqual(SI.min("SI:MED", "SI:LOW"), "SI:LOW")
        self.assertEqual(SI.min("SI:LOW", "SI:MED"), "SI:LOW")

    # ------------------------------------------------------------------
    # SI.lt() — strict ordering survives legacy fold
    # ------------------------------------------------------------------
    def test_lt_low_lt_med(self):
        self.assertTrue(SI.lt("SI:LOW", "SI:MED"))
        self.assertFalse(SI.lt("SI:MED", "SI:LOW"))

    def test_lt_legacy_high_treated_as_med(self):
        # HIGH normalises to MED → not strictly less than MED.
        self.assertFalse(SI.lt("SI:HIGH", "SI:MED"))
        self.assertFalse(SI.lt("SI:MED", "SI:HIGH"))
        # LOW is strictly less than HIGH (HIGH→MED).
        self.assertTrue(SI.lt("SI:LOW", "SI:HIGH"))


class CapabilityTokenSILegacyTests(unittest.TestCase):
    """Token JSONs that still ship SI:HIGH must surface as SI:MED at runtime."""

    def test_legacy_token_si_high_normalises_to_med(self):
        import json
        import tempfile
        from pep.capability_token import CapabilityToken

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({
                "session_id": "test",
                "allow_tools": ["filesystem.read_file"],
                "path_scope": ["workspace/"],
                "max_calls_per_tool": {},
                "server_source_integrity": {"filesystem": "SI:HIGH"},
                "server_data_sensitivity_policy": {},
            }, f)
            path = f.name
        try:
            tok = CapabilityToken(path)
            # Whatever v7-era HIGH-labelled server now reads back as MED.
            self.assertEqual(tok.get_server_si("filesystem"), "SI:MED")
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
