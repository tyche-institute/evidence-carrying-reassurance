"""Tests: the committed tables are what the verifier produces; tampering is caught.

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import copy
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verifier"))

from ecr import catalogue  # noqa: E402
from ecr.canon import canonical_bytes, digest  # noqa: E402
from ecr.keys import sign, verify  # noqa: E402
from ecr.verify import appraise  # noqa: E402


def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


POLICY = load("policy/relying-party-policy.json")
INDEX = load("fixtures/index.json")


class Canon(unittest.TestCase):
    def test_sorted_compact(self):
        self.assertEqual(canonical_bytes({"b": 1, "a": [True, None, "ü"]}), '{"a":[true,null,"ü"],"b":1}'.encode())

    def test_float_refused(self):
        with self.assertRaises(ValueError):
            canonical_bytes({"x": 1.5})


class Signatures(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        payload = {"a": 1, "b": "x"}
        sig = sign(payload, "test-key")
        self.assertTrue(verify(payload, sig)[0])
        self.assertFalse(verify({"a": 2, "b": "x"}, sig)[0])
        bad = dict(sig, key_id="sha256:" + "0" * 64)
        self.assertFalse(verify(payload, bad)[0])


class Tables(unittest.TestCase):
    def _rows(self, name):
        with (ROOT / "expected" / name).open(encoding="utf-8") as fh:
            return list(csv.DictReader(fh))

    def test_policy_cases_distribution(self):
        rows = self._rows("policy-cases.csv")
        self.assertEqual(len(rows), 24)
        layers = [r["first_failure_layer"] for r in rows]
        self.assertEqual((layers.count("none"), layers.count("carrier"), layers.count("binding"), layers.count("evidence"), layers.count("policy")), (3, 2, 2, 2, 15))

    def test_brokered_distribution(self):
        rows = self._rows("brokered-evidence-fixtures.csv")
        self.assertEqual(len(rows), 12)
        self.assertEqual(sum(r["accepted"] == "True" for r in rows), 2)
        self.assertEqual(sum(r["receipt_verifies"] == "True" and r["policy_accepts"] == "False" and r["binding_ok"] == "True" for r in rows), 8)

    def test_each_fixture_reproduces_its_row(self):
        for fam in ("policy-cases.csv", "brokered-evidence-fixtures.csv", "carrier-evidence-matrix.csv"):
            for r in self._rows(fam):
                if r.get("executed", "True") != "True":
                    continue
                d = appraise(load(r["fixture"]), POLICY)
                self.assertEqual(d["first_failure_layer"], r["first_failure_layer"], r["case_id"])
                self.assertEqual(d["reason_code"] or "", r["reason_code"], r["case_id"])
                for p in ("carrier_ok", "binding_ok", "evidence_ok", "policy_ok"):
                    self.assertEqual(str(d["predicates"][p]), r[p], f"{r['case_id']} {p}")

    def test_intended_equals_observed(self):
        for c in INDEX["cases"]:
            if not c["executed"] or c["family"] == "scenario":
                continue
            d = appraise(load(c["fixture"]), POLICY)
            self.assertEqual(d["first_failure_layer"], c["intended_layer"], c["case_id"])
            if c["intended_code"]:
                self.assertEqual(d["reason_code"], c["intended_code"], c["case_id"])

    def test_scenario_first_decisions_match_intended(self):
        """Scenario packets are appraised inside the scenario, under the policy in
        force at their presentation; their first decisions are committed under
        expected/reassurance/decisions/."""
        for c in INDEX["cases"]:
            if c["family"] != "scenario":
                continue
            d = load(f"expected/reassurance/decisions/{c['case_id']}.json")
            self.assertEqual(d["first_failure_layer"], c["intended_layer"], c["case_id"])
            self.assertEqual(d["reason_code"], c["intended_code"], c["case_id"])

    def test_coverage_controls_reach_their_code(self):
        rows = self._rows("coverage-controls.csv")
        self.assertEqual(len(rows), 12)
        for r in rows:
            self.assertEqual(r["reason_code"], r["target_code"], r["case_id"])
            self.assertEqual(appraise(load(r["fixture"]), POLICY)["reason_code"], r["target_code"], r["case_id"])

    def test_every_reason_code_fails_somewhere(self):
        """41 codes are the first failure of at least one packet; B01, V01 and R00
        cannot be a first failure by construction and fail in the check log."""
        rows = self._rows("reason-codes.csv")
        self.assertEqual(len(rows), 44)
        first = {r["code"] for r in rows if r["cases"]}
        log_only = {r["code"] for r in rows if not r["cases"] and int(r["failing_in_decisions"]) > 0}
        never = [r["code"] for r in rows if not r["cases"] and int(r["failing_in_decisions"]) == 0]
        self.assertEqual(never, [])
        self.assertEqual(log_only, {"B01_NO_CARRIER_RECORD", "V01_EVIDENCE_MISSING", "R00_UPSTREAM_PREDICATE_FAILED"})
        self.assertEqual(len(first), 41)
        for r in rows:
            if r["code"] in log_only:
                self.assertTrue(r["note"], r["code"])


class Tamper(unittest.TestCase):
    def setUp(self):
        self.p01 = load("fixtures/policy-cases/P01_direct_trusted_issuer.json")
        self.assertTrue(appraise(self.p01, POLICY)["accepted"])

    def test_edit_action_breaks_signature(self):
        pkt = copy.deepcopy(self.p01)
        pkt["evidence"]["payload"]["action"]["class"] = "read"
        d = appraise(pkt, POLICY)
        self.assertEqual(d["first_failure_layer"], "evidence")
        self.assertEqual(d["reason_code"], "V04_SIGNATURE_INVALID")

    def test_swap_carrier_record_breaks_binding(self):
        pkt = copy.deepcopy(self.p01)
        pkt["carrier_record"]["message_id"] = "someone-elses-message"
        d = appraise(pkt, POLICY)
        self.assertEqual(d["reason_code"], "B03_MESSAGE_ID_MISMATCH")

    def test_untrusted_root_in_policy_only(self):
        pkt = copy.deepcopy(self.p01)
        pol = copy.deepcopy(POLICY)
        del pol["accepted_roots"]["root:municipal-agent-ca"]
        d = appraise(pkt, pol)
        self.assertEqual(d["first_failure_layer"], "policy")
        self.assertEqual(d["reason_code"], "R04_ROOT_NOT_ACCEPTED")

    def test_timestamp_token_over_other_receipt(self):
        pkt = copy.deepcopy(self.p01)
        other = load("fixtures/policy-cases/P14_clock_skew_inside_window.json")
        pkt["timestamp_token"] = other["timestamp_token"]
        d = appraise(pkt, POLICY)
        self.assertEqual(d["reason_code"], "V08_TIMESTAMP_TOKEN_INVALID")

    def test_hold_when_claim_pending(self):
        s01 = load("fixtures/scenario/S01_mutate_with_co_approval.json")
        self.assertTrue(appraise(s01, POLICY)["accepted"])
        d = appraise(s01, POLICY, {"claims": {"G0": "pending"}})
        self.assertEqual(d["verdict"], "hold")
        low = load("fixtures/policy-cases/P01_direct_trusted_issuer.json")
        self.assertEqual(appraise(low, POLICY, {"claims": {"G0": "pending"}})["verdict"], "accepted")


class Determinism(unittest.TestCase):
    def test_generator_and_runner_reproduce_committed_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "carrier" / "local-xroad-dev").mkdir(parents=True)
            (tmp / "carrier" / "local-xroad-dev" / "message-binding.json").write_bytes((ROOT / "carrier" / "local-xroad-dev" / "message-binding.json").read_bytes())
            subprocess.run([sys.executable, str(ROOT / "verifier" / "gen_fixtures.py"), "--root", str(tmp)], check=True, capture_output=True)
            subprocess.run([sys.executable, str(ROOT / "verifier" / "run_matrix.py"), "--root", str(tmp)], check=True, capture_output=True)
            for sub in ("fixtures", "policy", "expected"):
                for p in sorted((tmp / sub).rglob("*")):
                    if p.is_file():
                        rel = p.relative_to(tmp)
                        self.assertEqual(p.read_bytes(), (ROOT / rel).read_bytes(), str(rel))

    def test_policy_digest_matches_run_summary(self):
        self.assertEqual(load("expected/RUN-SUMMARY.json")["policy_digest"], digest(POLICY))


if __name__ == "__main__":
    unittest.main()
