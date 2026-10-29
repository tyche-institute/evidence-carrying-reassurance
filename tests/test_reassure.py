"""Re-assurance log: digest selection is sound and selective.

Soundness: at every input change, every standing decision whose outcome
changes under the new inputs is among the decisions the digests select
(`missed` stays empty). Checked on seeded random event sequences over all
table and coverage packets, and on named cases.

    python3 -m unittest tests.test_reassure -v
"""

from __future__ import annotations

import copy
import csv
import json
import random
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "verifier"))

from ecr import catalogue  # noqa: E402
from ecr.keys import key_id_for  # noqa: E402
from ecr.randomseq import fresh, iso, random_change  # noqa: E402
from ecr.reassure import ReassuranceLog  # noqa: E402


def load(rel: str):
    return json.loads((ROOT / rel).read_text(encoding="utf-8"))


POLICY = load("policy/relying-party-policy.json")
INDEX = load("fixtures/index.json")
TABLE_PACKETS = [load(c["fixture"]) for c in INDEX["cases"] if c["executed"] and c["family"] != "scenario"]


def seed_log(packets: list[dict] | None = None) -> ReassuranceLog:
    log = ReassuranceLog(POLICY)
    for pkt in packets or TABLE_PACKETS:
        log.decide(pkt)
    return log


class Soundness(unittest.TestCase):
    def test_random_event_sequences_select_every_outcome_change(self):
        totals = {"standing": 0, "selected": 0, "changed": 0, "events": 0}
        for seed in range(6):
            rng = random.Random(seed)
            log = seed_log()
            registry = json.loads(json.dumps(catalogue.STATUS_ENTRIES))
            at = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
            for i in range(40):
                at += timedelta(days=1)
                kind, change = random_change(rng, log.policy, registry, at)
                rec = log.event(kind, iso(at), change, f"seed {seed} event {i}")
                self.assertEqual(rec["missed"], [], f"seed {seed} event {i} {kind}: outcome changed without a digest change")
                self.assertLessEqual(rec["selected"], rec["standing"])
                self.assertLessEqual(rec["outcome_changed"], rec["selected"])
                for o in rec["outcomes"]:
                    self.assertIn(o["outcome"], ("reaffirmed", "revoked"))
                    self.assertTrue(o["changed_inputs"])
                totals["standing"] += rec["standing"]
                totals["selected"] += rec["selected"]
                totals["changed"] += rec["outcome_changed"]
                totals["events"] += 1
        self.assertGreater(totals["standing"], 0)
        self.assertLess(totals["selected"], totals["standing"], "selection must do less work than re-appraising everything")
        self.assertGreater(totals["changed"], 0, "the random menu must produce revocations for the test to mean anything")

    def test_negative_control_selects_nothing(self):
        log = seed_log()
        p = copy.deepcopy(log.policy)
        p["approvers"]["approver:soc-deputy"] = {"key_id": key_id_for("approver-soc-deputy")}
        p["description"] = "re-issued"
        at = datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc)
        rec = log.event("trust_list_changed", iso(at), {"policy": p, "status_list": fresh(json.loads(json.dumps(catalogue.STATUS_ENTRIES)), at)})
        self.assertGreater(rec["standing"], 0)
        self.assertEqual(rec["selected"], 0)
        self.assertEqual(rec["outcome_changed"], 0)

    def test_status_change_selects_only_that_delegation(self):
        log = seed_log()
        registry = json.loads(json.dumps(catalogue.STATUS_ENTRIES))
        registry["del-002"] = {"status": "revoked", "since": "2026-06-02T08:00:00Z"}
        at = datetime(2026, 6, 2, 9, 0, tzinfo=timezone.utc)
        under_002 = sorted(d["case_id"] for _, d in log.standing() if log.packets[d["receipt_id"]]["evidence"] and
                           ((log.packets[d["receipt_id"]]["evidence"].get("attached_receipt") or log.packets[d["receipt_id"]]["evidence"])["payload"]["delegation"]["id"] == "del-002"))
        rec = log.event("status_changed", iso(at), {"status_list": fresh(registry, at)})
        self.assertEqual(sorted(o["case_id"] for o in rec["outcomes"]), under_002)
        self.assertTrue(all(o["outcome"] == "revoked" and o["reason_code"] == "R12_DELEGATION_REVOKED" for o in rec["outcomes"]))
        self.assertEqual(rec["missed"], [])

    def test_withdrawn_profile_selects_only_that_profile(self):
        s04 = load("fixtures/scenario/S04_read_with_new_model_version_after_policy_update.json")
        log = seed_log()
        p = copy.deepcopy(log.policy)
        p["allowed_runtime_profiles"]["model_versions"].append(catalogue.MODEL_VERSION_NEXT)
        log.event("trust_list_changed", "2026-06-17T16:00:00Z", {"policy": p})
        d = log.decide(s04)
        self.assertEqual(d["verdict"], "accepted")
        allowed = copy.deepcopy(log.policy["allowed_runtime_profiles"])
        allowed["model_versions"] = [catalogue.MODEL_VERSION_NEXT]
        registry = json.loads(json.dumps(catalogue.STATUS_ENTRIES))
        at = datetime(2026, 7, 8, 9, 0, tzinfo=timezone.utc)
        rec = log.event("runtime_profile_changed", iso(at), {"allowed_runtime_profiles": allowed, "status_list": fresh(registry, at)})
        self.assertEqual(rec["standing"], rec["selected"] + 1, "every standing decision but S04 carries the withdrawn profile")
        self.assertNotIn(d["receipt_id"], rec["affected"])
        self.assertTrue(all(o["outcome"] == "revoked" and o["reason_code"] == "R21_RUNTIME_PROFILE_NOT_ALLOWED" for o in rec["outcomes"]))

    def test_policy_attached_as_evidence_is_selected_on(self):
        log = seed_log()
        log.event("runtime_profile_changed", "2026-06-17T07:00:00Z", {})
        self.assertEqual(log.state["claims"]["G0"], "pending")
        p = copy.deepcopy(log.policy)
        del p["accepted_roots"]["root:municipal-agent-ca"]
        rec = log.attach_evidence("G0", "2026-06-17T16:00:00Z", {"policy_update": "municipal root withdrawn"}, policy=p)
        self.assertGreater(rec["selected"], 0)
        self.assertTrue(all(o["outcome"] == "revoked" for o in rec["outcomes"]))
        self.assertEqual(rec["missed"], [])

    def test_hold_released_when_claims_close(self):
        s01 = load("fixtures/scenario/S01_mutate_with_co_approval.json")
        log = seed_log([load("fixtures/policy-cases/P01_direct_trusted_issuer.json")])
        log.event("runtime_profile_changed", "2026-06-17T07:00:00Z", {})
        d = log.decide(s01)
        self.assertEqual((d["verdict"], d["reason_code"]), ("hold", "H01_HOLD_PENDING_REASSESSMENT"))
        rec = log.attach_evidence("G5", "2026-06-17T15:00:00Z", {"reassessment_record": "filed"})
        self.assertEqual(rec["released"], [])
        registry = json.loads(json.dumps(catalogue.STATUS_ENTRIES))
        at = datetime(2026, 6, 17, 16, 0, tzinfo=timezone.utc)
        rec = log.attach_evidence("G0", iso(at), {"regression_result": "pass"}, status_list=fresh(registry, at))
        self.assertEqual([r["verdict"] for r in rec["released"]], ["accepted"])
        self.assertEqual(log.held, {})

    def test_frozen_decision_is_replayed_when_the_audit_closes(self):
        log = seed_log([load("fixtures/policy-cases/P01_direct_trusted_issuer.json")])
        rid = log.decisions[0]["receipt_id"]
        rec = log.event("audit_challenge", "2026-06-30T09:00:00Z", {"receipt_ids": [rid]})
        self.assertEqual([o["outcome"] for o in rec["outcomes"]], ["frozen"])
        self.assertEqual(log.latest()[rid]["appraised_at"], "2026-06-30T09:00:00Z")
        registry = json.loads(json.dumps(catalogue.STATUS_ENTRIES))
        at = datetime(2026, 6, 30, 13, 0, tzinfo=timezone.utc)
        rec = log.attach_evidence(["G0", "G1", "G2", "G3", "G4", "G5"], iso(at), {"replay_bundle_digest": "x"}, status_list=fresh(registry, at))
        self.assertEqual([(r["outcome"], r["replay_matches_recorded"]) for r in rec["replayed"]], [("reaffirmed", True)])
        self.assertEqual(log.frozen, {})
        self.assertEqual(log.latest()[rid]["status"], "reaffirmed")

    def test_committed_scenario_has_no_missed_outcome(self):
        for rec in load("expected/reassurance/records.json"):
            self.assertEqual(rec.get("missed", []), [], rec["kind"])
        with (ROOT / "expected" / "reassurance" / "strategies.csv").open(encoding="utf-8") as fh:
            strategies = {r["strategy"]: r for r in csv.DictReader(fh)}
        self.assertEqual(strategies["digest_selected"]["revocations_missed"], "0")
        self.assertEqual(strategies["digest_selected"]["revocations_caught"], strategies["reappraise_all"]["revocations_caught"])
        self.assertLess(int(strategies["digest_selected"]["re_appraisals"]), int(strategies["reappraise_all"]["re_appraisals"]))
        self.assertEqual(strategies["whole_input_digest"]["revocations_missed"], "0")
        self.assertGreaterEqual(int(strategies["whole_input_digest"]["re_appraisals"]), int(strategies["digest_selected"]["re_appraisals"]))
        with (ROOT / "expected" / "reassurance" / "sensitivity.csv").open(encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["missed"], "0", f"seed {r['seed']}")
            self.assertLessEqual(int(r["selected"]), int(r["standing_total"]))
            self.assertEqual(r["entries_only_missed"], "0", f"seed {r['seed']}")
            self.assertEqual(r["keyed_fallback_missed"], "0", f"seed {r['seed']}")

    def test_single_changes_compare_the_strategies(self):
        """Every change applied to the initial state: digest selection misses
        nothing and never selects more than the entries-only digest; the keyed
        index alone misses only where the change names no identifier."""
        with (ROOT / "expected" / "reassurance" / "single-changes.csv").open(encoding="utf-8") as fh:
            rows = {r["category"]: r for r in csv.DictReader(fh)}
        self.assertEqual(int(rows["total"]["changes"]), 4000)
        for cat, r in rows.items():
            n = {k: int(v) for k, v in r.items() if k != "category"}
            self.assertEqual(n["digest_missed"], 0, cat)
            self.assertEqual(n["keyed_fallback_missed"], 0, cat)
            self.assertEqual(n["entries_only_missed"], 0, cat)
            self.assertEqual(n["whole_input_selected"], n["standing_pairs"], cat)
            self.assertLessEqual(n["digest_selected"], n["entries_only_selected"], cat)
            self.assertLessEqual(n["outcome_changed"], n["digest_selected"], cat)
            if cat not in ("thresholds", "status_pin_verifier_profile", "total"):
                self.assertEqual(n["keyed_index_missed"], 0, cat)
        self.assertGreater(int(rows["thresholds"]["keyed_index_missed"]), 0)


if __name__ == "__main__":
    unittest.main()
