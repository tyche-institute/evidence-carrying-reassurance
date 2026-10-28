"""Re-assurance mechanics: decision log, change events, digest-selected
re-appraisal, holds, freezes and the replay bundle.

Mechanics
---------
* Every decision is appended to a log with the five digests of the input
  slices it read (`decision["depends_on"]`, see `verify.depends_on`): the
  trust-anchor entries it consulted, the status entry of its delegation, the
  allow-list membership of its runtime profile, the policy parameters, and
  the carrier-configuration membership of its carrier record.
* A *standing* decision is the latest decision for a receipt whose status is
  `accepted` or `reaffirmed`: an action the relying party admitted and still
  vouches for. A rejected decision carries no standing claim (the action was
  refused); a held decision is appraised again when the hold is released.
* A change event carries the new inputs (a new policy, a new allow-list, a
  fresh status list). For every standing decision the log recomputes the five
  digests under the new inputs and compares them with the recorded ones.
  The decisions with at least one changed digest are *selected*; only they
  are re-appraised and recorded: `reaffirmed` (still accepted) or `revoked`
  (now rejected, with the reason code). The event kind does not take part in
  the selection; it names the claims of the assurance case that the event
  reopens and the evidence that closes them.
* The log also measures what a re-appraise-everything rule would have done:
  it appraises every standing decision under the new inputs and counts those
  whose outcome changes. A decision whose outcome changes but whose digests
  did not is a soundness failure; it is recorded under `missed` and the
  property test in `tests/test_reassure.py` asserts the list stays empty.
  Measurement is instrumentation (`measure=True`); the recorded log holds
  only the selected re-appraisals.
* A re-appraisal starts from the relying party's current status view: the
  runner and the tests hand every event a status list fetched for it. The
  soundness property is stated for that discipline; with a stale view, R11
  fails for a reason that is time, not a changed input.
* An audit challenge freezes the challenged decisions whatever their status;
  the replay bundle is the evidence. When the audit's claims close, the
  frozen decisions are replayed under the current inputs and the record says
  whether the replay reproduces the recorded verdict.
* An event that reopens the top-level claim G0 without evidence to close it
  (a runtime-profile change, an action-class escalation) sets G0 `pending`.
  While a claim is pending, new high-risk actions get the verdict `hold`
  (H01); low-risk actions are appraised as usual. Attaching the evidence the
  trigger table names (and, where it is part of that evidence, the policy
  update) sets the claim back to `accepted`; a policy update attached this
  way is selected on like any other input change, and the held actions are
  re-appraised against the inputs current at release.

The six event kinds are the six rows of the trigger table in the article;
`evidence_attached` is the closing move of a row.
"""

from __future__ import annotations

import copy
from typing import Any

from .canon import digest
from .verify import appraise

EVENT_TYPES = {
    # reopens: claims of the assurance case the event reopens
    # auto_close: claims whose re-appraisal evidence the event itself produces
    "trust_list_changed": {"reopens": ["G3", "G4"], "auto_close": ["G3", "G4"]},
    "status_changed": {"reopens": ["G4"], "auto_close": ["G4"]},
    "runtime_profile_changed": {"reopens": ["G0", "G3", "G5"], "auto_close": ["G3"]},
    "action_class_escalation": {"reopens": ["G0", "G4"], "auto_close": ["G4"]},
    "carrier_config_changed": {"reopens": ["G1", "G2"], "auto_close": ["G1", "G2"]},
    "audit_challenge": {"reopens": ["G0", "G1", "G2", "G3", "G4", "G5"], "auto_close": []},
}
PENDING_EVIDENCE = {
    "runtime_profile_changed": {"G0": "regression result for the runtime profile in force + policy update admitting or withdrawing the profile",
                                "G5": "re-assessment record"},
    "action_class_escalation": {"G0": "policy approval of the new action scope (human-approval rule)"},
}
CLAIMS = ("G0", "G1", "G2", "G3", "G4", "G5")
STANDING = ("accepted", "reaffirmed")


class ReassuranceLog:
    def __init__(self, policy: dict, measure: bool = True):
        self.policy = copy.deepcopy(policy)
        self.measure = measure
        self.decisions: list[dict] = []          # append-only
        self.packets: dict[str, dict] = {}       # receipt_id -> packet (replay bundle input)
        self.state = {"claims": {c: "accepted" for c in CLAIMS}, "pending_evidence": {}}
        self.held: dict[str, dict] = {}          # receipt_id -> packet on hold
        self.frozen: dict[str, dict] = {}        # receipt_id -> the decision frozen by an audit challenge
        self.records: list[dict] = []            # re-assurance records, one per event or attachment
        self.current_status_list: dict | None = None   # the relying party's latest status view
        self.whole: dict[str, dict] = {}         # receipt_id -> digests of the WHOLE inputs at decision time (comparison strategy only)
        self.seq = 0

    # -- helpers -----------------------------------------------------------
    def _whole_digests(self, status: dict | None) -> dict:
        """Digests over the whole policy and the whole status list, as a
        selection rule without slices would keep them (v0.2.0 behaviour)."""
        return {"policy": digest(self.policy), "status_list": digest(status) if status is not None else None}

    def _with_current_status(self, packet: dict) -> dict:
        """Re-appraisal consults the status source again: the packet's status
        list is replaced by the latest list the relying party holds."""
        pkt = copy.deepcopy(packet)
        if self.current_status_list is not None and pkt.get("status_list") is not None:
            pkt["status_list"] = self.current_status_list
        return pkt

    def _apply(self, change: dict[str, Any]) -> None:
        if change.get("policy") is not None:
            self.policy = copy.deepcopy(change["policy"])
        if change.get("allowed_runtime_profiles") is not None:
            self.policy["allowed_runtime_profiles"] = copy.deepcopy(change["allowed_runtime_profiles"])
        if change.get("status_list") is not None:
            self.current_status_list = change["status_list"]

    def _append(self, decision: dict, status: str, event_seq: int, extra: dict | None = None) -> None:
        self.seq += 1
        d = copy.deepcopy(decision)
        d["seq"] = self.seq
        d["status"] = status
        d["re_appraisal"] = True
        d["event_seq"] = event_seq
        for k in ("changed_inputs", "replay_matches_recorded"):   # belong to one re-appraisal, never inherited
            d.pop(k, None)
        if extra:
            d.update(extra)
        self.decisions.append(d)

    # -- decisions ---------------------------------------------------------
    def decide(self, packet: dict, now: str | None = None) -> dict:
        d = appraise(packet, self.policy, self.state, now=now)
        self.seq += 1
        d["seq"] = self.seq
        d["status"] = d["verdict"]
        d["re_appraisal"] = False
        self.decisions.append(d)
        self.packets[d["receipt_id"]] = packet
        self.whole[d["receipt_id"]] = self._whole_digests(packet.get("status_list"))
        if d["verdict"] == "hold":
            self.held[d["receipt_id"]] = packet
        return d

    def latest(self) -> dict[str, dict]:
        """Latest decision per receipt id."""
        out: dict[str, dict] = {}
        for d in self.decisions:
            if d["receipt_id"]:
                out[d["receipt_id"]] = d
        return out

    def standing(self) -> list[tuple[str, dict]]:
        return sorted(((rid, d) for rid, d in self.latest().items() if d["status"] in STANDING), key=lambda kv: kv[1]["seq"])

    # -- selection ---------------------------------------------------------
    def _select_and_reappraise(self, at: str, event_seq: int) -> dict:
        """Compare the five digests of every standing decision under the
        current inputs; re-appraise and record the selected ones. Returns the
        selection record, including the re-appraise-all measurement."""
        affected, outcomes, missed = [], [], []
        standing = self.standing()
        outcome_changed = 0
        whole_now = self._whole_digests(self.current_status_list)
        selected_whole = 0
        for rid, d in standing:
            pkt = self._with_current_status(self.packets[rid])
            w = self.whole.get(rid, {})
            if w.get("policy") != whole_now["policy"] or (pkt.get("status_list") is not None and w.get("status_list") != digest(pkt["status_list"])):
                selected_whole += 1
            re = appraise(pkt, self.policy, None, now=at)
            changed = sorted(k for k in d["depends_on"] if d["depends_on"][k] != re["depends_on"].get(k))
            differs = not re["accepted"]            # a standing decision is accepted; its outcome changes iff it is now rejected
            if self.measure and differs:
                outcome_changed += 1
            if not changed:
                if differs:
                    missed.append(rid)
                continue
            affected.append(rid)
            outcome = "reaffirmed" if re["accepted"] else "revoked"
            outcomes.append({"receipt_id": rid, "case_id": d["case_id"], "outcome": outcome,
                             "reason_code": re["reason_code"], "changed_inputs": changed})
            self._append(re, status=outcome, event_seq=event_seq, extra={"changed_inputs": changed})
        return {"standing": len(standing), "selected": len(affected), "selected_whole_input": selected_whole, "affected": affected,
                "outcomes": outcomes, "outcome_changed": outcome_changed if self.measure else None, "missed": missed}

    # -- events ------------------------------------------------------------
    def event(self, kind: str, at: str, change: dict[str, Any], note: str = "") -> dict:
        spec = EVENT_TYPES[kind]
        before_policy = copy.deepcopy(self.policy)
        event_seq = len(self.records) + 1
        self._apply(change)
        reopened = list(spec["reopens"])
        for cl in reopened:
            self.state["claims"][cl] = "pending"
        if kind == "audit_challenge":
            # freeze the challenged decisions whatever their status; the replay bundle is the evidence
            affected, outcomes = [], []
            standing_before = len(self.standing())          # counted before the freeze, as for every other event
            for rid, d in sorted(self.latest().items(), key=lambda kv: kv[1]["seq"]):
                if rid in change.get("receipt_ids", []):
                    affected.append(rid)
                    outcomes.append({"receipt_id": rid, "case_id": d["case_id"], "outcome": "frozen",
                                     "reason_code": None, "changed_inputs": []})
                    self.frozen[rid] = d
                    self._append(d, status="frozen", event_seq=event_seq, extra={"appraised_at": at, "changed_inputs": []})
            sel = {"standing": standing_before, "selected": len(affected), "selected_whole_input": 0, "affected": affected,
                   "outcomes": outcomes, "outcome_changed": 0 if self.measure else None, "missed": []}
        else:
            sel = self._select_and_reappraise(at, event_seq)
        for cl in spec["auto_close"]:
            self.state["claims"][cl] = "accepted"
        for cl, ev in PENDING_EVIDENCE.get(kind, {}).items():
            self.state["pending_evidence"][cl] = ev
        rec = {
            "event_seq": event_seq, "kind": kind, "at": at, "note": note,
            "reopened_claims": reopened,
            "claims_after": dict(self.state["claims"]),
            "pending_evidence": dict(self.state["pending_evidence"]),
            "policy_digest_before": digest(before_policy), "policy_digest_after": digest(self.policy),
            "inputs_changed": sorted(k for k in ("policy", "allowed_runtime_profiles", "status_list") if change.get(k) is not None),
            **sel,
            "held_actions": sorted(self.held),
            "frozen_decisions": sorted(self.frozen),
        }
        self.records.append(rec)
        return rec

    def attach_evidence(self, claims: str | list[str], at: str, evidence: dict, note: str = "",
                        status_list: dict | None = None, policy: dict | None = None) -> dict:
        """Operator closes pending claims with the evidence the trigger table
        names. A policy update that is part of that evidence is applied here
        and selected on like any other input change. When no claim is
        pending any more, held actions are re-appraised (with the current
        inputs) and released or rejected, and frozen decisions are replayed."""
        if isinstance(claims, str):
            claims = [claims]
        before_policy = copy.deepcopy(self.policy)
        event_seq = len(self.records) + 1
        self._apply({"status_list": status_list, "policy": policy})
        for claim in claims:
            self.state["claims"][claim] = "accepted"
            self.state["pending_evidence"].pop(claim, None)
        if policy is not None or status_list is not None:
            sel = self._select_and_reappraise(at, event_seq)
        else:
            sel = {"standing": len(self.standing()), "selected": 0, "affected": [], "outcomes": [],
                   "outcome_changed": 0 if self.measure else None, "missed": []}
        released, replayed = [], []
        if not any(st == "pending" for st in self.state["claims"].values()):
            for rid, pkt in list(self.held.items()):
                d = self.decide(self._with_current_status(pkt), now=at)
                released.append({"receipt_id": rid, "case_id": d["case_id"], "verdict": d["verdict"], "reason_code": d["reason_code"]})
                if d["verdict"] != "hold":
                    self.held.pop(rid)
            for rid, frozen in list(self.frozen.items()):
                pkt = self._with_current_status(self.packets[rid])
                re = appraise(pkt, self.policy, None, now=at)
                outcome = "reaffirmed" if re["accepted"] else "revoked"
                matches = (re["verdict"], re["reason_code"]) == (frozen["verdict"], frozen["reason_code"])
                replayed.append({"receipt_id": rid, "case_id": frozen["case_id"], "outcome": outcome,
                                 "reason_code": re["reason_code"], "replay_matches_recorded": matches})
                self._append(re, status=outcome, event_seq=event_seq, extra={"replay_matches_recorded": matches})
                self.frozen.pop(rid)
        rec = {"event_seq": event_seq, "kind": "evidence_attached", "at": at, "note": note,
               "claim": ";".join(claims), "evidence": evidence, "claims_after": dict(self.state["claims"]),
               "pending_evidence": dict(self.state["pending_evidence"]),
               "policy_digest_before": digest(before_policy), "policy_digest_after": digest(self.policy),
               "inputs_changed": sorted(k for k, v in (("policy", policy), ("status_list", status_list)) if v is not None),
               **sel,
               "released": released, "replayed": replayed,
               "held_actions": sorted(self.held), "frozen_decisions": sorted(self.frozen)}
        self.records.append(rec)
        return rec

    # -- audit -------------------------------------------------------------
    def replay_bundle(self, receipt_id: str) -> dict:
        """Everything an assessor needs to re-run one decision: the packet, the
        policy in force, and every decision recorded for the receipt."""
        return {
            "receipt_id": receipt_id,
            "packet": self.packets[receipt_id],
            "policy": self.policy,
            "decisions": [d for d in self.decisions if d["receipt_id"] == receipt_id],
        }

    def strategies(self) -> list[dict]:
        """Re-appraisal count and revocations caught under four rules on the
        recorded events: never re-appraise (static verdict), re-appraise every
        standing decision at every input change, re-appraise the decisions
        whose digest over a WHOLE changed input differs (no slices), and
        re-appraise the slice-digest-selected decisions only."""
        evs = [r for r in self.records if r.get("inputs_changed")]
        revoked = sum(1 for r in self.records for o in r.get("outcomes", []) if o["outcome"] == "revoked")
        all_n = sum(r["standing"] for r in evs)
        sel_n = sum(r["selected"] for r in evs)
        changed = sum((r.get("outcome_changed") or 0) for r in evs)
        missed = sum(len(r.get("missed", [])) for r in evs)
        whole_n = sum(r.get("selected_whole_input", 0) for r in evs)
        return [
            {"strategy": "static_verdict", "description": "never re-appraise a recorded decision", "input_changes": len(evs),
             "re_appraisals": 0, "revocations_caught": 0, "revocations_missed": revoked},
            {"strategy": "reappraise_all", "description": "re-appraise every standing decision at every input change", "input_changes": len(evs),
             "re_appraisals": all_n, "revocations_caught": changed, "revocations_missed": 0},
            {"strategy": "whole_input_digest", "description": "re-appraise the decisions whose digest over a whole changed input differs (no slices)", "input_changes": len(evs),
             "re_appraisals": whole_n, "revocations_caught": revoked, "revocations_missed": 0},
            {"strategy": "digest_selected", "description": "re-appraise the decisions whose input-slice digests changed (this article)", "input_changes": len(evs),
             "re_appraisals": sel_n, "revocations_caught": revoked, "revocations_missed": missed},
        ]
