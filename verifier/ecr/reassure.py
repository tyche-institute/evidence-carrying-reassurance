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
from .verify import appraise, receipt_payload, unwrap

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


def decision_keys(packet: dict) -> set[tuple[str, str]]:
    """The identifiers a keyed invalidation index (in the style of CAEP or
    token introspection) would file a decision under: the roots the issuer
    asserts, the timestamp root, the broker, the approver, the delegation id
    and its status source, the three runtime-profile values, the action
    class, and the carrier's members. Comparison strategy only."""
    rp = receipt_payload(packet.get("evidence")) or {}
    _, env = unwrap(packet.get("evidence"))
    issuer = rp.get("issuer") or {}
    keys: set[tuple[str, str]] = set()
    for e in issuer.get("endorsements") or []:
        if isinstance(e, dict) and isinstance(e.get("payload"), dict) and e["payload"].get("root"):
            keys.add(("root", e["payload"]["root"]))
    if issuer.get("root"):
        keys.add(("root", issuer["root"]))
    tp = (packet.get("timestamp_token") or {}).get("payload") or {}
    if tp.get("root"):
        keys.add(("timestamp_root", tp["root"]))
    ep = (env or {}).get("payload") or {}
    if ep.get("broker"):
        keys.add(("broker", ep["broker"]))
    cap = (packet.get("co_approval") or {}).get("payload") or {}
    if cap.get("approver"):
        keys.add(("approver", cap["approver"]))
    deleg = rp.get("delegation") or {}
    if deleg.get("id"):
        keys.add(("delegation", deleg["id"]))
    sp = ((packet.get("status_list") or {}).get("payload") or {})
    for src in (deleg.get("status_source"), sp.get("source")):
        if src:
            keys.add(("status_source", src))
    rt = rp.get("runtime") or {}
    for k, f in (("model_version", "model_version"), ("tool_profile", "tool_profile_digest"), ("prompt_profile", "prompt_profile_digest")):
        if rt.get(f):
            keys.add((k, rt[f]))
    if (rp.get("action") or {}).get("class"):
        keys.add(("action_class", rp["action"]["class"]))
    rec = packet.get("carrier_record") or {}
    for k in ("carrier", "instance", "client", "service"):
        if rec.get(k):
            keys.add((k, rec[k]))
    return keys


def changed_keys(before: dict, after: dict, status_before: dict | None, status_after: dict | None) -> set[tuple[str, str]]:
    """The identifiers a change names, as an issuer of change signals would
    name them: every table entry added, removed or edited, every runtime
    value admitted or withdrawn, every status entry that differs. Thresholds,
    the verifier profile and the message-log flag name no identifier."""
    out: set[tuple[str, str]] = set()
    for table, kind in (("accepted_roots", "root"), ("accepted_timestamp_roots", "timestamp_root"), ("accepted_brokers", "broker"),
                        ("approvers", "approver"), ("status_sources", "status_source"), ("action_classes", "action_class")):
        a, b = before.get(table) or {}, after.get(table) or {}
        out |= {(kind, k) for k in set(a) | set(b) if a.get(k) != b.get(k)}
    for field, kind in (("model_versions", "model_version"), ("tool_profile_digests", "tool_profile"), ("prompt_profile_digests", "prompt_profile")):
        a = set(before["allowed_runtime_profiles"].get(field, [])); b = set(after["allowed_runtime_profiles"].get(field, []))
        out |= {(kind, v) for v in a ^ b}
    ca, cb = before["carrier"], after["carrier"]
    for field, kind in (("accepted_clients", "client"), ("accepted_services", "service")):
        out |= {(kind, v) for v in set(ca.get(field, [])) ^ set(cb.get(field, []))}
    for field in ("carrier", "instance"):
        if ca.get(field) != cb.get(field):
            out |= {(field, ca.get(field)), (field, cb.get(field))}
    if status_after is not None:
        ea = ((status_before or {}).get("payload") or {}).get("entries") or {}
        eb = (status_after.get("payload") or {}).get("entries") or {}
        out |= {("delegation", d) for d in set(ea) | set(eb) if ea.get(d) != eb.get(d)}
        sa, sb = ((status_before or {}).get("payload") or {}).get("source"), (status_after.get("payload") or {}).get("source")
        ka, kb = ((status_before or {}).get("signature") or {}).get("key_id"), (status_after.get("signature") or {}).get("key_id")
        if status_before is not None and (sa != sb or ka != kb):
            out |= {("status_source", sa), ("status_source", sb)}
    return out


KEYED_POLICY_FIELDS = ("accepted_roots", "accepted_timestamp_roots", "accepted_brokers", "approvers", "status_sources",
                       "action_classes", "allowed_runtime_profiles")
KEYED_CARRIER_FIELDS = ("accepted_clients", "accepted_services", "carrier", "instance")


def unkeyed_change(before: dict, after: dict) -> bool:
    """Whether the policy changed outside the tables a keyed index files
    decisions under: a threshold, the verifier profile, the message-log flag."""
    def rest(p: dict) -> dict:
        r = {k: v for k, v in p.items() if k not in KEYED_POLICY_FIELDS}
        r["carrier"] = {k: v for k, v in (p.get("carrier") or {}).items() if k not in KEYED_CARRIER_FIELDS}
        return r
    return digest(rest(before)) != digest(rest(after))


def _entries_view(status: dict | None) -> dict | None:
    """A status list without its issue time and signature: source and entries."""
    if status is None:
        return None
    sp = status.get("payload") or {}
    return {"source": sp.get("source"), "entries": sp.get("entries"), "key_id": (status.get("signature") or {}).get("key_id")}


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
        self._status_seen: dict | None = None    # before any status event: the list the accepted packets carried (comparison strategies only)
        self.keys: dict[str, set] = {}           # receipt_id -> identifiers a keyed index files it under (comparison strategy only)
        self._before: tuple[dict, dict | None] | None = None   # inputs before the current change (comparison strategies only)
        self.seq = 0

    # -- helpers -----------------------------------------------------------
    def _with_current_status(self, packet: dict) -> dict:
        """Re-appraisal consults the status source again: the packet's status
        list is replaced by the latest list the relying party holds."""
        pkt = copy.deepcopy(packet)
        if self.current_status_list is not None and pkt.get("status_list") is not None:
            pkt["status_list"] = self.current_status_list
        return pkt

    def _apply(self, change: dict[str, Any]) -> None:
        self._before = (copy.deepcopy(self.policy), self.current_status_list or self._status_seen)
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
        self.keys[d["receipt_id"]] = decision_keys(packet)
        if d["accepted"] and packet.get("status_list") is not None:
            self._status_seen = packet["status_list"]
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
        # comparison strategies, measured on the same standing set: a digest over each whole input
        # (the status list as received, issue time included), the same over the status entries only,
        # and a keyed index that selects the decisions filed under an identifier the change names
        pol_before, st_before = self._before if self._before is not None else (self.policy, self.current_status_list or self._status_seen)
        st_after = self.current_status_list
        policy_changed = digest(pol_before) != digest(self.policy)
        whole_all = policy_changed or (st_after is not None and digest(st_before) != digest(st_after))
        entries_all = policy_changed or (st_after is not None and _entries_view(st_before) != _entries_view(st_after))
        named = changed_keys(pol_before, self.policy, st_before, st_after)
        unkeyed = unkeyed_change(pol_before, self.policy)
        cmp = {k: {"selected": 0, "caught": 0, "missed": 0, "disagree": 0} for k in ("whole_input", "entries_only", "keyed_index", "keyed_fallback")}
        for rid, d in standing:
            pkt = self._with_current_status(self.packets[rid])
            re = appraise(pkt, self.policy, None, now=at)
            changed = sorted(k for k in d["depends_on"] if d["depends_on"][k] != re["depends_on"].get(k))
            differs = not re["accepted"]            # a standing decision is accepted; its outcome changes iff it is now rejected
            if self.measure and differs:
                outcome_changed += 1
            keyed = bool(self.keys.get(rid, set()) & named)
            for k, sel_k in (("whole_input", whole_all), ("entries_only", entries_all), ("keyed_index", keyed), ("keyed_fallback", keyed or unkeyed)):
                cmp[k]["selected"] += 1 if sel_k else 0
                cmp[k]["disagree"] += 1 if sel_k != bool(changed) else 0     # selected by one of the two rules only
                if differs:
                    cmp[k]["caught" if sel_k else "missed"] += 1
            if not changed:
                if differs:
                    missed.append(rid)
                continue
            affected.append(rid)
            outcome = "reaffirmed" if re["accepted"] else "revoked"
            outcomes.append({"receipt_id": rid, "case_id": d["case_id"], "outcome": outcome,
                             "reason_code": re["reason_code"], "changed_inputs": changed})
            self._append(re, status=outcome, event_seq=event_seq, extra={"changed_inputs": changed})
        return {"standing": len(standing), "selected": len(affected), "selected_whole_input": cmp["whole_input"]["selected"],
                "comparison": cmp, "affected": affected,
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
            sel = {"standing": standing_before, "selected": len(affected), "selected_whole_input": 0, "comparison": None, "affected": affected,
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
            sel = {"standing": len(self.standing()), "selected": 0, "comparison": None, "affected": [], "outcomes": [],
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
        """Re-appraisal count and outcome changes caught and missed under seven
        rules on the recorded events, each measured on the same standing
        decisions at every input change: never re-appraise (static verdict);
        re-appraise every standing decision (the reference); re-appraise all
        when a whole input's digest changed, with the status list digested as
        received and with its entries only; re-appraise the decisions filed
        under an identifier the change names (keyed index), alone and with
        re-appraise-all when the change names no identifier; and re-appraise
        the decisions whose input-slice digests changed."""
        evs = [r for r in self.records if r.get("inputs_changed")]
        n = len(evs)
        all_n = sum(r["standing"] for r in evs)
        changed = sum((r.get("outcome_changed") or 0) for r in evs)
        sel_n = sum(r["selected"] for r in evs)
        missed = sum(len(r.get("missed", [])) for r in evs)
        def cmp(k: str, f: str) -> int:
            return sum((r.get("comparison") or {}).get(k, {}).get(f, 0) for r in evs)
        rows = [
            ("static_verdict", "never re-appraise a recorded decision", 0, 0, changed),
            ("reappraise_all", "re-appraise every standing decision at every input change", all_n, changed, 0),
            ("whole_input_digest", "re-appraise all when the digest of a whole input (policy, or status list as received) changed", cmp("whole_input", "selected"), cmp("whole_input", "caught"), cmp("whole_input", "missed")),
            ("entries_only_digest", "as above, with the status list digested without its issue time", cmp("entries_only", "selected"), cmp("entries_only", "caught"), cmp("entries_only", "missed")),
            ("keyed_index", "re-appraise the decisions filed under an identifier the change names", cmp("keyed_index", "selected"), cmp("keyed_index", "caught"), cmp("keyed_index", "missed")),
            ("keyed_index_fallback", "as above, and re-appraise all when the change names no identifier", cmp("keyed_fallback", "selected"), cmp("keyed_fallback", "caught"), cmp("keyed_fallback", "missed")),
            ("digest_selected", "re-appraise the decisions whose input-slice digests changed", sel_n, changed - missed, missed),
        ]
        return [{"strategy": a, "description": b, "input_changes": n, "re_appraisals": c, "revocations_caught": d, "revocations_missed": e} for a, b, c, d, e in rows]
