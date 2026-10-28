#!/usr/bin/env python3
"""Appraise every fixture, run the re-assurance scenario, write the tables.

    python3 verifier/run_matrix.py [--root <artifact dir>] [--out <dir>]

Default --out is <root>/expected. `make check` runs it into a temporary
directory and diffs against the committed expected/ tree.

Outputs
  policy-cases.csv, brokered-evidence-fixtures.csv, carrier-evidence-matrix.csv
  coverage-controls.csv            one packet per reason code the three tables do not reach
  first-failure-summary.csv        counts per layer and family
  traceability.csv                 threat -> case -> fixture -> layer/code -> mitigation -> claim
  baselines.csv                    weaker acceptance rules on the same packets
  reason-codes.csv                 the code table, with the cases that reach each code and the
                                   number of recorded decisions whose check log shows it failing
  decisions/<case>.json            full decision record per table or coverage packet
  worked-examples/<case>.md        packet + decision + check log, P01 and P07
  reassurance/{log.jsonl,records.json,summary.csv,strategies.csv,decisions/S*.json,replay-bundle-P01.json}
  RUN-SUMMARY.json                 headline numbers quoted in the article
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ecr import __version__, catalogue  # noqa: E402
from ecr import ablation  # noqa: E402
from ecr import randomseq  # noqa: E402
from ecr.baselines import summarise  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402
import random  # noqa: E402
from ecr.canon import digest, file_sha256  # noqa: E402
from ecr.codes import CODES  # noqa: E402
from ecr.objects import status_list  # noqa: E402
from ecr.reassure import ReassuranceLog  # noqa: E402
from ecr.verify import appraise  # noqa: E402

CLAIM_OF_LAYER = {"carrier": "G1", "binding": "G2", "evidence": "G3", "policy": "G4", "none": "—"}
TABLE_FAMILIES = ("policy-cases", "brokered-evidence-fixtures", "carrier-evidence-matrix")


def load(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def dump_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(p: Path, rows: list[dict], fields: list[str]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: ("" if r.get(k) is None else r.get(k)) for k in fields})


def b(x) -> str:
    return "True" if x else "False"


def worked_example_md(case: dict, packet: dict, decision: dict) -> str:
    out = [f"# Worked example {case['case_id']}", "", case["description"], "",
           f"* family: {case['family']}; claim strength: {case['claim_strength']}; threat: {case['threat_id']}",
           f"* verdict: **{decision['verdict']}**; first-failure layer: {decision['first_failure_layer']}; reason: {decision['reason_code'] or '—'} — {decision['reason']}",
           f"* predicates: " + ", ".join(f"{k}={v}" for k, v in decision["predicates"].items()), ""]
    for name in ("carrier_record", "evidence", "timestamp_token", "status_list", "co_approval"):
        out += [f"## {name}", "", "```json", json.dumps(packet.get(name), indent=2, sort_keys=True, ensure_ascii=False), "```", ""]
    out += ["## check log", "", "| layer | check | result | detail |", "|---|---|---|---|"]
    for layer in ("carrier", "binding", "evidence", "policy"):
        for e in decision["checks"][layer]:
            out.append(f"| {layer} | {e['check']} | {e['result']} | {e['detail'].replace('|', '/')} |")
    out += ["", "## decision record (depends_on digests)", "", "```json", json.dumps(decision["depends_on"], indent=2, sort_keys=True), "```", ""]
    return "\n".join(out)


# --------------------------------------------------------------------------- sensitivity
SENSITIVITY_SEEDS = 100
SENSITIVITY_EVENTS = 40


def run_sensitivity(policy: dict, table_packets: list[dict], seeds: int = SENSITIVITY_SEEDS, n_events: int = SENSITIVITY_EVENTS) -> list[dict]:
    """The committed scenario is one author-chosen sequence. Here the same
    decision set (every executed table and coverage packet) meets `seeds`
    seeded random sequences of `n_events` input changes drawn from every
    table the checks read; the row reports how much work the slice digests
    selected against re-appraising everything, and that nothing was missed."""
    rows = []
    for seed in range(seeds):
        rng = random.Random(seed)
        log = ReassuranceLog(policy)
        for pkt in table_packets:
            log.decide(pkt)
        registry = json.loads(json.dumps(catalogue.STATUS_ENTRIES))
        at = datetime(2026, 6, 1, 9, 0, tzinfo=timezone.utc)
        tot = {"standing": 0, "selected": 0, "whole": 0, "changed": 0, "missed": 0, "inputs": 0}
        for i in range(n_events):
            at += timedelta(days=1)
            kind, change = randomseq.random_change(rng, log.policy, registry, at)
            rec = log.event(kind, randomseq.iso(at), change, f"seed {seed} event {i}")
            tot["standing"] += rec["standing"]; tot["selected"] += rec["selected"]; tot["whole"] += rec["selected_whole_input"]
            tot["changed"] += rec["outcome_changed"]; tot["missed"] += len(rec["missed"]); tot["inputs"] += 1 if rec["inputs_changed"] else 0
        rows.append({"seed": seed, "events": n_events, "input_changes": tot["inputs"], "standing_total": tot["standing"], "selected": tot["selected"],
                     "whole_input_selected": tot["whole"], "outcome_changed": tot["changed"], "missed": tot["missed"],
                     "selected_share": f"{tot['selected'] / tot['standing']:.3f}" if tot["standing"] else ""})
    return rows


# --------------------------------------------------------------------------- the scenario

def run_reassurance(root: Path, policy: dict, packets: dict[str, dict]) -> tuple[ReassuranceLog, list[dict], dict]:
    """Five simulated weeks (3 June to 8 July 2026) of the relying party's
    log: three decisions of the first run, then the trigger table's six event
    kinds, a negative-control policy change, a status renewal, an audit with a
    high-risk action arriving during it, a withdrawal of the old runtime
    profile, and the new actions that arrive in between.
    All clocks are literals ('simulated time')."""
    log = ReassuranceLog(policy)
    for cid in ("P01_direct_trusted_issuer", "P02_brokered_trusted_issuer", "P14_clock_skew_inside_window"):
        log.decide(packets[cid])
    summary: list[dict] = []
    registry = json.loads(json.dumps(catalogue.STATUS_ENTRIES))   # the registry's current entries

    def row(rec: dict, extra: str = "") -> None:
        oc = Counter(o["outcome"] for o in rec.get("outcomes", []))
        rp = Counter(o["outcome"] for o in rec.get("replayed", []))
        summary.append({
            "event_seq": rec["event_seq"], "kind": rec["kind"], "at": rec["at"], "note": rec.get("note", ""),
            "reopened_claims": ";".join(rec.get("reopened_claims", [])),
            "claims_closed": rec.get("claim", ""),
            "inputs_changed": ";".join(rec.get("inputs_changed", [])),
            "standing": rec.get("standing", ""), "selected": rec.get("selected", ""),
            "outcome_changed": "" if rec.get("outcome_changed") is None else rec.get("outcome_changed"),
            "missed": len(rec.get("missed", [])),
            "reaffirmed": oc.get("reaffirmed", 0) + rp.get("reaffirmed", 0), "revoked": oc.get("revoked", 0) + rp.get("revoked", 0),
            "frozen": oc.get("frozen", 0), "released": len(rec.get("released", [])),
            "held_after": len(rec.get("held_actions", [])),
            "claims_pending_after": ";".join(sorted(c for c, s in rec["claims_after"].items() if s == "pending")),
            "detail": extra,
        })

    def fresh_status(issued_at: str, **changes) -> dict:
        """The registry's list as the relying party fetches it at re-appraisal."""
        registry.update(changes)
        return status_list("status-municipal", catalogue.STATUS_SOURCES["status-municipal"], issued_at, json.loads(json.dumps(registry)))

    def new_action(cid: str, note: str) -> dict:
        d = log.decide(packets[cid])
        summary.append({"event_seq": "", "kind": "new_action", "at": packets[cid]["presented_at"], "note": note,
                        "reopened_claims": "", "claims_closed": "", "inputs_changed": "", "standing": "", "selected": "", "outcome_changed": "", "missed": "",
                        "reaffirmed": "", "revoked": "", "frozen": "", "released": "",
                        "held_after": len(log.held), "claims_pending_after": ";".join(sorted(c for c, s in log.state["claims"].items() if s == "pending")),
                        "detail": f"{cid}: verdict {d['verdict']} ({d['reason_code'] or 'all four predicates hold'})"})
        return d

    def sel(rec: dict) -> str:
        return f"standing {rec['standing']}, selected {rec['selected']}, outcome changed {rec['outcome_changed']}"

    # E1 trust list changes: vendor root admitted for read-only actions
    p1 = json.loads(json.dumps(log.policy))
    p1["accepted_roots"]["root:vendor-demo-ca"] = {"key_id": catalogue.key_id_for("root-vendor-demo-ca"), "accepted_for": ["read"]}
    rec = log.event("trust_list_changed", "2026-06-03T09:00:00Z", {"policy": p1, "status_list": fresh_status("2026-06-03T08:30:00Z")},
                    "vendor root admitted for read-only actions")
    row(rec, "no standing decision consulted the vendor root's entry; " + sel(rec))
    # E2 status change: del-002 revoked by the registry
    rec = log.event("status_changed", "2026-06-10T08:30:00Z",
                    {"status_list": fresh_status("2026-06-10T08:00:00Z", **{"del-002": {"status": "revoked", "since": "2026-06-10T07:45:00Z"}})},
                    "registry re-issues the list with del-002 revoked")
    row(rec, "the one decision under del-002 (P02) selected and revoked; decisions under del-001 not selected; " + sel(rec))
    # E3 runtime profile change: model upgraded; policy not yet updated
    rec = log.event("runtime_profile_changed", "2026-06-17T07:00:00Z", {"status_list": fresh_status("2026-06-17T06:30:00Z")},
                    f"model {catalogue.MODEL_VERSION} -> {catalogue.MODEL_VERSION_NEXT} deployed; policy unchanged")
    row(rec, "the relying party refreshes its status view; no entry a standing decision read changed; G0 and G5 pending until the trigger table's evidence is attached; " + sel(rec))
    new_action("S01_mutate_with_co_approval", "S01: mutate with co-approval, previous model")
    new_action("S02_read_with_new_model_version", "S02: read with the new model version")
    # operator attaches the trigger table's evidence
    rec = log.attach_evidence("G5", "2026-06-17T15:00:00Z", {"reassessment_record": "re-assessment of the enrichment workflow under the new model"}, "re-assessment record filed")
    row(rec, "G0 still pending; held action stays held")
    p3 = json.loads(json.dumps(log.policy))
    p3["allowed_runtime_profiles"]["model_versions"].append(catalogue.MODEL_VERSION_NEXT)
    rec = log.attach_evidence("G0", "2026-06-17T16:00:00Z",
                              {"regression_result": "pass: 48/48 enrichment regression cases under " + catalogue.MODEL_VERSION_NEXT,
                               "policy_update": p3["policy_id"] + " admits " + catalogue.MODEL_VERSION_NEXT},
                              "regression passed; policy admits the new profile",
                              status_list=fresh_status("2026-06-17T15:30:00Z"), policy=p3)
    row(rec, "policy update selected on: the admitted profile is not the one the standing decisions carry; held action released: "
        + "; ".join(f"{r['case_id']}={r['verdict']}" for r in rec["released"]) + "; " + sel(rec))
    new_action("S04_read_with_new_model_version_after_policy_update", "S04: the S02 action repeated after the policy update")
    # E4 action-class escalation attempt
    d_esc = new_action("S03_mutate_outside_scope_with_co_approval", "S03: mutation under a read/enrich delegation, co-approval present")
    rec = log.event("action_class_escalation", "2026-06-20T10:00:00Z", {"status_list": fresh_status("2026-06-20T09:30:00Z")},
                    "mutation requested under a read/enrich delegation")
    row(rec, f"S03 verdict {d_esc['verdict']} ({d_esc['reason_code']}); fresh status view changes no entry a standing decision read; G0 pending until the new scope is approved; " + sel(rec))
    rec = log.attach_evidence("G0", "2026-06-20T14:00:00Z", {"policy_approval": "SOC lead approves scope read/enrich/mutate for the agent under del-006 with co-approval"}, "scope approved")
    row(rec, "no held actions")
    # E5 carrier configuration change
    p5 = json.loads(json.dumps(log.policy))
    p5["carrier"]["accepted_services"].append("DEV/COM/1234/TestService/mock2")
    rec = log.event("carrier_config_changed", "2026-06-24T09:00:00Z", {"policy": p5, "status_list": fresh_status("2026-06-24T08:30:00Z")},
                    "second service admitted on the carrier")
    row(rec, "every standing decision's carrier record names the first service; its membership did not change; " + sel(rec))
    # E6 negative control: a policy change outside every slice a standing decision read
    p6 = json.loads(json.dumps(log.policy))
    p6["approvers"]["approver:soc-deputy"] = {"key_id": catalogue.key_id_for("approver-soc-deputy")}
    rec = log.event("trust_list_changed", "2026-06-26T10:00:00Z", {"policy": p6, "status_list": fresh_status("2026-06-26T09:30:00Z")},
                    "negative control: a second approver registered")
    row(rec, "negative control: no standing decision carries a co-approval by the new approver; " + sel(rec))
    # E7 status renewal: the registry re-issues del-001 with a renewal mark (status still active)
    rec = log.event("status_changed", "2026-06-29T09:00:00Z",
                    {"status_list": fresh_status("2026-06-29T08:30:00Z", **{"del-001": {"status": "active", "renewed_at": "2026-06-29T08:00:00Z"}})},
                    "registry re-issues del-001 after renewal; status active")
    row(rec, "every decision under del-001 selected (its status entry changed) and reaffirmed; " + sel(rec))
    # E8 audit challenge on P01; a high-risk action arrives during the audit
    p01_rid = next(d["receipt_id"] for d in log.decisions if d["case_id"] == "P01_direct_trusted_issuer")
    rec = log.event("audit_challenge", "2026-06-30T09:00:00Z", {"receipt_ids": [p01_rid]}, "auditor challenges the enrichment decision")
    row(rec, "decision frozen; replay bundle produced; every claim pending")
    new_action("S05_mutate_during_audit", "S05: mutate with co-approval, admitted model, during the audit")
    bundle = log.replay_bundle(p01_rid)
    rec = log.attach_evidence(["G0", "G1", "G2", "G3", "G4", "G5"], "2026-06-30T13:00:00Z",
                              {"replay_bundle_digest": digest(bundle), "reviewer_note": "replay reproduces the recorded decision"},
                              "re-assurance record closes the challenge", status_list=fresh_status("2026-06-30T12:30:00Z"))
    row(rec, "frozen decision replayed: " + "; ".join(f"{r['case_id']}={r['outcome']}, replay matches recorded={r['replay_matches_recorded']}" for r in rec["replayed"])
        + "; held action released: " + "; ".join(f"{r['case_id']}={r['verdict']}" for r in rec["released"]))
    # E9 runtime profile withdrawn: the old model version leaves the allow-list after a defect report
    allowed = json.loads(json.dumps(log.policy["allowed_runtime_profiles"]))
    allowed["model_versions"] = [catalogue.MODEL_VERSION_NEXT]
    rec = log.event("runtime_profile_changed", "2026-07-08T09:00:00Z",
                    {"allowed_runtime_profiles": allowed, "status_list": fresh_status("2026-07-08T08:30:00Z")},
                    f"model {catalogue.MODEL_VERSION} withdrawn from the allow-list after a defect report")
    row(rec, "decisions carrying the withdrawn profile selected and revoked (R21); decisions under the admitted profile not selected; " + sel(rec))
    rec = log.attach_evidence(["G0", "G5"], "2026-07-08T15:00:00Z",
                              {"defect_report": "DR-2026-031 filed against " + catalogue.MODEL_VERSION,
                               "policy_update": log.policy["policy_id"] + " withdraws " + catalogue.MODEL_VERSION,
                               "review_list": sorted(o["case_id"] for o in log.records[-1]["outcomes"] if o["outcome"] == "revoked")},
                              "defect report filed; revoked decisions listed for operator review")
    row(rec, "no held actions; all claims accepted")
    return log, summary, bundle


# --------------------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    root = Path(a.root)
    out = Path(a.out) if a.out else root / "expected"
    policy = load(root / "policy" / "relying-party-policy.json")
    index = load(root / "fixtures" / "index.json")
    cases = {c["case_id"]: c for c in index["cases"]}
    packets: dict[str, dict] = {}
    decisions: dict[str, dict] = {}
    mismatches = []
    for c in index["cases"]:
        if not c["executed"]:
            continue
        pkt = load(root / c["fixture"])
        packets[c["case_id"]] = pkt
        if c["family"] == "scenario":
            continue                      # appraised inside the scenario, under the policy in force there
        d = appraise(pkt, policy)
        d["fixture"] = c["fixture"]
        d["fixture_sha256"] = file_sha256(root / c["fixture"])
        decisions[c["case_id"]] = d
        dump_json(out / "decisions" / f"{c['case_id']}.json", d)
        if d["first_failure_layer"] != c["intended_layer"] or (c["intended_code"] and d["reason_code"] != c["intended_code"]):
            mismatches.append((c["case_id"], c["intended_layer"], c["intended_code"], d["first_failure_layer"], d["reason_code"]))

    # re-assurance scenario (also yields the scenario packets' first decisions)
    log, rsummary, bundle = run_reassurance(root, policy, packets)
    first_scenario: dict[str, dict] = {}
    for d in log.decisions:
        if d["case_id"] in catalogue.SCENARIO_PACKETS and not d["re_appraisal"] and d["case_id"] not in first_scenario:
            first_scenario[d["case_id"]] = d
    for cid, (layer, code) in catalogue.SCENARIO_INTENDED.items():
        d = first_scenario[cid]
        if d["first_failure_layer"] != layer or (d["reason_code"] or None) != code:
            mismatches.append((cid, layer, code, d["first_failure_layer"], d["reason_code"]))
    if mismatches:
        for m in mismatches:
            print("INTENDED/OBSERVED MISMATCH", *m, file=sys.stderr)
        return 2

    def common(c, d):
        return {"case_id": c["case_id"], "carrier_ok": b(d["predicates"]["carrier_ok"]), "binding_ok": b(d["predicates"]["binding_ok"]),
                "evidence_ok": b(d["predicates"]["evidence_ok"]), "policy_ok": b(d["predicates"]["policy_ok"]), "accepted": b(d["accepted"]),
                "first_failure_layer": d["first_failure_layer"], "reason_code": d["reason_code"] or "", "reason": d["reason"],
                "threat_id": c["threat_id"], "mitigation_id": catalogue.mitigation_for(d["reason_code"]),
                "claim_strength": c["claim_strength"], "fixture": c["fixture"], "fixture_sha256": d["fixture_sha256"], "description": c["description"]}

    fields = ["case_id", "carrier_ok", "binding_ok", "evidence_ok", "policy_ok", "accepted", "first_failure_layer", "reason_code", "reason",
              "threat_id", "mitigation_id", "claim_strength", "fixture", "fixture_sha256", "description"]
    pc = [common(cases[cid], decisions[cid]) for cid in catalogue.POLICY_CASES]
    write_csv(out / "policy-cases.csv", pc, fields)
    ef = []
    for cid in catalogue.BROKERED_FIXTURES:
        r = common(cases[cid], decisions[cid])
        r["receipt_verifies"] = r["evidence_ok"]
        r["policy_accepts"] = r["policy_ok"]
        ef.append(r)
    write_csv(out / "brokered-evidence-fixtures.csv", ef, ["case_id", "receipt_verifies", "policy_accepts"] + fields[1:])
    cm = []
    for cid, (desc, basis, threat, intended, spec) in catalogue.CARRIER_MATRIX.items():
        c = cases[cid]
        if spec is None:
            cm.append({"case_id": cid, "basis": basis, "executed": "False", "carrier_ok": "", "binding_ok": "", "evidence_ok": "", "policy_ok": "",
                       "accepted": "", "first_failure_layer": "carrier (planned)", "reason_code": "", "reason": "not executed: planned national test-instance run",
                       "threat_id": threat, "mitigation_id": "M8", "claim_strength": "planned", "fixture": "", "fixture_sha256": "", "description": desc,
                       "source_artifact": "", "source_sha256": ""})
        else:
            r = common(c, decisions[cid])
            r.update({"basis": basis, "executed": "True", "source_artifact": "carrier/local-xroad-dev/message-binding.json",
                      "source_sha256": file_sha256(root / "carrier" / "local-xroad-dev" / "message-binding.json")})
            cm.append(r)
    write_csv(out / "carrier-evidence-matrix.csv", cm, ["case_id", "basis", "executed"] + fields[1:] + ["source_artifact", "source_sha256"])
    nc = []
    for cid, (desc, strength, threat, intended, spec) in catalogue.COVERAGE_CONTROLS.items():
        r = common(cases[cid], decisions[cid])
        r["target_code"] = intended[1]
        r["deviation"] = json.dumps(spec, sort_keys=True)
        nc.append(r)
    write_csv(out / "coverage-controls.csv", nc, ["case_id", "target_code"] + fields[1:] + ["deviation"])

    # first-failure summary
    summ = []
    for fam, ids in (("policy-cases", list(catalogue.POLICY_CASES)), ("brokered-evidence-fixtures", list(catalogue.BROKERED_FIXTURES)),
                     ("carrier-evidence-matrix (executed)", [k for k, v in catalogue.CARRIER_MATRIX.items() if v[4] is not None]),
                     ("coverage-controls", list(catalogue.COVERAGE_CONTROLS))):
        cnt = Counter(decisions[i]["first_failure_layer"] for i in ids)
        summ.append({"family": fam, "packets": len(ids), "accepted": cnt.get("none", 0), "carrier": cnt.get("carrier", 0), "binding": cnt.get("binding", 0),
                     "evidence": cnt.get("evidence", 0), "policy": cnt.get("policy", 0),
                     "accepted_ids": ";".join(i for i in ids if decisions[i]["first_failure_layer"] == "none"),
                     "carrier_ids": ";".join(i for i in ids if decisions[i]["first_failure_layer"] == "carrier"),
                     "binding_ids": ";".join(i for i in ids if decisions[i]["first_failure_layer"] == "binding"),
                     "evidence_ids": ";".join(i for i in ids if decisions[i]["first_failure_layer"] == "evidence")})
    write_csv(out / "first-failure-summary.csv", summ, ["family", "packets", "accepted", "carrier", "binding", "evidence", "policy", "accepted_ids", "carrier_ids", "binding_ids", "evidence_ids"])

    # traceability
    tr = []
    for cid in list(catalogue.POLICY_CASES) + list(catalogue.BROKERED_FIXTURES) + list(catalogue.CARRIER_MATRIX) + list(catalogue.COVERAGE_CONTROLS):
        c = cases[cid]
        d = decisions.get(cid)
        code = d["reason_code"] if d else None
        mid = catalogue.mitigation_for(code) if d else "M8"
        tr.append({"threat_id": c["threat_id"], "threat": catalogue.THREATS[c["threat_id"]], "case_id": cid, "family": c["family"],
                   "fixture": c["fixture"] or "(planned)", "first_failure_layer": d["first_failure_layer"] if d else "carrier (planned)",
                   "reason_code": code or "", "mitigation_id": mid, "mitigation": catalogue.MITIGATIONS[mid][0] if mid in catalogue.MITIGATIONS else "",
                   "claim_reopened": CLAIM_OF_LAYER.get(d["first_failure_layer"], "G1") if d else "G1"})
    tr.sort(key=lambda r: (r["threat_id"], r["case_id"]))
    write_csv(out / "traceability.csv", tr, ["threat_id", "threat", "case_id", "family", "fixture", "first_failure_layer", "reason_code", "mitigation_id", "mitigation", "claim_reopened"])

    # baselines on the 24 + 12 + 15 executed packets of the three tables
    table_ids = list(catalogue.POLICY_CASES) + list(catalogue.BROKERED_FIXTURES) + [k for k, v in catalogue.CARRIER_MATRIX.items() if v[4] is not None]
    base_rows = summarise([decisions[i] for i in table_ids])
    for r in base_rows:
        r["scope"] = "P01-P24 + E01-E12 + executed C rows"
    base_rows_p = summarise([decisions[i] for i in catalogue.POLICY_CASES])
    for r in base_rows_p:
        r["scope"] = "P01-P24 only"
    write_csv(out / "baselines.csv", base_rows_p + base_rows, ["scope", "rule", "predicates", "description", "packets", "accepted", "accepted_also_by_full_chain", "accepted_but_rejected_by_full_chain", "let_through_ids"])

    # reason codes: cases that reach the code as first failure (tables, coverage controls, scenario first
    # decisions) and the number of recorded decisions whose check log shows the code failing
    all_recorded = list(decisions.values()) + list(log.decisions)
    first_by_code: dict[str, set] = {}
    for d in list(decisions.values()) + list(first_scenario.values()):
        if d["reason_code"]:
            first_by_code.setdefault(d["reason_code"], set()).add(d["case_id"])
    for d in log.decisions:
        if d["verdict"] == "hold":
            first_by_code.setdefault(d["reason_code"], set()).add(d["case_id"])
    in_log: Counter = Counter()
    for d in all_recorded:
        failed = {e["check"] for layer in d["checks"].values() for e in layer if e["result"] == "fail"}
        if d["reason_code"]:
            failed.add(d["reason_code"])
        for code in failed:
            in_log[code] += 1
    code_rows = []
    for k, v in CODES.items():
        code_rows.append({"code": k, "layer": v[0], "meaning": v[1], "cases": ";".join(sorted(first_by_code.get(k, set()))),
                          "failing_in_decisions": in_log.get(k, 0),
                          "note": catalogue.STRUCTURALLY_NOT_FIRST.get(k, "")})
    write_csv(out / "reason-codes.csv", code_rows, ["code", "layer", "meaning", "cases", "failing_in_decisions", "note"])

    # worked examples
    for cid in ("P01_direct_trusted_issuer", "P07_wrong_action_class"):
        (out / "worked-examples").mkdir(parents=True, exist_ok=True)
        (out / "worked-examples" / f"{cid}.md").write_text(worked_example_md(cases[cid], packets[cid], decisions[cid]), encoding="utf-8")

    # re-assurance outputs
    (out / "reassurance").mkdir(parents=True, exist_ok=True)
    with (out / "reassurance" / "log.jsonl").open("w", encoding="utf-8") as fh:
        for d in log.decisions:
            fh.write(json.dumps(d, sort_keys=True, ensure_ascii=False) + "\n")
    dump_json(out / "reassurance" / "records.json", log.records)
    write_csv(out / "reassurance" / "summary.csv", rsummary,
              ["event_seq", "kind", "at", "note", "reopened_claims", "claims_closed", "inputs_changed", "standing", "selected", "outcome_changed", "missed",
               "reaffirmed", "revoked", "frozen", "released", "held_after", "claims_pending_after", "detail"])
    strategies = log.strategies()
    write_csv(out / "reassurance" / "strategies.csv", strategies, ["strategy", "description", "input_changes", "re_appraisals", "revocations_caught", "revocations_missed"])
    for cid, d in first_scenario.items():
        dd = dict(d)
        dd["fixture"] = cases[cid]["fixture"]
        dd["fixture_sha256"] = file_sha256(root / cases[cid]["fixture"])
        dump_json(out / "reassurance" / "decisions" / f"{cid}.json", dd)
    dump_json(out / "reassurance" / "replay-bundle-P01.json", bundle)

    # rule-family ablation on the policy-rejected table packets (P, E, C)
    abl_rows = ablation.summarise([decisions[i] for i in table_ids])
    write_csv(out / "ablation.csv", abl_rows, ["family", "codes", "description", "policy_rejected_packets", "packets_failing_a_rule_of_the_family",
                                              "accepted_if_family_removed", "accepted_if_family_removed_ids"])

    # sensitivity: seeded random input-change sequences over every executed non-scenario packet
    sens_rows = run_sensitivity(policy, [packets[c["case_id"]] for c in index["cases"] if c["executed"] and c["family"] != "scenario"])
    write_csv(out / "reassurance" / "sensitivity.csv", sens_rows, ["seed", "events", "input_changes", "standing_total", "selected", "whole_input_selected",
                                                                 "outcome_changed", "missed", "selected_share"])

    # headline numbers
    pcnt = Counter(decisions[i]["first_failure_layer"] for i in catalogue.POLICY_CASES)
    ecnt = Counter(decisions[i]["first_failure_layer"] for i in catalogue.BROKERED_FIXTURES)
    ncnt = Counter(decisions[i]["first_failure_layer"] for i in catalogue.COVERAGE_CONTROLS)
    policy_only = [i for i in catalogue.POLICY_CASES if decisions[i]["predicates"]["carrier_ok"] and decisions[i]["predicates"]["binding_ok"]
                   and decisions[i]["predicates"]["evidence_ok"] and not decisions[i]["predicates"]["policy_ok"]]
    events = [r for r in log.records if r["kind"] != "evidence_attached"]
    attachments = [r for r in log.records if r["kind"] == "evidence_attached"]
    input_changes = [r for r in log.records if r.get("inputs_changed")]
    as_first = sorted(first_by_code)
    in_log_only = sorted(k for k in CODES if k not in first_by_code and in_log.get(k, 0) > 0)
    headline = {
        "verifier_version": __version__, "policy_id": policy["policy_id"], "policy_digest": digest(policy),
        "packets": {"total": len(packets), "tables": len(table_ids), "coverage_controls": len(catalogue.COVERAGE_CONTROLS), "scenario": len(catalogue.SCENARIO_PACKETS),
                    "planned_rows": sum(1 for v in catalogue.CARRIER_MATRIX.values() if v[4] is None)},
        "policy_cases": {"total": len(catalogue.POLICY_CASES), **{k: pcnt.get(k, 0) for k in ("none", "carrier", "binding", "evidence", "policy")}, "policy_only_ids": policy_only},
        "brokered_fixtures": {"total": len(catalogue.BROKERED_FIXTURES), **{k: ecnt.get(k, 0) for k in ("none", "carrier", "binding", "evidence", "policy")}},
        "carrier_matrix": {"rows": len(catalogue.CARRIER_MATRIX), "executed": sum(1 for v in catalogue.CARRIER_MATRIX.values() if v[4] is not None),
                           "planned": sum(1 for v in catalogue.CARRIER_MATRIX.values() if v[4] is None)},
        "coverage_controls": {"total": len(catalogue.COVERAGE_CONTROLS), **{k: ncnt.get(k, 0) for k in ("none", "carrier", "binding", "evidence", "policy")},
                              "codes": sorted(v[3][1] for v in catalogue.COVERAGE_CONTROLS.values())},
        "baselines_P": {r["rule"]: {"accepted": r["accepted"], "let_through": r["accepted_but_rejected_by_full_chain"]} for r in base_rows_p},
        "baselines_all": {r["rule"]: {"accepted": r["accepted"], "let_through": r["accepted_but_rejected_by_full_chain"]} for r in base_rows},
        "reason_codes": {"total": len(CODES), "as_first_failure": len(as_first), "in_check_log_only": in_log_only,
                         "exercised": len(as_first) + len(in_log_only), "never_failing": sorted(k for k in CODES if k not in first_by_code and in_log.get(k, 0) == 0)},
        "reason_codes_exercised": as_first,
        "reassurance": {
            "window": {"from": events[0]["at"], "to": log.records[-1]["at"]},
            "events": len(events), "attachments": len(attachments), "input_changes": len(input_changes),
            "decisions_first_run": 3, "new_actions": len(catalogue.SCENARIO_PACKETS),
            "standing_total": sum(r["standing"] for r in input_changes),
            "re_appraisals_selected": sum(r["selected"] for r in input_changes),
            "outcome_changed": sum((r.get("outcome_changed") or 0) for r in input_changes),
            "missed": sum(len(r.get("missed", [])) for r in input_changes),
            "outcomes": dict(Counter(o["outcome"] for r in log.records for o in r.get("outcomes", []))),
            "replayed": [{"case_id": o["case_id"], "outcome": o["outcome"], "replay_matches_recorded": o["replay_matches_recorded"]} for r in attachments for o in r.get("replayed", [])],
            "holds": sum(1 for d in log.decisions if d["verdict"] == "hold"),
            "released": [o for r in attachments for o in r.get("released", [])],
            "strategies": {s["strategy"]: {k: s[k] for k in ("re_appraisals", "revocations_caught", "revocations_missed")} for s in strategies},
        },
        "ablation": {r["family"]: {"accepted_if_family_removed": r["accepted_if_family_removed"], "packets_failing_a_rule_of_the_family": r["packets_failing_a_rule_of_the_family"]}
                     for r in abl_rows} | {"policy_rejected_packets": abl_rows[0]["policy_rejected_packets"]},
        "sensitivity": {
            "seeds": len(sens_rows), "events_per_seed": SENSITIVITY_EVENTS, "decisions_per_seed": len([c for c in index["cases"] if c["executed"] and c["family"] != "scenario"]),
            "standing_total": sum(r["standing_total"] for r in sens_rows), "selected": sum(r["selected"] for r in sens_rows),
            "whole_input_selected": sum(r["whole_input_selected"] for r in sens_rows),
            "outcome_changed": sum(r["outcome_changed"] for r in sens_rows), "missed": sum(r["missed"] for r in sens_rows),
            "selected_share_min": min(float(r["selected_share"]) for r in sens_rows), "selected_share_median": sorted(float(r["selected_share"]) for r in sens_rows)[len(sens_rows) // 2],
            "selected_share_max": max(float(r["selected_share"]) for r in sens_rows),
            "outcome_changed_min": min(r["outcome_changed"] for r in sens_rows), "outcome_changed_max": max(r["outcome_changed"] for r in sens_rows),
        },
        "carrier_source_sha256": file_sha256(root / "carrier" / "local-xroad-dev" / "message-binding.json"),
    }
    dump_json(out / "RUN-SUMMARY.json", headline)
    print(json.dumps(headline["policy_cases"]), json.dumps(headline["brokered_fixtures"]), json.dumps(headline["coverage_controls"]))
    print("baselines (P):", json.dumps(headline["baselines_P"]))
    print("reason codes:", json.dumps(headline["reason_codes"]))
    print("ablation:", json.dumps(headline["ablation"]))
    print("sensitivity:", json.dumps(headline["sensitivity"]))
    print("re-assurance:", json.dumps(headline["reassurance"]["strategies"]), "outcomes", headline["reassurance"]["outcomes"], "holds", headline["reassurance"]["holds"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
