"""Rule-family ablation on the policy-rejected packets.

For every packet that is witnessed, bound and verified but rejected by
policy, the check log records every policy rule that fails, not only the
first. Removing one rule family at a time and asking whether the packet
would then be accepted shows which rejections rest on a single family and
which are caught by more than one. The families follow the order of the
policy checks. The count is over the constructed set, not a deployment.
"""

from __future__ import annotations

FAMILIES = {
    "F1_verifier_profile": ("R01", "R02"),
    "F2_roots_and_brokers": ("R03", "R04", "R05", "R06", "R07", "R08"),
    "F3_status_and_delegation": ("R09", "R10", "R11", "R12", "R13", "R14"),
    "F4_scope_and_co_approval": ("R15", "R16"),
    "F5_time": ("R17", "R18", "R19", "R20"),
    "F6_runtime_profile": ("R21",),
}

DESCRIPTIONS = {
    "F1_verifier_profile": "verifier profile named and matching",
    "F2_roots_and_brokers": "accepted roots per action class, root conflicts, broker registration and alias injectivity",
    "F3_status_and_delegation": "status source, status age, revocation, suspension, validity interval",
    "F4_scope_and_co_approval": "action class inside the delegation's scope; co-approval where the class requires it",
    "F5_time": "timestamp root, clock skew, binding age, freshness window",
    "F6_runtime_profile": "model version, tool profile and prompt profile in the allowed set",
}


def failing_policy_codes(decision: dict) -> set[str]:
    return {c["check"] for c in decision["checks"].get("policy", []) if c["result"] == "fail" and not c["check"].startswith("R00")}


def policy_rejected(decision: dict) -> bool:
    p = decision["predicates"]
    return p["carrier_ok"] and p["binding_ok"] and p["evidence_ok"] and not p["policy_ok"]


def summarise(decisions: list[dict]) -> list[dict]:
    rejected = [d for d in decisions if policy_rejected(d)]
    rows = []
    for fam, prefixes in FAMILIES.items():
        inside = lambda code: code[:3] in prefixes  # noqa: E731
        accepted_without = [d for d in rejected if all(inside(c) for c in failing_policy_codes(d))]
        touched = [d for d in rejected if any(inside(c) for c in failing_policy_codes(d))]
        rows.append({
            "family": fam,
            "codes": "+".join(prefixes),
            "description": DESCRIPTIONS[fam],
            "policy_rejected_packets": len(rejected),
            "packets_failing_a_rule_of_the_family": len(touched),
            "accepted_if_family_removed": len(accepted_without),
            "accepted_if_family_removed_ids": ";".join(sorted(d["case_id"] for d in accepted_without)),
        })
    multi = sorted(d["case_id"] for d in rejected if len({c[:3] for c in failing_policy_codes(d)} & {p for ps in FAMILIES.values() for p in ps}) > 1
                   and len({fam for fam, ps in FAMILIES.items() if any(c[:3] in ps for c in failing_policy_codes(d))}) > 1)
    rows.append({
        "family": "any_single_family",
        "codes": "",
        "description": "rejections that rest on one family only (removing it accepts the packet)",
        "policy_rejected_packets": len(rejected),
        "packets_failing_a_rule_of_the_family": len(rejected),
        "accepted_if_family_removed": sum(r["accepted_if_family_removed"] for r in rows),
        "accepted_if_family_removed_ids": "caught by two families: " + (";".join(multi) if multi else "none"),
    })
    return rows
