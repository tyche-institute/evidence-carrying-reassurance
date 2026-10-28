"""Weaker acceptance rules, counted on the same packets.

The baselines are not competing systems; they are the acceptance rules a
relying party uses when it stops at the carrier log, at receipt
verification, or at carrier + verification without binding and policy. The
comparison measures how many of the constructed failures each rule lets
through. It says nothing about field frequency.
"""

from __future__ import annotations

BASELINES = {
    "A0_carrier_log_only": ("carrier_ok",),
    "A1_receipt_verification_only": ("evidence_ok",),
    "A2_carrier_and_verification": ("carrier_ok", "evidence_ok"),
    "A3_carrier_binding_verification": ("carrier_ok", "binding_ok", "evidence_ok"),
    "A4_four_predicate_chain": ("carrier_ok", "binding_ok", "evidence_ok", "policy_ok"),
}

DESCRIPTIONS = {
    "A0_carrier_log_only": "accept if the carrier witnessed the exchange",
    "A1_receipt_verification_only": "accept if the receipt verifies under its profile",
    "A2_carrier_and_verification": "accept if the carrier witnessed and the receipt verifies (no binding, no policy)",
    "A3_carrier_binding_verification": "accept if witnessed, bound and verified (no policy)",
    "A4_four_predicate_chain": "the article's rule: witnessed, bound, verified and policy-accepted",
}


def baseline_accepts(decision: dict, rule: str) -> bool:
    return all(decision["predicates"][p] for p in BASELINES[rule])


def summarise(decisions: list[dict]) -> list[dict]:
    rows = []
    for rule, preds in BASELINES.items():
        acc = [d for d in decisions if baseline_accepts(d, rule)]
        wrong = [d for d in acc if not d["accepted"]]
        rows.append({
            "rule": rule,
            "predicates": "+".join(preds),
            "description": DESCRIPTIONS[rule],
            "packets": len(decisions),
            "accepted": len(acc),
            "accepted_also_by_full_chain": len(acc) - len(wrong),
            "accepted_but_rejected_by_full_chain": len(wrong),
            "let_through_ids": ";".join(sorted(d["case_id"] for d in wrong)),
        })
    return rows
