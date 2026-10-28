#!/usr/bin/env python3
"""Generate the policy file and every fixture packet, deterministically.

    python3 verifier/gen_fixtures.py [--root <artifact dir>]

Writes policy/relying-party-policy.json, fixtures/<family>/<case>.json,
fixtures/index.json and carrier/local-xroad-dev/carrier-record.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ecr import catalogue  # noqa: E402
from ecr.canon import canonical_bytes  # noqa: E402


def dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # pretty but deterministic; canonical_bytes() is what signatures cover
    canonical_bytes(obj)  # refuse anything outside the canonical subset
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    a = ap.parse_args()
    root = Path(a.root)
    binding = root / "carrier" / "local-xroad-dev" / "message-binding.json"
    base = catalogue.carrier_record(binding)
    dump(root / "carrier" / "local-xroad-dev" / "carrier-record.json", base)
    policy = catalogue.build_policy()
    dump(root / "policy" / "relying-party-policy.json", policy)
    index = []
    for family, cases in catalogue.FAMILIES.items():
        for case_id, (desc, strength, threat, intended, spec) in cases.items():
            if family == "scenario":
                # scenario packets are appraised under the policy in force at their presentation time in the scenario
                intended = catalogue.SCENARIO_INTENDED[case_id]
            entry = {"case_id": case_id, "family": family, "description": desc, "claim_strength": strength,
                     "threat_id": threat, "intended_layer": intended[0], "intended_code": intended[1],
                     "executed": spec is not None, "fixture": None}
            if family == "carrier-evidence-matrix":
                entry["basis"] = strength
                entry["claim_strength"] = "observed" if strength == "observed-local-dev-stack" else ("derived" if strength.startswith("derived") else ("planned" if strength.startswith("future") else "synthetic-negative-control"))
            if spec is not None:
                pkt = catalogue.build_packet(case_id, spec, base)
                rel = Path("fixtures") / family / f"{case_id}.json"
                dump(root / rel, pkt)
                entry["fixture"] = rel.as_posix()
                entry["deviations_from_P01"] = {k: ([list(t) for t in v] if k in ("tamper", "endorsement_tamper") else v) for k, v in spec.items()}
            index.append(entry)
    dump(root / "fixtures" / "index.json", {"profile": "ecr-fixture-index/0.3", "cases": index,
                                            "threats": catalogue.THREATS,
                                            "mitigations": {k: v[0] for k, v in catalogue.MITIGATIONS.items()}})
    print(f"wrote {sum(1 for e in index if e['executed'])} packets, {len(index)} index rows, policy {policy['policy_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
