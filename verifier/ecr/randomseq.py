"""Seeded random input-change sequences over the relying party's inputs.

Shared by the soundness tests and by the sensitivity run of
`run_matrix.py`: one input change drawn from every table the checks read
(accepted roots, one delegation's status entry, the runtime allow-list, the
carrier configuration, thresholds, action-class rules, approvers, broker
registration, timestamp roots, status-source pin and verifier profile), the
status list re-issued 30 minutes before each event.
"""

from __future__ import annotations

import copy
import json
import random
from datetime import datetime, timedelta

from . import catalogue
from .keys import key_id_for
from .objects import status_list

MOCK1 = "DEV/COM/1234/TestService/mock1"
MOCK2 = "DEV/COM/1234/TestService/mock2"
CLIENT = "DEV/COM/4321/TestClient"


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def fresh(registry: dict, at: datetime) -> dict:
    """The registry's list as fetched 30 minutes before the event."""
    return status_list("status-municipal", catalogue.STATUS_SOURCES["status-municipal"], iso(at - timedelta(minutes=30)),
                       json.loads(json.dumps(registry)))


def random_change(rng: random.Random, policy: dict, registry: dict, at: datetime) -> tuple[str, dict]:
    """One input change drawn from every table the checks read."""
    p = copy.deepcopy(policy)
    kind = "trust_list_changed"
    k = rng.randrange(10)
    if k == 0:                                   # accepted roots: admit, withdraw or re-scope
        root = rng.choice(["root:municipal-agent-ca", "root:partner-ca", "root:vendor-demo-ca"])
        label = {"root:municipal-agent-ca": "root-municipal-agent-ca", "root:partner-ca": "root-partner-ca", "root:vendor-demo-ca": "root-vendor-demo-ca"}[root]
        if root in p["accepted_roots"] and rng.random() < 0.4:
            del p["accepted_roots"][root]
        else:
            p["accepted_roots"][root] = {"key_id": key_id_for(label), "accepted_for": rng.sample(["read", "enrich", "mutate"], rng.randrange(1, 4))}
    elif k == 1:                                 # status entry of one delegation
        kind = "status_changed"
        d = rng.choice(sorted(registry))
        st = rng.choice(["active", "revoked", "suspended"])
        registry[d] = {"status": st} if st == "active" else {"status": st, "since": iso(at - timedelta(hours=1))}
    elif k == 2:                                 # runtime allow-list
        kind = "runtime_profile_changed"
        mv = p["allowed_runtime_profiles"]["model_versions"]
        v = rng.choice([catalogue.MODEL_VERSION, catalogue.MODEL_VERSION_NEXT])
        if v in mv:
            mv.remove(v)
        else:
            mv.append(v)
    elif k == 3:                                 # carrier configuration
        kind = "carrier_config_changed"
        c = p["carrier"]
        what = rng.randrange(3)
        if what == 0:
            c["accepted_services"] = [MOCK2] if c["accepted_services"] == [MOCK1] else [MOCK1] if MOCK2 in c["accepted_services"] and rng.random() < 0.5 else [MOCK1, MOCK2]
        elif what == 1:
            c["accepted_clients"] = [CLIENT, "DEV/COM/4321/OtherClient"] if c["accepted_clients"] == [CLIENT] else [CLIENT]
        else:
            c["require_message_log"] = not c["require_message_log"]
    elif k == 4:                                 # thresholds
        p["status_max_age_s"] = rng.choice([3600, 7200, 86400])
        p["clock_skew_tolerance_s"] = rng.choice([5, 30, 300])
        p["carrier_binding_max_age_s"] = rng.choice([60, 600, 3600])
        p["freshness_window_s"] = rng.choice([60, 900, 86400])
    elif k == 5:                                 # action-class rules
        kind = "action_class_escalation"
        ac = rng.choice(["read", "enrich", "mutate"])
        p["action_classes"][ac] = {"co_approval": rng.random() < 0.5, "high_risk": rng.random() < 0.5}
    elif k == 6:                                 # approvers
        if "approver:soc-deputy" in p["approvers"]:
            del p["approvers"]["approver:soc-deputy"]
        else:
            p["approvers"]["approver:soc-deputy"] = {"key_id": key_id_for("approver-soc-deputy")}
        if rng.random() < 0.3:
            p["approvers"].pop("approver:soc-lead", None)
        else:
            p["approvers"]["approver:soc-lead"] = {"key_id": key_id_for("approver-soc-lead")}
    elif k == 7:                                 # broker registration
        reg = p["accepted_brokers"].get("broker:municipal-evidence-broker")
        if reg and rng.random() < 0.3:
            del p["accepted_brokers"]["broker:municipal-evidence-broker"]
        else:
            p["accepted_brokers"]["broker:municipal-evidence-broker"] = {"key_id": key_id_for("broker-municipal"),
                                                                        "mapping_ids": rng.choice([["map-2026-05"], ["map-2026-01"], ["map-2026-05", "map-2026-06"]])}
    elif k == 8:                                 # timestamp roots
        tr = p["accepted_timestamp_roots"]
        if "root:vendor-tsa-root" in tr and rng.random() < 0.5:
            del tr["root:vendor-tsa-root"]
        else:
            tr["root:vendor-tsa-root"] = {"key_id": key_id_for("root-vendor-tsa"), "accepted_for": ["read", "enrich"]}
        tr["root:municipal-tsa-root"]["accepted_for"] = rng.sample(["read", "enrich", "mutate"], rng.randrange(1, 4))
    else:                                        # status source pin, verifier profile
        if rng.random() < 0.2:
            p["status_sources"]["status:municipal-delegation-registry"] = {"key_id": key_id_for("status-municipal-rotated")}
        else:
            p["status_sources"]["status:municipal-delegation-registry"] = {"key_id": key_id_for("status-municipal")}
        p["require_verifier_profile"] = rng.choice(["ecr-verifier/0.2", "ecr-verifier/0.2", "ecr-verifier/0.2", "ecr-verifier/0.1"])
    return kind, {"policy": p, "status_list": fresh(registry, at)}
