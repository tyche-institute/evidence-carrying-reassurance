"""The case catalogue: identities, the relying-party policy, and every
policy case (P01–P24), brokered-evidence fixture (E01–E12) and
carrier/evidence matrix row (C01–C18), the coverage controls (N01–N12, one
per reason code the three tables do not reach), plus the packets used by the
re-assurance scenario (S01–S05).

Each case is a small dict of deviations from a baseline accepted packet;
`build_packet` turns it into a complete packet. The deviations are the
whole definition of a case, so a reader can see in one place what makes
P07 differ from P01.
"""

from __future__ import annotations

import copy
import json
import uuid
from pathlib import Path

from . import PROFILE_VERIFIER
from .canon import digest, file_sha256
from .keys import key_id_for
from .objects import NAMESPACE, broker_envelope, co_approval, endorsement, receipt, status_list, timestamp_token

# --------------------------------------------------------------------------- identities (label -> id)

ROOTS = {
    "root-municipal-agent-ca": "root:municipal-agent-ca",
    "root-partner-ca": "root:partner-ca",
    "root-vendor-demo-ca": "root:vendor-demo-ca",
    "root-municipal-tsa": "root:municipal-tsa-root",
    "root-vendor-tsa": "root:vendor-tsa-root",
}
ISSUERS = {   # label -> (id, root label or None)
    "issuer-soc": ("issuer:soc-agent-platform", "root-municipal-agent-ca"),
    "issuer-partner": ("issuer:partner-agent-platform", "root-partner-ca"),
    "issuer-vendor": ("issuer:vendor-agent-platform", "root-vendor-demo-ca"),
    "issuer-unanchored": ("issuer:unanchored-agent-platform", None),
}
TSAS = {"tsa-municipal": ("tsa:municipal-tsa", "root-municipal-tsa"), "tsa-vendor": ("tsa:vendor-tsa", "root-vendor-tsa")}
STATUS_SOURCES = {"status-municipal": "status:municipal-delegation-registry", "status-vendor": "status:vendor-registry"}
BROKERS = {"broker-municipal": "broker:municipal-evidence-broker"}
APPROVERS = {"approver-soc-lead": "approver:soc-lead"}

AGENT = {"agent_id": "urn:agent:municipal-soc:ir-enrichment", "runtime_instance": "ir-enrichment-01"}
TOOL_PROFILE = {"tools": ["asset-register.lookup", "case-file.append"], "profile_id": "ir-tools/2026.05"}
PROMPT_PROFILE = {"system_prompt_id": "ir-enrich-v3", "guardrails": ["no-mutation-without-approval"], "profile_id": "ir-prompt/2026.05"}
MODEL_VERSION = "ir-enrichment-model/2026.05"
MODEL_VERSION_NEXT = "ir-enrichment-model/2026.07"

DELEGATIONS = {
    "del-001": {"grantor": "analyst:mara", "scope": ["read", "enrich"], "valid_from": "2026-05-01T00:00:00Z", "valid_until": "2026-06-30T23:59:59Z"},
    "del-002": {"grantor": "analyst:mara", "scope": ["read", "enrich"], "valid_from": "2026-05-01T00:00:00Z", "valid_until": "2026-06-30T23:59:59Z"},
    "del-003": {"grantor": "analyst:mara", "scope": ["read", "enrich"], "valid_from": "2026-05-01T00:00:00Z", "valid_until": "2026-06-30T23:59:59Z"},
    "del-004": {"grantor": "analyst:mara", "scope": ["read", "enrich"], "valid_from": "2026-05-01T00:00:00Z", "valid_until": "2026-06-30T23:59:59Z"},
    "del-005": {"grantor": "analyst:mara", "scope": ["read", "enrich"], "valid_from": "2026-04-01T00:00:00Z", "valid_until": "2026-05-27T10:00:00Z"},
    "del-006": {"grantor": "soc-lead:priit", "scope": ["read", "enrich", "mutate"], "valid_from": "2026-05-01T00:00:00Z", "valid_until": "2026-06-30T23:59:59Z"},
}
STATUS_ENTRIES = {
    "del-001": {"status": "active"},
    "del-002": {"status": "active"},
    "del-003": {"status": "revoked", "since": "2026-05-20T09:00:00Z"},
    "del-004": {"status": "suspended", "since": "2026-05-26T16:00:00Z"},
    "del-005": {"status": "active"},
    "del-006": {"status": "active"},
}

ACTIONS = {
    "read": {"class": "read", "target": "asset-register:host/citizen-services-07", "tool": "asset-register.lookup", "summary": "look up asset context for the affected host"},
    "enrich": {"class": "enrich", "target": "case-file:INC-2026-0427", "tool": "case-file.append", "summary": "append a structured asset-context enrichment note to the case file"},
    "mutate": {"class": "mutate", "target": "case-file:INC-2026-0427", "tool": "case-file.update", "summary": "change the case severity and close the ticket"},
}

STANDARD_MAPPING = [
    {"issuer": "issuer:soc-agent-platform", "root": "root:municipal-agent-ca", "alias": "alias:soc"},
    {"issuer": "issuer:partner-agent-platform", "root": "root:partner-ca", "alias": "alias:partner"},
    {"issuer": "issuer:vendor-agent-platform", "root": "root:vendor-demo-ca", "alias": "alias:vendor"},
    {"issuer": "issuer:unanchored-agent-platform", "root": None, "alias": "alias:unanchored"},
]
ALIAS_CLASH_MAPPING = [
    {"issuer": "issuer:soc-agent-platform", "root": "root:municipal-agent-ca", "alias": "alias:soc"},
    {"issuer": "issuer:partner-agent-platform", "root": "root:partner-ca", "alias": "alias:soc"},
]

# clocks
CARRIER_OBSERVED = "2026-05-27T11:14:19Z"
ISSUED = "2026-05-27T11:14:21Z"
TSA_TIME = "2026-05-27T11:14:22Z"
PRESENTED = "2026-05-27T11:16:19Z"
STATUS_ISSUED = "2026-05-27T11:00:00Z"

# --------------------------------------------------------------------------- policy

def build_policy() -> dict:
    return {
        "policy_id": "rp-policy:municipal-soc/0.2",
        "description": "Relying-party policy of the municipal security operations centre for agentic incident enrichment.",
        "carrier": {
            "carrier": "x-road",
            "instance": "DEV",
            "accepted_clients": ["DEV/COM/4321/TestClient"],
            "accepted_services": ["DEV/COM/1234/TestService/mock1"],
            "require_message_log": True,
        },
        "accepted_roots": {
            "root:municipal-agent-ca": {"key_id": key_id_for("root-municipal-agent-ca"), "accepted_for": ["read", "enrich", "mutate"]},
            "root:partner-ca": {"key_id": key_id_for("root-partner-ca"), "accepted_for": ["read", "enrich"]},
        },
        "accepted_timestamp_roots": {
            "root:municipal-tsa-root": {"key_id": key_id_for("root-municipal-tsa"), "accepted_for": ["read", "enrich", "mutate"]},
        },
        "status_sources": {
            "status:municipal-delegation-registry": {"key_id": key_id_for("status-municipal")},
        },
        "accepted_brokers": {
            "broker:municipal-evidence-broker": {"key_id": key_id_for("broker-municipal"), "mapping_ids": ["map-2026-05"]},
        },
        "approvers": {
            "approver:soc-lead": {"key_id": key_id_for("approver-soc-lead")},
        },
        "require_verifier_profile": PROFILE_VERIFIER,
        "status_max_age_s": 3600,
        "clock_skew_tolerance_s": 30,
        "carrier_binding_max_age_s": 600,
        "freshness_window_s": 900,
        "action_classes": {
            "read": {"co_approval": False, "high_risk": False},
            "enrich": {"co_approval": False, "high_risk": False},
            "mutate": {"co_approval": True, "high_risk": True},
        },
        "allowed_runtime_profiles": {
            "model_versions": [MODEL_VERSION],
            "tool_profile_digests": [digest(TOOL_PROFILE)],
            "prompt_profile_digests": [digest(PROMPT_PROFILE)],
        },
    }


# --------------------------------------------------------------------------- carrier record

def carrier_record(binding_path: Path) -> dict:
    mb = json.loads(binding_path.read_text())
    return {
        "carrier": "x-road",
        "instance": "DEV",
        "client": mb["request"]["x_road_client"],
        "service": mb["participants"]["service"],
        "message_id": mb["response"]["x_road_id"],
        "request_id": mb["response"]["x_road_request_id"],
        "request_hash": mb["response"]["x_road_request_hash"],
        "request_payload_sha256": mb["request"]["request_payload_sha256"],
        "response_body_sha256": mb["response"]["response_body_sha256"],
        "response_headers_sha256": mb["response"]["response_headers_sha256"],
        "http_status": mb["response"]["http_status"],
        "observed_at": CARRIER_OBSERVED,
        "status": "accepted",
        "fault": None,
        "message_log": {
            "provider_security_server": mb["participants"]["provider_security_server"],
            "provider_rows": [9, 10],
            "consumer_security_server": mb["participants"]["consumer_security_server"],
            "consumer_rows": [4, 5],
            "ss0_logrecord_csv_sha256": mb["message_log_evidence"]["ss0_logrecord_csv_sha256"],
            "ss1_logrecord_csv_sha256": mb["message_log_evidence"]["ss1_logrecord_csv_sha256"],
        },
        "source": {
            "artifact": "carrier/local-xroad-dev/message-binding.json",
            "sha256": file_sha256(binding_path),
            "basis": "observed-local-dev-stack",
            "run_date": mb["run_date"],
            "xroad_commit": mb["xroad_source"]["commit"],
        },
    }


# --------------------------------------------------------------------------- packet builder

DEFAULTS = {
    "issuer": "issuer-soc",
    "endorsing_roots": None,          # None -> the issuer's own root, status active
    "delegation": "del-001",
    "action": "enrich",
    "tsa": "tsa-municipal",
    "issued_at": ISSUED,
    "tsa_time": TSA_TIME,
    "presented_at": PRESENTED,
    "status": "fresh",                # fresh | stale | vendor | None
    "status_issued_at": STATUS_ISSUED,
    "carrier": "real",                # real | shifted | rejected | validation_unavailable | timestamp_unavailable | None
    "carrier_observed_at": None,      # with "shifted": a time-shifted copy of the observed exchange (scenario only)
    "evidence": "receipt",            # receipt | None
    "subject": True,
    "verifier_profile": PROFILE_VERIFIER,
    "model_version": MODEL_VERSION,
    "receipt_carrier_overrides": {},
    "brokered": False,
    "mapping": None,
    "normalized_overrides": {},
    "broker_digest_of_other": False,
    "co_approval": False,
    "mapping_id": "map-2026-05",      # the broker's mapping id (R07 when not registered)
    "carrier_overrides": {},          # fields of the carrier record (K03/K04 controls)
    "endorsement_tamper": [],         # (dotted path, value) applied to the issuer's endorsements BEFORE the receipt is signed
    "tamper": [],                     # (dotted path, value) applied to the finished packet (post-signature tamper controls)
}


def set_path(obj, path: str, value) -> None:
    """Set `value` at a dotted path; a numeric segment indexes a list."""
    parts = path.split(".")
    cur = obj
    for seg in parts[:-1]:
        cur = cur[int(seg)] if isinstance(cur, list) else cur[seg]
    last = parts[-1]
    if isinstance(cur, list):
        cur[int(last)] = value
    else:
        cur[last] = value


def build_packet(case_id: str, spec: dict, base_carrier: dict) -> dict:
    s = {**DEFAULTS, **spec}
    # carrier
    if s["carrier"] is None:
        rec = None
    else:
        rec = copy.deepcopy(base_carrier)
        if s["carrier"] == "shifted":
            ts = s["carrier_observed_at"]
            rec["observed_at"] = ts
            rec["message_id"] = "tyche-sim-run-" + ts.replace("-", "").replace(":", "")
            rec["request_id"] = str(uuid.uuid5(NAMESPACE, "carrier-request:" + case_id))
            rec["message_log"]["note"] = "time-shifted copy of the observed exchange; row numbers and digests refer to the 2026-05-27 run"
            rec["source"]["basis"] = "derived-from-observed-artifact (time-shifted copy for the re-assurance scenario)"
        elif s["carrier"] == "rejected":
            rec.update({"status": "rejected", "fault": "access-denied: client subsystem has no access right to the service",
                        "http_status": 403, "message_log": None, "response_body_sha256": None, "response_headers_sha256": None})
            rec["source"]["basis"] = "synthetic-negative-control"
        elif s["carrier"] == "validation_unavailable":
            rec.update({"status": "validation_unavailable", "fault": "certificate-status-unavailable: OCSP response missing or expired",
                        "http_status": 500, "message_log": None, "response_body_sha256": None, "response_headers_sha256": None})
            rec["source"]["basis"] = "synthetic-negative-control"
        elif s["carrier"] == "timestamp_unavailable":
            rec.update({"status": "timestamp_unavailable", "fault": "timestamping-unavailable: message log could not obtain a timestamp",
                        "http_status": 500, "message_log": None})
            rec["source"]["basis"] = "synthetic-negative-control"
        if s["carrier_overrides"]:
            for k, v in s["carrier_overrides"].items():
                set_path(rec, k, v)
            rec["source"]["basis"] = "synthetic-negative-control"
    # receipt
    issuer_label = s["issuer"]
    issuer_id, root_label = ISSUERS[issuer_label]
    root_id = ROOTS[root_label] if root_label else None
    ends = []
    roots = s["endorsing_roots"] if s["endorsing_roots"] is not None else ([(root_label, "active")] if root_label else [])
    for rl, st in roots:
        ends.append(endorsement(rl, ROOTS[rl], issuer_label, issuer_id, st, "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"))
    for path, value in s["endorsement_tamper"]:
        set_path(ends, path, value)
    deleg = {"id": s["delegation"], "grantee": AGENT["agent_id"], "status_source": STATUS_SOURCES["status-municipal"], **DELEGATIONS[s["delegation"]]}
    bc = rec if rec is not None else base_carrier
    rc = {"carrier": "x-road", "message_id": bc["message_id"], "request_id": bc["request_id"],
          "request_digest": bc["request_payload_sha256"], "response_digest": bc["response_body_sha256"]}
    rc.update(s["receipt_carrier_overrides"])
    runtime = {"model_version": s["model_version"], "tool_profile_digest": digest(TOOL_PROFILE), "prompt_profile_digest": digest(PROMPT_PROFILE)}
    if s["verifier_profile"] is not None:
        runtime["verifier_profile"] = s["verifier_profile"]
    rcpt = None
    if s["evidence"] == "receipt":
        rcpt = receipt(case_name=case_id, issuer_label=issuer_label, issuer_id=issuer_id, root_id=root_id, endorsements=ends,
                       subject=AGENT if s["subject"] else None, delegation=deleg, carrier=rc, action=ACTIONS[s["action"]],
                       runtime=runtime, issued_at=s["issued_at"])
    evidence = rcpt
    if rcpt is not None and s["brokered"]:
        norm = {"issuer_alias": next((m["alias"] for m in (s["mapping"] or STANDARD_MAPPING) if m["issuer"] == issuer_id), "alias:unknown"),
                "root": root_id if root_id else "root:municipal-agent-ca",   # a broker-asserted root for an unanchored issuer
                "carrier_message_id": rc["message_id"], "request_digest": rc["request_digest"], "response_digest": rc["response_digest"]}
        norm.update(s["normalized_overrides"])
        other = None
        if s["broker_digest_of_other"]:
            other = receipt(case_name=case_id + ":other", issuer_label=issuer_label, issuer_id=issuer_id, root_id=root_id, endorsements=ends,
                            subject=AGENT, delegation=deleg, carrier=rc, action=ACTIONS["read"], runtime=runtime, issued_at=s["issued_at"])
        evidence = broker_envelope("broker-municipal", BROKERS["broker-municipal"], s["mapping_id"], s["mapping"] or STANDARD_MAPPING,
                                   norm, rcpt, signed_digest_of=other)
    # timestamp token over the receipt payload
    ts = None
    if rcpt is not None:
        tsa_id, tsa_root_label = TSAS[s["tsa"]]
        ts = timestamp_token(rcpt["payload"], s["tsa"], tsa_id, tsa_root_label, ROOTS[tsa_root_label], s["tsa_time"])
    # status list
    sl = None
    if s["status"] == "fresh" or s["status"] == "stale":
        sl = status_list("status-municipal", STATUS_SOURCES["status-municipal"], s["status_issued_at"], STATUS_ENTRIES)
    elif s["status"] == "vendor":
        sl = status_list("status-vendor", STATUS_SOURCES["status-vendor"], s["status_issued_at"], STATUS_ENTRIES)
    ca = None
    if rcpt is not None and s["co_approval"]:
        ca = co_approval(rcpt["payload"], "approver-soc-lead", APPROVERS["approver-soc-lead"], s["issued_at"])
    pkt = {
        "profile": "ecr-packet/0.2",
        "case_id": case_id,
        "presented_at": s["presented_at"],
        "carrier_record": rec,
        "evidence": evidence,
        "timestamp_token": ts,
        "status_list": sl,
        "co_approval": ca,
    }
    for path, value in s["tamper"]:
        set_path(pkt, path, value)
    return pkt


# --------------------------------------------------------------------------- threats and mitigations

THREATS = {
    "T0": "none: positive control (all four predicates hold)",
    "T1": "tamper with or replay evidence (broker metadata, payload digests, old carrier bindings)",
    "T2": "present untrusted or aliased roots (valid signature under an unaccepted root; alias across roots)",
    "T3": "exploit broker opacity (broker-only attestation; normalisation that alters bound fields)",
    "T4": "supply stale authority (expired, revoked or suspended delegation; stale or wrong status source)",
    "T5": "escalate the action class (evidence scoped to read or enrich presented for a mutating action; missing co-approval)",
    "T6": "carrier failure or unavailability (rejected exchange, status-check or timestamp outage, no record)",
    "T7": "profile and clock drift (wrong or missing verifier profile; issuer/TSA clock disagreement)",
    "T8": "runtime-profile drift (model, tool or prompt changed outside the relying party's control; a high-risk action presented while a reopened claim is pending)",
}
MITIGATIONS = {
    "M1": ("binding check", ("B03", "B04", "B05", "B06", "B02")),
    "M2": ("profile verification: mandatory fields, signatures, digests", ("V03", "V04", "V05", "V06", "V07", "V08", "V09", "V10", "V01", "V02")),
    "M3": ("accepted-root policy, fail-closed on conflict", ("R03", "R04", "R05", "R06")),
    "M4": ("broker registration and injective alias mapping", ("R07", "R08")),
    "M5": ("named status source with maximum age", ("R09", "R10", "R11", "R12", "R13")),
    "M6": ("delegation validity, action scope, co-approval", ("R14", "R15", "R16")),
    "M7": ("timestamp root, clock skew, binding age, freshness window", ("R17", "R18", "R19", "R20")),
    "M8": ("carrier acceptance, fail closed", ("K01", "K02", "K03", "K04", "K05", "B01")),
    "M9": ("verifier-profile pin and runtime-profile allow-list", ("R01", "R02", "R21")),
    "M10": ("hold on high-risk actions while a reopened claim is pending", ("H01",)),
}


def mitigation_for(code: str | None) -> str:
    if code is None:
        return "—"
    for mid, (_, prefixes) in MITIGATIONS.items():
        if code[:3] in prefixes:
            return mid
    return "—"


# --------------------------------------------------------------------------- the cases

# fields: description, claim_strength, threat, intended (layer, code), spec
POLICY_CASES = {
    "P01_direct_trusted_issuer": ("Direct issuer under an accepted root; append-only enrichment within delegated scope.", "simulation", "T0", ("none", None), {}),
    "P02_brokered_trusted_issuer": ("Broker normalises a trusted issuer without becoming the root of truth.", "simulation", "T0", ("none", None), {"brokered": True, "delegation": "del-002"}),
    "P03_valid_signature_untrusted_issuer": ("Signature verifies; issuer root is outside relying-party policy.", "synthetic-negative-control", "T2", ("policy", "R04_ROOT_NOT_ACCEPTED"), {"issuer": "issuer-vendor"}),
    "P04_stale_delegation": ("Delegation expired before the carrier event time.", "synthetic-negative-control", "T4", ("policy", "R14_DELEGATION_NOT_VALID_AT_EVENT"), {"delegation": "del-005"}),
    "P05_revoked_delegation": ("Status source marks the delegation revoked.", "synthetic-negative-control", "T4", ("policy", "R12_DELEGATION_REVOKED"), {"delegation": "del-003"}),
    "P06_suspended_delegation": ("Status source marks the delegation suspended.", "synthetic-negative-control", "T4", ("policy", "R13_DELEGATION_SUSPENDED"), {"delegation": "del-004"}),
    "P07_wrong_action_class": ("Receipt scoped to read and enrich; the action mutates the case file, with a listed co-approver present, so the scope rule is the only failing rule.", "synthetic-negative-control", "T5", ("policy", "R15_ACTION_OUTSIDE_SCOPE"), {"action": "mutate", "co_approval": True}),
    "P08_broker_metadata_tamper": ("Broker's signed digest no longer matches the attached receipt.", "synthetic-negative-control", "T1", ("evidence", "V07_BROKER_DIGEST_MISMATCH"), {"brokered": True, "delegation": "del-002", "broker_digest_of_other": True}),
    "P09_conflicting_roots": ("Two accepted roots assert incompatible issuer status; policy fails closed.", "simulation", "T2", ("policy", "R06_ROOT_CONFLICT"), {"endorsing_roots": [("root-municipal-agent-ca", "active"), ("root-partner-ca", "revoked")]}),
    "P10_stale_status_source": ("Status list older than the relying party's maximum status age.", "simulation", "T4", ("policy", "R11_STATUS_STALE"), {"status": "stale", "status_issued_at": "2026-05-27T08:00:00Z"}),
    "P11_carrier_request_id_mismatch": ("Receipt names a different X-Road message id than the carrier record.", "synthetic-negative-control", "T1", ("binding", "B03_MESSAGE_ID_MISMATCH"), {"receipt_carrier_overrides": {"message_id": "tyche-real-run-20260527T093000Z", "request_id": "0d2f6c1e-5b1a-4c3e-9a7f-2e8d4b6c1a90"}}),
    "P12_response_payload_hash_mismatch": ("Response digest in the receipt differs from the carrier's response body digest.", "synthetic-negative-control", "T1", ("binding", "B05_RESPONSE_DIGEST_MISMATCH"), {"receipt_carrier_overrides": {"response_digest": "6f0c3a9e5d2b7c1f4e8a0b3d6c9f2e5a8b1d4c7f0a3e6b9d2c5f8a1b4e7d0c3f"}}),
    "P13_replay_outside_window": ("Receipt binds to a carrier event older than the binding age limit (replayed carrier event).", "synthetic-negative-control", "T1", ("policy", "R19_BINDING_AGE_EXCEEDED"), {"issued_at": "2026-05-27T12:30:00Z", "tsa_time": "2026-05-27T12:30:01Z", "presented_at": "2026-05-27T12:31:00Z", "status_issued_at": "2026-05-27T12:00:00Z"}),
    "P14_clock_skew_inside_window": ("Issuer and timestamp-authority clocks differ by 20 s, inside the 30 s tolerance.", "simulation", "T0", ("none", None), {"tsa_time": "2026-05-27T11:14:41Z"}),
    "P15_clock_skew_outside_window": ("Issuer and timestamp-authority clocks differ by 120 s, outside the 30 s tolerance.", "simulation", "T7", ("policy", "R18_CLOCK_SKEW_EXCEEDED"), {"tsa_time": "2026-05-27T11:16:21Z", "presented_at": "2026-05-27T11:17:00Z"}),
    "P16_timestamp_root_mismatch": ("Timestamp verifies under a root the policy does not accept for the action.", "synthetic-negative-control", "T2", ("policy", "R17_TIMESTAMP_ROOT_NOT_ACCEPTED"), {"tsa": "tsa-vendor"}),
    "P17_missing_agent_subject": ("Receipt lacks the mandatory agent subject.", "synthetic-negative-control", "T3", ("evidence", "V03_REQUIRED_FIELD_MISSING"), {"subject": False}),
    "P18_broker_cross_root_alias": ("Broker maps two issuer identities under different roots to one alias.", "synthetic-negative-control", "T2", ("policy", "R08_BROKER_ALIAS_NOT_INJECTIVE"), {"brokered": True, "delegation": "del-002", "mapping": ALIAS_CLASH_MAPPING}),
    "P19_carrier_rejected_member_auth": ("Carrier rejects the client subsystem's access before any evidence appraisal.", "simulation", "T6", ("carrier", "K02_CARRIER_REJECTED"), {"carrier": "rejected"}),
    "P20_valid_receipt_carrier_unknown": ("Receipt verifies offline; no carrier record accepted by this relying party.", "simulation", "T6", ("carrier", "K01_CARRIER_RECORD_MISSING"), {"carrier": None}),
    "P21_missing_verifier_profile": ("Receipt omits the verifier profile the policy requires.", "synthetic-negative-control", "T7", ("policy", "R01_VERIFIER_PROFILE_MISSING"), {"verifier_profile": None}),
    "P22_wrong_status_source": ("Status list signed by a source other than the one policy names.", "synthetic-negative-control", "T4", ("policy", "R10_STATUS_SOURCE_NOT_ACCEPTED"), {"status": "vendor"}),
    "P23_broker_only_attestation": ("Only the broker asserts a root; the issuer carries none.", "synthetic-negative-control", "T3", ("policy", "R03_ISSUER_ROOT_ABSENT"), {"issuer": "issuer-unanchored", "brokered": True, "delegation": "del-002"}),
    "P24_dual_control_required": ("Mutating action within delegated scope but without the required co-approval.", "simulation", "T5", ("policy", "R16_CO_APPROVAL_REQUIRED"), {"delegation": "del-006", "action": "mutate"}),
}

BROKERED_FIXTURES = {
    "E01_direct_trusted_issuer": ("Direct trusted issuer accepted (control).", "simulation", "T0", ("none", None), {}),
    "E02_brokered_trusted_issuer": ("Brokered trusted issuer accepted (control).", "simulation", "T0", ("none", None), {"brokered": True, "delegation": "del-002"}),
    "E03_brokered_untrusted_root": ("Valid brokered receipt under a root outside policy.", "synthetic-negative-control", "T2", ("policy", "R04_ROOT_NOT_ACCEPTED"), {"brokered": True, "issuer": "issuer-vendor", "delegation": "del-002"}),
    "E04_stale_delegation": ("Brokered receipt with an expired delegation.", "synthetic-negative-control", "T4", ("policy", "R14_DELEGATION_NOT_VALID_AT_EVENT"), {"brokered": True, "delegation": "del-005"}),
    "E05_wrong_action_class": ("Brokered receipt scoped to enrichment, used for a mutation.", "synthetic-negative-control", "T5", ("policy", "R15_ACTION_OUTSIDE_SCOPE"), {"brokered": True, "delegation": "del-002", "action": "mutate"}),
    "E06_message_id_mismatch": ("Brokered receipt bound to a different carrier message id.", "synthetic-negative-control", "T1", ("binding", "B03_MESSAGE_ID_MISMATCH"), {"brokered": True, "delegation": "del-002", "receipt_carrier_overrides": {"message_id": "tyche-real-run-20260527T093000Z", "request_id": "0d2f6c1e-5b1a-4c3e-9a7f-2e8d4b6c1a90"}}),
    "E07_broker_alias_confusion": ("Broker normalises two issuers under different roots to one alias.", "synthetic-negative-control", "T2", ("policy", "R08_BROKER_ALIAS_NOT_INJECTIVE"), {"brokered": True, "delegation": "del-002", "mapping": ALIAS_CLASH_MAPPING}),
    "E08_cross_root_conflict": ("Brokered receipt whose accepted roots disagree about issuer status.", "synthetic-negative-control", "T2", ("policy", "R06_ROOT_CONFLICT"), {"brokered": True, "delegation": "del-002", "endorsing_roots": [("root-municipal-agent-ca", "active"), ("root-partner-ca", "revoked")]}),
    "E09_missing_status_source": ("Brokered receipt without the status list the delegation names.", "synthetic-negative-control", "T4", ("policy", "R09_STATUS_SOURCE_MISSING"), {"brokered": True, "delegation": "del-002", "status": None}),
    "E10_expired_timestamp": ("Brokered receipt presented a day after its timestamp.", "synthetic-negative-control", "T1", ("policy", "R20_TIMESTAMP_OUTSIDE_WINDOW"), {"brokered": True, "delegation": "del-002", "presented_at": "2026-05-28T11:14:22Z", "status_issued_at": "2026-05-28T11:00:00Z"}),
    "E11_payload_hash_mismatch": ("Brokered receipt whose response digest differs from the carrier's.", "synthetic-negative-control", "T1", ("binding", "B05_RESPONSE_DIGEST_MISMATCH"), {"brokered": True, "delegation": "del-002", "receipt_carrier_overrides": {"response_digest": "6f0c3a9e5d2b7c1f4e8a0b3d6c9f2e5a8b1d4c7f0a3e6b9d2c5f8a1b4e7d0c3f"}}),
    "E12_replayed_carrier_binding": ("Brokered receipt bound to a carrier event older than the binding age limit.", "synthetic-negative-control", "T1", ("policy", "R19_BINDING_AGE_EXCEEDED"), {"brokered": True, "delegation": "del-002", "issued_at": "2026-05-27T12:30:00Z", "tsa_time": "2026-05-27T12:30:01Z", "presented_at": "2026-05-27T12:31:00Z", "status_issued_at": "2026-05-27T12:00:00Z"}),
}

# carrier/evidence matrix: (description, basis, threat, intended, spec or None for a planned row)
CARRIER_MATRIX = {
    "C01_observed_exchange_valid_binding": ("Observed local-dev exchange with a matching receipt binding.", "observed-local-dev-stack", "T0", ("none", None), {}),
    "C02_observed_exchange_policy_reject": ("Same carrier record; issuer root outside policy.", "derived-from-observed-artifact", "T2", ("policy", "R04_ROOT_NOT_ACCEPTED"), {"issuer": "issuer-vendor"}),
    "C03_request_id_mismatch": ("Carrier accepted; receipt names a different message id.", "synthetic-negative-control", "T1", ("binding", "B03_MESSAGE_ID_MISMATCH"), {"receipt_carrier_overrides": {"message_id": "tyche-real-run-20260527T093000Z", "request_id": "0d2f6c1e-5b1a-4c3e-9a7f-2e8d4b6c1a90"}}),
    "C04_response_hash_mismatch": ("Carrier accepted; response digest in the receipt changed.", "synthetic-negative-control", "T1", ("binding", "B05_RESPONSE_DIGEST_MISMATCH"), {"receipt_carrier_overrides": {"response_digest": "6f0c3a9e5d2b7c1f4e8a0b3d6c9f2e5a8b1d4c7f0a3e6b9d2c5f8a1b4e7d0c3f"}}),
    "C05_missing_sidecar_manifest": ("Message exists; no evidence object accompanies it.", "synthetic-negative-control", "T3", ("binding", "B02_NO_EVIDENCE"), {"evidence": None}),
    "C06_broker_transformation_mismatch": ("Broker normalisation changes a field covered by the binding.", "synthetic-negative-control", "T3", ("binding", "B06_BROKER_BINDING_ALTERED"), {"brokered": True, "delegation": "del-002", "normalized_overrides": {"carrier_message_id": "tyche-real-run-20260527T111419Z-normalized"}}),
    "C07_clock_skew_inside": ("Clock skew 20 s, inside tolerance.", "derived-from-observed-artifact", "T0", ("none", None), {"tsa_time": "2026-05-27T11:14:41Z"}),
    "C08_clock_skew_outside": ("Clock skew 120 s, outside tolerance.", "synthetic-negative-control", "T7", ("policy", "R18_CLOCK_SKEW_EXCEEDED"), {"tsa_time": "2026-05-27T11:16:21Z", "presented_at": "2026-05-27T11:17:00Z"}),
    "C09_stale_global_configuration": ("Security-server global-configuration boundary: planned, not executed.", "future-test-xroad-plan", "T6", ("carrier", None), None),
    "C10_member_subsystem_auth_failure": ("Carrier rejects an unauthorised subsystem: executed as P19 on the local stack's access-rights model; a national test-instance run remains planned.", "future-test-xroad-plan", "T6", ("carrier", None), None),
    "C11_certificate_rotation_boundary": ("Signing/authentication certificate rollover boundary: planned, not executed.", "future-test-xroad-plan", "T6", ("carrier", None), None),
    "C12_ocsp_outage": ("Carrier could not check certificate status; fail closed.", "synthetic-negative-control", "T6", ("carrier", "K05_CARRIER_VALIDATION_UNAVAILABLE"), {"carrier": "validation_unavailable"}),
    "C13_tsa_outage": ("Carrier could not timestamp the message log; fail closed.", "synthetic-negative-control", "T6", ("carrier", "K05_CARRIER_VALIDATION_UNAVAILABLE"), {"carrier": "timestamp_unavailable"}),
    "C14_verifier_profile_mismatch": ("Receipt names a verifier profile other than the required one.", "synthetic-negative-control", "T7", ("policy", "R02_VERIFIER_PROFILE_MISMATCH"), {"verifier_profile": "ecr-verifier/0.1"}),
    "C15_replay_old_carrier_event": ("Old accepted carrier event replayed outside the binding age limit.", "synthetic-negative-control", "T1", ("policy", "R19_BINDING_AGE_EXCEEDED"), {"issued_at": "2026-05-27T12:30:00Z", "tsa_time": "2026-05-27T12:30:01Z", "presented_at": "2026-05-27T12:31:00Z", "status_issued_at": "2026-05-27T12:00:00Z"}),
    "C16_evidence_only_no_carrier": ("Offline receipt without a carrier witness.", "synthetic-negative-control", "T6", ("carrier", "K01_CARRIER_RECORD_MISSING"), {"carrier": None}),
    "C17_carrier_only_no_agent_evidence": ("Valid X-Road exchange with no agent-authority evidence at all.", "derived-from-observed-artifact", "T3", ("binding", "B02_NO_EVIDENCE"), {"evidence": None}),
    "C18_broker_root_conflict_after_carrier_success": ("Carrier says the exchange happened; accepted roots disagree about authority.", "synthetic-negative-control", "T2", ("policy", "R06_ROOT_CONFLICT"), {"brokered": True, "delegation": "del-002", "endorsing_roots": [("root-municipal-agent-ca", "active"), ("root-partner-ca", "revoked")]}),
}

# re-assurance scenario packets (not part of the three tables). Their carrier
# records are time-shifted copies of the observed exchange, labelled as such.
def _shift(observed: str, issued: str, tsa: str, presented: str, status_issued: str) -> dict:
    return {"carrier": "shifted", "carrier_observed_at": observed, "issued_at": issued, "tsa_time": tsa,
            "presented_at": presented, "status_issued_at": status_issued}


SCENARIO_PACKETS = {
    "S01_mutate_with_co_approval": ("Mutating action within scope with a listed co-approver; accepted unless a claim is pending.", "simulation", "T8", ("none", None),
                                    {"delegation": "del-006", "action": "mutate", "co_approval": True,
                                     **_shift("2026-06-17T07:28:00Z", "2026-06-17T07:28:02Z", "2026-06-17T07:28:03Z", "2026-06-17T07:30:00Z", "2026-06-17T07:00:00Z")}),
    "S02_read_with_new_model_version": ("Read action by the upgraded model before policy admits the new profile.", "simulation", "T8", ("policy", "R21_RUNTIME_PROFILE_NOT_ALLOWED"),
                                        {"action": "read", "model_version": MODEL_VERSION_NEXT,
                                         **_shift("2026-06-17T07:33:00Z", "2026-06-17T07:33:02Z", "2026-06-17T07:33:03Z", "2026-06-17T07:35:00Z", "2026-06-17T07:00:00Z")}),
    "S03_mutate_outside_scope_with_co_approval": ("Escalation attempt: mutation under a read/enrich delegation, co-approval present.", "simulation", "T5", ("policy", "R15_ACTION_OUTSIDE_SCOPE"),
                                                  {"action": "mutate", "co_approval": True,
                                                   **_shift("2026-06-20T09:48:00Z", "2026-06-20T09:48:02Z", "2026-06-20T09:48:03Z", "2026-06-20T09:50:00Z", "2026-06-20T09:00:00Z")}),
    "S04_read_with_new_model_version_after_policy_update": ("The S02 action repeated after the policy admits the new profile.", "simulation", "T0", ("none", None),
                                                            {"action": "read", "model_version": MODEL_VERSION_NEXT,
                                                             **_shift("2026-06-17T16:03:00Z", "2026-06-17T16:03:02Z", "2026-06-17T16:03:03Z", "2026-06-17T16:05:00Z", "2026-06-17T15:30:00Z")}),
    "S05_mutate_during_audit": ("Mutating action with co-approval by the admitted model, presented while an audit challenge holds every claim pending.", "simulation", "T8", ("none", "H01_HOLD_PENDING_REASSESSMENT"),
                                {"delegation": "del-006", "action": "mutate", "co_approval": True, "model_version": MODEL_VERSION_NEXT,
                                 **_shift("2026-06-30T09:58:00Z", "2026-06-30T09:58:02Z", "2026-06-30T09:58:03Z", "2026-06-30T10:00:00Z", "2026-06-30T09:30:00Z")}),
}
# S01, S02, S03 are appraised under the policy in force at their presentation
# time in the scenario; S01 is held (G0 pending), S04 is accepted after the
# policy admits the new profile, S05 is held during the audit. The intended
# outcomes above are checked against the scenario log, not against the base
# policy.
SCENARIO_INTENDED = {
    "S01_mutate_with_co_approval": ("none", "H01_HOLD_PENDING_REASSESSMENT"),
    "S02_read_with_new_model_version": ("policy", "R21_RUNTIME_PROFILE_NOT_ALLOWED"),
    "S03_mutate_outside_scope_with_co_approval": ("policy", "R15_ACTION_OUTSIDE_SCOPE"),
    "S04_read_with_new_model_version_after_policy_update": ("none", None),
    "S05_mutate_during_audit": ("none", "H01_HOLD_PENDING_REASSESSMENT"),
}

# coverage controls: one packet per reason code that none of the 51 table
# packets reaches as a first failure. Three codes cannot be a first failure
# by construction and appear in the check log instead: B01 (always preceded
# by a carrier failure), V01 (always preceded by B02), R00 (the policy
# layer's record that an earlier predicate failed).
_HEX = "6f0c3a9e5d2b7c1f4e8a0b3d6c9f2e5a8b1d4c7f0a3e6b9d2c5f8a1b4e7d0c3f"
COVERAGE_CONTROLS = {
    "N01_carrier_service_outside_policy": ("Carrier accepted the exchange, but the provider service is not in the relying party's accepted set.", "synthetic-negative-control", "T6", ("carrier", "K03_CARRIER_CONFIG_MISMATCH"),
                                           {"carrier_overrides": {"service": "DEV/COM/1234/OtherService/mock1"}}),
    "N02_message_log_rows_absent": ("Carrier accepted the exchange; the record carries no message-log rows for either side.", "synthetic-negative-control", "T6", ("carrier", "K04_MESSAGE_LOG_MISSING"),
                                    {"carrier_overrides": {"message_log.provider_rows": [], "message_log.consumer_rows": []}}),
    "N03_request_digest_mismatch": ("Receipt's request digest differs from the carrier record's request payload digest.", "synthetic-negative-control", "T1", ("binding", "B04_REQUEST_DIGEST_MISMATCH"),
                                    {"receipt_carrier_overrides": {"request_digest": _HEX}}),
    "N04_unknown_receipt_profile": ("Receipt declares a profile this verifier does not implement.", "synthetic-negative-control", "T7", ("evidence", "V02_PROFILE_UNKNOWN"),
                                    {"tamper": [("evidence.payload.profile", "ecr-receipt/0.1")]}),
    "N05_receipt_payload_edited": ("Receipt payload edited after signing (action summary).", "synthetic-negative-control", "T1", ("evidence", "V04_SIGNATURE_INVALID"),
                                   {"tamper": [("evidence.payload.action.summary", "append an enrichment note (edited after signing)")]}),
    "N06_endorsement_signature_invalid": ("Issuer carries a root endorsement whose payload was altered; the root signature over it no longer verifies.", "synthetic-negative-control", "T2", ("evidence", "V05_ENDORSEMENT_INVALID"),
                                          {"endorsement_tamper": [("0.payload.valid_until", "2028-01-01T00:00:00Z")]}),
    "N07_broker_signature_invalid": ("Broker envelope payload edited after signing (mapping id).", "synthetic-negative-control", "T3", ("evidence", "V06_BROKER_SIGNATURE_INVALID"),
                                     {"brokered": True, "delegation": "del-002", "tamper": [("evidence.payload.mapping_id", "map-2026-06")]}),
    "N08_timestamp_token_edited": ("Timestamp token payload edited after signing (time).", "synthetic-negative-control", "T1", ("evidence", "V08_TIMESTAMP_TOKEN_INVALID"),
                                   {"tamper": [("timestamp_token.payload.time", "2026-05-27T11:14:23Z")]}),
    "N09_status_list_edited": ("Status list payload edited after signing (issue time).", "synthetic-negative-control", "T4", ("evidence", "V09_STATUS_LIST_INVALID"),
                               {"tamper": [("status_list.payload.issued_at", "2026-05-27T11:10:00Z")]}),
    "N10_co_approval_edited": ("Co-approval payload edited after signing (approval time).", "synthetic-negative-control", "T5", ("evidence", "V10_CO_APPROVAL_INVALID"),
                               {"delegation": "del-006", "action": "mutate", "co_approval": True, "tamper": [("co_approval.payload.approved_at", "2026-05-27T11:14:30Z")]}),
    "N11_root_not_accepted_for_mutation": ("Partner root is accepted for read and enrich only; the action mutates the case file with scope and co-approval in order.", "synthetic-negative-control", "T5", ("policy", "R05_ROOT_NOT_ACCEPTED_FOR_ACTION"),
                                           {"issuer": "issuer-partner", "delegation": "del-006", "action": "mutate", "co_approval": True}),
    "N12_broker_mapping_not_registered": ("Broker signs with its registered key under a mapping id the relying party has not registered.", "synthetic-negative-control", "T3", ("policy", "R07_BROKER_NOT_ACCEPTED"),
                                          {"brokered": True, "delegation": "del-002", "mapping_id": "map-2026-01"}),
}
STRUCTURALLY_NOT_FIRST = {
    "B01_NO_CARRIER_RECORD": "always preceded by a carrier-layer failure (K01, K02 or K05)",
    "V01_EVIDENCE_MISSING": "always preceded by B02_NO_EVIDENCE at the binding layer",
    "R00_UPSTREAM_PREDICATE_FAILED": "the policy layer's record that an earlier predicate failed",
}

FAMILIES = {
    "policy-cases": POLICY_CASES,
    "brokered-evidence-fixtures": BROKERED_FIXTURES,
    "carrier-evidence-matrix": CARRIER_MATRIX,
    "coverage-controls": COVERAGE_CONTROLS,
    "scenario": SCENARIO_PACKETS,
}
