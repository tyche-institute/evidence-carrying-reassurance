"""The four-predicate appraisal.

    Assured(a) = CarrierOK(a) ∧ BindingOK(a) ∧ EvidenceOK(a) ∧ PolicyOK(a)

All four predicates are evaluated and reported; the first-failure layer is
the first of carrier, binding, evidence, policy whose predicate is false, and
the reason code is the first failing check inside that layer. PolicyOK is
false whenever an earlier predicate is false (rule R00): policy appraises
only witnessed, bound and verified evidence.

A packet is one JSON object:

    {
      "case_id": ..., "presented_at": "<ISO 8601 Z>",
      "carrier_record": {...} | null,
      "evidence": <receipt> | <broker envelope> | null,
      "timestamp_token": {...} | null,
      "status_list": {...} | null,
      "co_approval": {...} | null
    }

`appraise(packet, policy, state)` returns a decision record (dict) that is
itself in the canonical subset, so it can be digested and logged.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from . import PROFILE_BROKER, PROFILE_COAPPROVAL, PROFILE_ENDORSEMENT, PROFILE_RECEIPT, PROFILE_STATUS, PROFILE_TIMESTAMP
from .canon import digest
from .codes import describe
from .keys import verify as verify_sig

LAYERS = ("carrier", "binding", "evidence", "policy")

RECEIPT_MANDATORY = (
    "profile", "receipt_id", "issued_at", "subject", "issuer", "delegation", "carrier", "action", "runtime",
)
SUBJECT_MANDATORY = ("agent_id",)
ISSUER_MANDATORY = ("id", "key_id")          # root may be null; endorsements may be empty (policy decides)
DELEGATION_MANDATORY = ("id", "grantor", "grantee", "scope", "valid_from", "valid_until", "status_source")
CARRIER_MANDATORY = ("carrier", "message_id", "request_id", "request_digest", "response_digest")
ACTION_MANDATORY = ("class", "target", "tool")
RUNTIME_MANDATORY = ("model_version", "tool_profile_digest", "prompt_profile_digest")


def parse_time(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def seconds_between(a: str, b: str) -> int:
    return int((parse_time(b) - parse_time(a)).total_seconds())


class Check:
    """Accumulates the checks of one layer; the first failure fixes the reason."""

    def __init__(self, layer: str):
        self.layer = layer
        self.log: list[dict] = []
        self.failed: str | None = None

    def ok(self, code: str, detail: str = "") -> None:
        self.log.append({"check": code, "result": "pass", "detail": detail})

    def fail(self, code: str, detail: str = "") -> None:
        self.log.append({"check": code, "result": "fail", "detail": detail})
        if self.failed is None:
            self.failed = code

    def skip(self, code: str, detail: str = "") -> None:
        self.log.append({"check": code, "result": "skip", "detail": detail})

    @property
    def passed(self) -> bool:
        return self.failed is None


# --------------------------------------------------------------------------- helpers

def unwrap(evidence: dict | None) -> tuple[dict | None, dict | None]:
    """Return (receipt, envelope). A direct receipt has no envelope."""
    if evidence is None:
        return None, None
    profile = (evidence.get("payload") or {}).get("profile")
    if profile == PROFILE_BROKER:
        return evidence.get("attached_receipt"), evidence
    return evidence, None


def receipt_payload(evidence: dict | None) -> dict | None:
    r, _ = unwrap(evidence)
    return (r or {}).get("payload") if r else None


# --------------------------------------------------------------------------- layers

def check_carrier(packet: dict, policy: dict) -> Check:
    c = Check("carrier")
    rec = packet.get("carrier_record")
    if rec is None:
        c.fail("K01_CARRIER_RECORD_MISSING")
        return c
    c.ok("K01_CARRIER_RECORD_MISSING", "carrier record present")
    status = rec.get("status")
    if status == "accepted":
        c.ok("K02_CARRIER_REJECTED", "carrier status accepted")
    elif status in ("validation_unavailable", "timestamp_unavailable"):
        c.fail("K05_CARRIER_VALIDATION_UNAVAILABLE", f"carrier status {status}: {rec.get('fault')}")
    else:
        c.fail("K02_CARRIER_REJECTED", f"carrier status {status}: {rec.get('fault')}")
    cfg = policy["carrier"]
    if (rec.get("carrier") == cfg["carrier"] and rec.get("instance") == cfg["instance"]
            and rec.get("client") in cfg["accepted_clients"] and rec.get("service") in cfg["accepted_services"]):
        c.ok("K03_CARRIER_CONFIG_MISMATCH", f"{rec.get('instance')} {rec.get('client')} -> {rec.get('service')}")
    else:
        c.fail("K03_CARRIER_CONFIG_MISMATCH", f"{rec.get('instance')} {rec.get('client')} -> {rec.get('service')}")
    ml = rec.get("message_log") or {}
    if cfg.get("require_message_log") and status == "accepted":
        if ml.get("provider_rows") and ml.get("consumer_rows"):
            c.ok("K04_MESSAGE_LOG_MISSING", f"provider rows {ml['provider_rows']}, consumer rows {ml['consumer_rows']}")
        else:
            c.fail("K04_MESSAGE_LOG_MISSING")
    if status == "accepted":
        c.ok("K05_CARRIER_VALIDATION_UNAVAILABLE", "validation and timestamping chains available")
    else:
        c.skip("K04_MESSAGE_LOG_MISSING", "not required or carrier not accepted")
    return c


def check_binding(packet: dict, carrier_ok: bool) -> Check:
    c = Check("binding")
    rec = packet.get("carrier_record")
    if rec is None or not carrier_ok:
        c.fail("B01_NO_CARRIER_RECORD")
        return c
    c.ok("B01_NO_CARRIER_RECORD", "carrier record accepted")
    rp = receipt_payload(packet.get("evidence"))
    if rp is None:
        c.fail("B02_NO_EVIDENCE")
        return c
    c.ok("B02_NO_EVIDENCE", "evidence object present")
    rc = rp.get("carrier") or {}
    if rc.get("message_id") == rec.get("message_id") and rc.get("request_id") == rec.get("request_id"):
        c.ok("B03_MESSAGE_ID_MISMATCH", rc.get("message_id", ""))
    else:
        c.fail("B03_MESSAGE_ID_MISMATCH", f"receipt {rc.get('message_id')}/{rc.get('request_id')} vs carrier {rec.get('message_id')}/{rec.get('request_id')}")
    if rc.get("request_digest") == rec.get("request_payload_sha256"):
        c.ok("B04_REQUEST_DIGEST_MISMATCH", rc.get("request_digest", ""))
    else:
        c.fail("B04_REQUEST_DIGEST_MISMATCH", f"receipt {rc.get('request_digest')} vs carrier {rec.get('request_payload_sha256')}")
    if rc.get("response_digest") == rec.get("response_body_sha256"):
        c.ok("B05_RESPONSE_DIGEST_MISMATCH", rc.get("response_digest", ""))
    else:
        c.fail("B05_RESPONSE_DIGEST_MISMATCH", f"receipt {rc.get('response_digest')} vs carrier {rec.get('response_body_sha256')}")
    _, env = unwrap(packet.get("evidence"))
    if env is not None:
        norm = (env.get("payload") or {}).get("normalized") or {}
        same = (norm.get("carrier_message_id") == rc.get("message_id")
                and norm.get("request_digest") == rc.get("request_digest")
                and norm.get("response_digest") == rc.get("response_digest"))
        if same:
            c.ok("B06_BROKER_BINDING_ALTERED", "broker normalisation preserves binding fields")
        else:
            c.fail("B06_BROKER_BINDING_ALTERED", f"normalized {norm.get('carrier_message_id')} vs receipt {rc.get('message_id')}")
    else:
        c.skip("B06_BROKER_BINDING_ALTERED", "direct receipt")
    return c


def _verify_endorsement(e: dict, expect_subject_key: str) -> tuple[bool, str]:
    p = e.get("payload") or {}
    if p.get("profile") != PROFILE_ENDORSEMENT:
        return False, "endorsement profile unknown"
    ok, why = verify_sig(p, e.get("signature"))
    if not ok:
        return False, why
    if (e["signature"].get("key_id") != p.get("root_key_id")):
        return False, "endorsement not signed by the root key it names"
    if p.get("subject_key_id") != expect_subject_key:
        return False, "endorsement names a different subject key"
    return True, "ok"


def check_evidence(packet: dict) -> Check:
    c = Check("evidence")
    ev = packet.get("evidence")
    if ev is None:
        c.fail("V01_EVIDENCE_MISSING")
        return c
    c.ok("V01_EVIDENCE_MISSING", "evidence object present")
    rcpt, env = unwrap(ev)
    rp = (rcpt or {}).get("payload") or {}
    if rp.get("profile") != PROFILE_RECEIPT:
        c.fail("V02_PROFILE_UNKNOWN", str(rp.get("profile")))
        return c
    c.ok("V02_PROFILE_UNKNOWN", rp["profile"])
    missing = [f for f in RECEIPT_MANDATORY if f not in rp]
    for group, keys in (("subject", SUBJECT_MANDATORY), ("issuer", ISSUER_MANDATORY), ("delegation", DELEGATION_MANDATORY),
                        ("carrier", CARRIER_MANDATORY), ("action", ACTION_MANDATORY), ("runtime", RUNTIME_MANDATORY)):
        sub = rp.get(group)
        if isinstance(sub, dict):
            missing += [f"{group}.{k}" for k in keys if k not in sub]
    if missing:
        c.fail("V03_REQUIRED_FIELD_MISSING", ", ".join(missing))
    else:
        c.ok("V03_REQUIRED_FIELD_MISSING", "all mandatory fields present")
    ok, why = verify_sig(rp, rcpt.get("signature"))
    if ok and rcpt["signature"].get("key_id") == (rp.get("issuer") or {}).get("key_id"):
        c.ok("V04_SIGNATURE_INVALID", "issuer signature verifies; key_id matches issuer.key_id")
    else:
        c.fail("V04_SIGNATURE_INVALID", why if not ok else "signature key differs from issuer.key_id")
    ends = (rp.get("issuer") or {}).get("endorsements") or []
    bad = []
    for e in ends:
        eok, ewhy = _verify_endorsement(e, (rp.get("issuer") or {}).get("key_id"))
        if not eok:
            bad.append(ewhy)
    if bad:
        c.fail("V05_ENDORSEMENT_INVALID", "; ".join(bad))
    else:
        c.ok("V05_ENDORSEMENT_INVALID", f"{len(ends)} endorsement(s) verify" if ends else "no endorsement carried")
    if env is not None:
        ep = env.get("payload") or {}
        ok, why = verify_sig(ep, env.get("signature"))
        if ok:
            c.ok("V06_BROKER_SIGNATURE_INVALID", "broker signature verifies")
        else:
            c.fail("V06_BROKER_SIGNATURE_INVALID", why)
        if ep.get("attached_receipt_digest") == digest(rcpt):
            c.ok("V07_BROKER_DIGEST_MISMATCH", ep.get("attached_receipt_digest", ""))
        else:
            c.fail("V07_BROKER_DIGEST_MISMATCH", f"signed {ep.get('attached_receipt_digest')} vs attached {digest(rcpt)}")
    else:
        c.skip("V06_BROKER_SIGNATURE_INVALID", "direct receipt")
        c.skip("V07_BROKER_DIGEST_MISMATCH", "direct receipt")
    ts = packet.get("timestamp_token")
    if ts is None:
        c.fail("V08_TIMESTAMP_TOKEN_INVALID", "no timestamp token")
    else:
        tp = ts.get("payload") or {}
        ok, why = verify_sig(tp, ts.get("signature"))
        eok, ewhy = _verify_endorsement(tp.get("endorsement") or {}, ts.get("signature", {}).get("key_id"))
        if tp.get("profile") == PROFILE_TIMESTAMP and ok and eok and tp.get("digest") == digest(rp):
            c.ok("V08_TIMESTAMP_TOKEN_INVALID", f"{tp.get('tsa')} at {tp.get('time')} over receipt payload digest")
        else:
            c.fail("V08_TIMESTAMP_TOKEN_INVALID", why if not ok else (ewhy if not eok else "digest does not cover receipt payload"))
    sl = packet.get("status_list")
    if sl is None:
        c.skip("V09_STATUS_LIST_INVALID", "no status list (policy decides)")
    else:
        sp = sl.get("payload") or {}
        ok, why = verify_sig(sp, sl.get("signature"))
        if sp.get("profile") == PROFILE_STATUS and ok:
            c.ok("V09_STATUS_LIST_INVALID", f"{sp.get('source')} issued {sp.get('issued_at')}")
        else:
            c.fail("V09_STATUS_LIST_INVALID", why)
    ca = packet.get("co_approval")
    if ca is None:
        c.skip("V10_CO_APPROVAL_INVALID", "no co-approval (policy decides)")
    else:
        cp = ca.get("payload") or {}
        ok, why = verify_sig(cp, ca.get("signature"))
        if cp.get("profile") == PROFILE_COAPPROVAL and ok and cp.get("receipt_payload_digest") == digest(rp):
            c.ok("V10_CO_APPROVAL_INVALID", cp.get("approver", ""))
        else:
            c.fail("V10_CO_APPROVAL_INVALID", why if not ok else "co-approval does not cover receipt payload digest")
    return c


def check_policy(packet: dict, policy: dict, upstream_ok: bool, now: str | None = None) -> Check:
    """`now` is the appraisal time. At first presentation it is the packet's
    `presented_at`. At re-appraisal it is the event time: status freshness
    (R11) is then measured against the event, while the freshness window
    (R20) stays bound to the original presentation, which is the only moment
    the evidence was presented."""
    c = Check("policy")
    if not upstream_ok:
        c.fail("R00_UPSTREAM_PREDICATE_FAILED")
        return c
    c.ok("R00_UPSTREAM_PREDICATE_FAILED", "carrier, binding and evidence predicates hold")
    rcpt, env = unwrap(packet["evidence"])
    rp = rcpt["payload"]
    rec = packet["carrier_record"]
    presented = packet["presented_at"]
    status_ref = now or presented
    action_class = rp["action"]["class"]

    # R01/R02 verifier profile
    vp = rp["runtime"].get("verifier_profile")
    if vp is None:
        c.fail("R01_VERIFIER_PROFILE_MISSING")
    else:
        c.ok("R01_VERIFIER_PROFILE_MISSING", vp)
        if vp == policy["require_verifier_profile"]:
            c.ok("R02_VERIFIER_PROFILE_MISMATCH", vp)
        else:
            c.fail("R02_VERIFIER_PROFILE_MISMATCH", f"{vp} vs required {policy['require_verifier_profile']}")

    # R03–R06 roots
    issuer = rp["issuer"]
    ends = issuer.get("endorsements") or []
    asserted_roots = {e["payload"]["root"]: e["payload"] for e in ends}
    if issuer.get("root") is None or not ends:
        c.fail("R03_ISSUER_ROOT_ABSENT", "issuer.root null or no endorsement" + (" (broker asserts a root)" if env else ""))
    else:
        c.ok("R03_ISSUER_ROOT_ABSENT", issuer["root"])
        accepted = policy["accepted_roots"]
        root = issuer["root"]
        root_ok = root in accepted and root in asserted_roots and asserted_roots[root]["root_key_id"] == accepted[root]["key_id"]
        if root_ok:
            c.ok("R04_ROOT_NOT_ACCEPTED", root)
            if action_class in accepted[root]["accepted_for"]:
                c.ok("R05_ROOT_NOT_ACCEPTED_FOR_ACTION", f"{root} accepted for {action_class}")
            else:
                c.fail("R05_ROOT_NOT_ACCEPTED_FOR_ACTION", f"{root} not accepted for {action_class}")
        else:
            c.fail("R04_ROOT_NOT_ACCEPTED", root)
            c.skip("R05_ROOT_NOT_ACCEPTED_FOR_ACTION")
        statuses = {r: p["issuer_status"] for r, p in asserted_roots.items()
                    if r in accepted and p["root_key_id"] == accepted[r]["key_id"]}
        if len(set(statuses.values())) > 1:
            c.fail("R06_ROOT_CONFLICT", ", ".join(f"{r}={s}" for r, s in sorted(statuses.items())))
        elif statuses and set(statuses.values()) != {"active"}:
            c.fail("R06_ROOT_CONFLICT", "accepted root asserts issuer status " + next(iter(statuses.values())))
        else:
            c.ok("R06_ROOT_CONFLICT", "accepted roots agree: issuer active" if statuses else "no accepted root asserts status")

    # R07–R08 broker
    if env is None:
        c.skip("R07_BROKER_NOT_ACCEPTED", "direct receipt")
        c.skip("R08_BROKER_ALIAS_NOT_INJECTIVE", "direct receipt")
    else:
        ep = env["payload"]
        reg = policy["accepted_brokers"].get(ep["broker"])
        if reg and env["signature"]["key_id"] == reg["key_id"] and ep["mapping_id"] in reg["mapping_ids"]:
            c.ok("R07_BROKER_NOT_ACCEPTED", f"{ep['broker']} / {ep['mapping_id']}")
        else:
            c.fail("R07_BROKER_NOT_ACCEPTED", f"{ep['broker']} / {ep['mapping_id']}")
        seen: dict[str, set] = {}
        for m in ep["mapping"]:
            seen.setdefault(m["alias"], set()).add((m["issuer"], m["root"]))
        clash = {a: s for a, s in seen.items() if len(s) > 1}
        if clash:
            c.fail("R08_BROKER_ALIAS_NOT_INJECTIVE", "; ".join(f"{a} <- {sorted(s)}" for a, s in clash.items()))
        else:
            c.ok("R08_BROKER_ALIAS_NOT_INJECTIVE", f"{len(ep['mapping'])} mapping rows, aliases injective")

    # R09–R14 delegation status and validity
    deleg = rp["delegation"]
    sl = packet.get("status_list")
    if sl is None:
        c.fail("R09_STATUS_SOURCE_MISSING", deleg["status_source"])
        for code in ("R10_STATUS_SOURCE_NOT_ACCEPTED", "R11_STATUS_STALE", "R12_DELEGATION_REVOKED", "R13_DELEGATION_SUSPENDED"):
            c.skip(code)
    else:
        c.ok("R09_STATUS_SOURCE_MISSING", "status list present")
        sp = sl["payload"]
        src = policy["status_sources"].get(sp["source"])
        if (sp["source"] == deleg["status_source"] and src and sl["signature"]["key_id"] == src["key_id"]):
            c.ok("R10_STATUS_SOURCE_NOT_ACCEPTED", sp["source"])
        else:
            c.fail("R10_STATUS_SOURCE_NOT_ACCEPTED", f"{sp['source']} (delegation names {deleg['status_source']})")
        age = seconds_between(sp["issued_at"], status_ref)
        if 0 <= age <= policy["status_max_age_s"]:
            c.ok("R11_STATUS_STALE", f"status age {age} s <= {policy['status_max_age_s']} s")
        else:
            c.fail("R11_STATUS_STALE", f"status age {age} s > {policy['status_max_age_s']} s")
        entry = (sp["entries"].get(deleg["id"]) or {})
        st = entry.get("status", "unknown")
        if st == "revoked":
            c.fail("R12_DELEGATION_REVOKED", f"{deleg['id']} revoked since {entry.get('since')}")
        else:
            c.ok("R12_DELEGATION_REVOKED", f"{deleg['id']} {st}")
        if st == "suspended":
            c.fail("R13_DELEGATION_SUSPENDED", f"{deleg['id']} suspended since {entry.get('since')}")
        elif st == "active":
            c.ok("R13_DELEGATION_SUSPENDED", f"{deleg['id']} active")
        elif st == "revoked":
            c.skip("R13_DELEGATION_SUSPENDED")
        else:
            c.fail("R13_DELEGATION_SUSPENDED", f"{deleg['id']} status {st}")
    event_time = rec["observed_at"]
    if deleg["valid_from"] <= event_time <= deleg["valid_until"]:
        c.ok("R14_DELEGATION_NOT_VALID_AT_EVENT", f"{deleg['valid_from']}..{deleg['valid_until']} contains {event_time}")
    else:
        c.fail("R14_DELEGATION_NOT_VALID_AT_EVENT", f"{deleg['valid_from']}..{deleg['valid_until']} excludes {event_time}")

    # R15–R16 action scope and co-approval
    if action_class in deleg["scope"]:
        c.ok("R15_ACTION_OUTSIDE_SCOPE", f"{action_class} in {deleg['scope']}")
    else:
        c.fail("R15_ACTION_OUTSIDE_SCOPE", f"{action_class} not in {deleg['scope']}")
    rule = policy["action_classes"].get(action_class) or {}
    if rule.get("co_approval"):
        ca = packet.get("co_approval")
        approver = (ca or {}).get("payload", {}).get("approver")
        pin = policy["approvers"].get(approver or "")
        if ca and pin and ca["signature"]["key_id"] == pin["key_id"]:
            c.ok("R16_CO_APPROVAL_REQUIRED", f"co-approval by {approver}")
        else:
            c.fail("R16_CO_APPROVAL_REQUIRED", f"{action_class} requires co-approval; " + ("none present" if not ca else f"approver {approver} not listed"))
    else:
        c.skip("R16_CO_APPROVAL_REQUIRED", f"{action_class} needs no co-approval")

    # R17–R20 time
    tp = packet["timestamp_token"]["payload"]
    troot = policy["accepted_timestamp_roots"].get(tp["root"])
    if troot and tp["endorsement"]["payload"]["root_key_id"] == troot["key_id"] and action_class in troot["accepted_for"]:
        c.ok("R17_TIMESTAMP_ROOT_NOT_ACCEPTED", tp["root"])
    else:
        c.fail("R17_TIMESTAMP_ROOT_NOT_ACCEPTED", tp["root"])
    skew = abs(seconds_between(rp["issued_at"], tp["time"]))
    if skew <= policy["clock_skew_tolerance_s"]:
        c.ok("R18_CLOCK_SKEW_EXCEEDED", f"|issued_at - tsa.time| = {skew} s <= {policy['clock_skew_tolerance_s']} s")
    else:
        c.fail("R18_CLOCK_SKEW_EXCEEDED", f"|issued_at - tsa.time| = {skew} s > {policy['clock_skew_tolerance_s']} s")
    bind_age = seconds_between(event_time, tp["time"])
    if 0 <= bind_age <= policy["carrier_binding_max_age_s"]:
        c.ok("R19_BINDING_AGE_EXCEEDED", f"tsa.time - carrier.observed_at = {bind_age} s <= {policy['carrier_binding_max_age_s']} s")
    else:
        c.fail("R19_BINDING_AGE_EXCEEDED", f"tsa.time - carrier.observed_at = {bind_age} s > {policy['carrier_binding_max_age_s']} s")
    fresh = seconds_between(tp["time"], presented)
    if 0 <= fresh <= policy["freshness_window_s"]:
        c.ok("R20_TIMESTAMP_OUTSIDE_WINDOW", f"presented_at - tsa.time = {fresh} s <= {policy['freshness_window_s']} s")
    else:
        c.fail("R20_TIMESTAMP_OUTSIDE_WINDOW", f"presented_at - tsa.time = {fresh} s > {policy['freshness_window_s']} s")

    # R21 runtime profile
    rt = rp["runtime"]
    allowed = policy["allowed_runtime_profiles"]
    if (rt["model_version"] in allowed["model_versions"] and rt["tool_profile_digest"] in allowed["tool_profile_digests"]
            and rt["prompt_profile_digest"] in allowed["prompt_profile_digests"]):
        c.ok("R21_RUNTIME_PROFILE_NOT_ALLOWED", rt["model_version"])
    else:
        c.fail("R21_RUNTIME_PROFILE_NOT_ALLOWED", rt["model_version"])
    return c


# --------------------------------------------------------------------------- appraisal

def _pin(table: dict, key) -> dict | None:
    """The one entry of a policy table that a check read, keyed by name; None
    when the check read no entry (the key is absent from the packet)."""
    return None if key is None else {str(key): table.get(key)}


def depends_on(packet: dict, policy: dict) -> dict:
    """Digests of the slices of the relying party's inputs that the checks of
    THIS packet read. Five digests, one per input class:

    * ``trust_anchors``: the accepted-root entry for every root the issuer
      asserts (None when the root is not accepted), the accepted
      timestamp-root entry for the token's root, the broker registration for
      the envelope's broker, the approver pin for the co-approval's approver;
    * ``status``: whether a status list is present, which source it names and
      whether that source is the one the delegation names and is pinned in
      policy (key id), the key the list is signed with, and the status entry
      for the delegation id used;
    * ``runtime_profile``: whether each of the receipt's three profile fields
      (model version, tool profile, prompt profile) is in the allow-list;
    * ``policy_parameters``: the thresholds every decision reads (required
      verifier profile, maximum status age, skew tolerance, binding age,
      freshness window) and the action-class rule for this action class;
    * ``carrier_config``: whether the carrier record's carrier, instance,
      client and service are accepted and whether a message log is required.

    A change to an input that does not touch a slice a decision read leaves
    that decision's five digests unchanged. The re-assurance log re-appraises
    exactly the decisions whose digests changed; the property test in
    ``tests/test_reassure.py`` checks that no decision whose outcome would
    change under the new inputs is left unselected.
    """
    rp = receipt_payload(packet.get("evidence")) or {}
    _, env = unwrap(packet.get("evidence"))
    issuer = rp.get("issuer") or {}
    asserted = {e["payload"]["root"] for e in (issuer.get("endorsements") or []) if isinstance(e, dict) and isinstance(e.get("payload"), dict) and e["payload"].get("root")}
    if issuer.get("root"):
        asserted.add(issuer["root"])
    tp = (packet.get("timestamp_token") or {}).get("payload") or {}
    ep = (env or {}).get("payload") or {}
    cap = (packet.get("co_approval") or {}).get("payload") or {}
    trust = {
        "roots": {r: policy["accepted_roots"].get(r) for r in sorted(asserted)},
        "timestamp_root": _pin(policy["accepted_timestamp_roots"], tp.get("root")),
        "broker": _pin(policy["accepted_brokers"], ep.get("broker")) if ep else None,
        "approver": _pin(policy["approvers"], cap.get("approver")) if cap else None,
    }
    deleg = rp.get("delegation") or {}
    sl = packet.get("status_list")
    sp = (sl or {}).get("payload") or {}
    status = {
        "present": sl is not None,
        "delegation_id": deleg.get("id"),
        "source_named_by_delegation": deleg.get("status_source"),
        "source": sp.get("source"),
        "source_pinned": _pin(policy["status_sources"], sp.get("source")) if sl is not None else None,
        "list_key_id": ((sl or {}).get("signature") or {}).get("key_id"),
        "entry": (sp.get("entries") or {}).get(deleg.get("id")) if (sl is not None and deleg.get("id")) else None,
    }
    rt = rp.get("runtime") or {}
    allowed = policy["allowed_runtime_profiles"]
    runtime = {
        "model_version": rt.get("model_version"),
        "model_version_allowed": rt.get("model_version") in allowed["model_versions"],
        "tool_profile_allowed": rt.get("tool_profile_digest") in allowed["tool_profile_digests"],
        "prompt_profile_allowed": rt.get("prompt_profile_digest") in allowed["prompt_profile_digests"],
    }
    action_class = (rp.get("action") or {}).get("class")
    params = {
        "require_verifier_profile": policy["require_verifier_profile"],
        "status_max_age_s": policy["status_max_age_s"],
        "clock_skew_tolerance_s": policy["clock_skew_tolerance_s"],
        "carrier_binding_max_age_s": policy["carrier_binding_max_age_s"],
        "freshness_window_s": policy["freshness_window_s"],
        "action_class_rule": _pin(policy["action_classes"], action_class),
    }
    rec = packet.get("carrier_record") or {}
    cfg = policy["carrier"]
    carrier = {
        "carrier_matches": rec.get("carrier") == cfg["carrier"],
        "instance_matches": rec.get("instance") == cfg["instance"],
        "client_accepted": rec.get("client") in cfg["accepted_clients"],
        "service_accepted": rec.get("service") in cfg["accepted_services"],
        "require_message_log": bool(cfg.get("require_message_log")),
    }
    return {
        "trust_anchors": digest(trust),
        "status": digest(status),
        "runtime_profile": digest(runtime),
        "policy_parameters": digest(params),
        "carrier_config": digest(carrier),
    }


def appraise(packet: dict, policy: dict, state: dict | None = None, now: str | None = None) -> dict:
    """Evaluate the four predicates; return the decision record.

    `state` is the assurance-case state kept by the re-assurance log:
    {"claims": {"G0": "accepted"|"pending"|...}}. A pending claim puts a
    high-risk action on hold (H01) instead of accepting it. `now` is the
    appraisal time (see check_policy); None means the packet's presented_at.
    """
    k = check_carrier(packet, policy)
    b = check_binding(packet, k.passed)
    v = check_evidence(packet)
    r = check_policy(packet, policy, k.passed and b.passed and v.passed, now)
    preds = {"carrier_ok": k.passed, "binding_ok": b.passed, "evidence_ok": v.passed, "policy_ok": r.passed}
    layer, code = "none", None
    for name, chk in (("carrier", k), ("binding", b), ("evidence", v), ("policy", r)):
        if not chk.passed:
            layer, code = name, chk.failed
            break
    accepted = all(preds.values())
    verdict = "accepted" if accepted else "rejected"
    rp = receipt_payload(packet.get("evidence")) or {}
    action_class = (rp.get("action") or {}).get("class")
    hold_reason = None
    if accepted and state:
        pending = sorted(cl for cl, st in (state.get("claims") or {}).items() if st == "pending")
        high_risk = policy["action_classes"].get(action_class, {}).get("high_risk", False)
        if pending and high_risk:
            verdict, code, hold_reason = "hold", "H01_HOLD_PENDING_REASSESSMENT", f"claims pending: {', '.join(pending)}"
    return {
        "case_id": packet.get("case_id"),
        "receipt_id": rp.get("receipt_id"),
        "action_class": action_class,
        "presented_at": packet.get("presented_at"),
        "appraised_at": now or packet.get("presented_at"),
        "predicates": preds,
        "accepted": accepted,
        "verdict": verdict,
        "first_failure_layer": layer,
        "reason_code": code,
        "reason": describe(code) if code else "all four predicates hold",
        "hold_reason": hold_reason,
        "checks": {"carrier": k.log, "binding": b.log, "evidence": v.log, "policy": r.log},
        "depends_on": depends_on(packet, policy),
        "policy_id": policy["policy_id"],
        "verifier_profile": policy["require_verifier_profile"],
    }
