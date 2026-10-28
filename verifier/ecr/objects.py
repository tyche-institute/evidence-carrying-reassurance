"""Constructors for the signed objects of the evidence-packet profile.

Each constructor returns a plain dict in the canonical subset. Signatures are
detached blocks over the `payload` member. Time is ISO 8601 UTC with a `Z`.
"""

from __future__ import annotations

import uuid
from typing import Any

from . import (
    PROFILE_BROKER,
    PROFILE_COAPPROVAL,
    PROFILE_ENDORSEMENT,
    PROFILE_RECEIPT,
    PROFILE_STATUS,
    PROFILE_TIMESTAMP,
)
from .canon import digest
from .keys import key_id_for, public_key_b64_for, sign

NAMESPACE = uuid.UUID("6f1b3f1e-6a1c-4d7e-9c47-5b1d6a4a2e10")


def urn_uuid(name: str) -> str:
    return "urn:uuid:" + str(uuid.uuid5(NAMESPACE, name))


def endorsement(root_label: str, root_id: str, subject_label: str, subject_id: str,
                issuer_status: str, valid_from: str, valid_until: str) -> dict:
    payload = {
        "profile": PROFILE_ENDORSEMENT,
        "root": root_id,
        "root_key_id": key_id_for(root_label),
        "subject": subject_id,
        "subject_key_id": key_id_for(subject_label),
        "subject_public_key": public_key_b64_for(subject_label),
        "issuer_status": issuer_status,
        "valid_from": valid_from,
        "valid_until": valid_until,
    }
    return {"payload": payload, "signature": sign(payload, root_label)}


def receipt(*, case_name: str, issuer_label: str, issuer_id: str, root_id: str | None,
            endorsements: list[dict], subject: dict | None, delegation: dict, carrier: dict,
            action: dict, runtime: dict, issued_at: str, extra: dict | None = None) -> dict:
    payload: dict[str, Any] = {
        "profile": PROFILE_RECEIPT,
        "receipt_id": urn_uuid("receipt:" + case_name),
        "issued_at": issued_at,
        "issuer": {
            "id": issuer_id,
            "key_id": key_id_for(issuer_label),
            "root": root_id,
            "endorsements": endorsements,
        },
        "delegation": delegation,
        "carrier": carrier,
        "action": action,
        "runtime": runtime,
    }
    if subject is not None:
        payload["subject"] = subject
    if extra:
        payload.update(extra)
    return {"payload": payload, "signature": sign(payload, issuer_label)}


def timestamp_token(receipt_payload: dict, tsa_label: str, tsa_id: str, root_label: str,
                    root_id: str, time: str) -> dict:
    payload = {
        "profile": PROFILE_TIMESTAMP,
        "tsa": tsa_id,
        "root": root_id,
        "time": time,
        "digest": digest(receipt_payload),
        "endorsement": endorsement(root_label, root_id, tsa_label, tsa_id, "active",
                                   "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z"),
    }
    return {"payload": payload, "signature": sign(payload, tsa_label)}


def status_list(source_label: str, source_id: str, issued_at: str, entries: dict) -> dict:
    payload = {
        "profile": PROFILE_STATUS,
        "source": source_id,
        "issued_at": issued_at,
        "entries": entries,
    }
    return {"payload": payload, "signature": sign(payload, source_label)}


def broker_envelope(broker_label: str, broker_id: str, mapping_id: str, mapping: list[dict],
                    normalized: dict, attached_receipt: dict,
                    signed_digest_of: dict | None = None) -> dict:
    """The broker signs its payload, which carries the digest of the receipt it
    normalised. The receipt itself travels unsigned-by-the-broker as
    `attached_receipt`, so a receipt swapped or edited after brokering is
    caught by the digest, not by the broker signature (V07)."""
    payload = {
        "profile": PROFILE_BROKER,
        "broker": broker_id,
        "mapping_id": mapping_id,
        "mapping": mapping,
        "normalized": normalized,
        "attached_receipt_digest": digest(signed_digest_of if signed_digest_of is not None else attached_receipt),
    }
    return {"payload": payload, "signature": sign(payload, broker_label), "attached_receipt": attached_receipt}


def co_approval(receipt_payload: dict, approver_label: str, approver_id: str, approved_at: str) -> dict:
    payload = {
        "profile": PROFILE_COAPPROVAL,
        "approver": approver_id,
        "receipt_payload_digest": digest(receipt_payload),
        "approved_at": approved_at,
    }
    return {"payload": payload, "signature": sign(payload, approver_label)}
