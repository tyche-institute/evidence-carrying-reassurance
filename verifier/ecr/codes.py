"""Reason codes. One table, used by the verifier, the codebook and the tables.

Layer prefixes: K carrier, B binding, V evidence, R policy, H hold (re-assurance).
The verifier evaluates the layers in the fixed order K, B, V, R; the first layer
with a failing check is the recorded first-failure layer, and the first failing
check inside that layer is the recorded reason code.
"""

CODES = {
    # carrier
    "K01_CARRIER_RECORD_MISSING": ("carrier", "no carrier record accompanies the action"),
    "K02_CARRIER_REJECTED": ("carrier", "the carrier refused the exchange (fault recorded in the carrier record)"),
    "K03_CARRIER_CONFIG_MISMATCH": ("carrier", "instance, client or service is outside the relying party's accepted carrier configuration"),
    "K04_MESSAGE_LOG_MISSING": ("carrier", "the carrier record carries no message-log reference for both sides of the exchange"),
    "K05_CARRIER_VALIDATION_UNAVAILABLE": ("carrier", "the carrier could not complete certificate-status or timestamping checks; fail closed"),
    # binding
    "B01_NO_CARRIER_RECORD": ("binding", "nothing to bind to: carrier record absent or rejected"),
    "B02_NO_EVIDENCE": ("binding", "nothing to bind: no receipt or envelope accompanies the carrier record"),
    "B03_MESSAGE_ID_MISMATCH": ("binding", "receipt names a different carrier message id than the carrier record"),
    "B04_REQUEST_DIGEST_MISMATCH": ("binding", "receipt request digest differs from the carrier record's request payload digest"),
    "B05_RESPONSE_DIGEST_MISMATCH": ("binding", "receipt response digest differs from the carrier record's response body digest"),
    "B06_BROKER_BINDING_ALTERED": ("binding", "broker normalisation changed a field covered by the binding"),
    # evidence
    "V01_EVIDENCE_MISSING": ("evidence", "no evidence object present"),
    "V02_PROFILE_UNKNOWN": ("evidence", "evidence object does not declare a profile this verifier implements"),
    "V03_REQUIRED_FIELD_MISSING": ("evidence", "a field the profile marks mandatory is absent (for example the agent subject)"),
    "V04_SIGNATURE_INVALID": ("evidence", "issuer signature does not verify over the canonical payload"),
    "V05_ENDORSEMENT_INVALID": ("evidence", "a root endorsement of the issuer key does not verify or does not name the signing key"),
    "V06_BROKER_SIGNATURE_INVALID": ("evidence", "broker signature does not verify over the envelope payload"),
    "V07_BROKER_DIGEST_MISMATCH": ("evidence", "digest of the attached receipt differs from the digest the broker signed"),
    "V08_TIMESTAMP_TOKEN_INVALID": ("evidence", "timestamp token does not verify, or does not cover the receipt payload digest"),
    "V09_STATUS_LIST_INVALID": ("evidence", "status list signature does not verify"),
    "V10_CO_APPROVAL_INVALID": ("evidence", "co-approval does not verify or does not cover the receipt payload digest"),
    # policy (evaluated in this order; first failure is the reason)
    "R00_UPSTREAM_PREDICATE_FAILED": ("policy", "policy appraises only witnessed, bound and verified evidence"),
    "R01_VERIFIER_PROFILE_MISSING": ("policy", "receipt omits the verifier profile the policy requires"),
    "R02_VERIFIER_PROFILE_MISMATCH": ("policy", "receipt names a verifier profile other than the one the policy requires"),
    "R03_ISSUER_ROOT_ABSENT": ("policy", "issuer asserts no root and carries no endorsement; broker assertion does not substitute"),
    "R04_ROOT_NOT_ACCEPTED": ("policy", "issuer root is outside the relying party's accepted-root set"),
    "R05_ROOT_NOT_ACCEPTED_FOR_ACTION": ("policy", "issuer root is accepted, but not for this action class"),
    "R06_ROOT_CONFLICT": ("policy", "two accepted roots assert incompatible issuer status; fail closed"),
    "R07_BROKER_NOT_ACCEPTED": ("policy", "broker or its mapping id is not registered with the relying party"),
    "R08_BROKER_ALIAS_NOT_INJECTIVE": ("policy", "broker mapping sends two issuer identities under different roots to one alias"),
    "R09_STATUS_SOURCE_MISSING": ("policy", "no status list accompanies a delegation that names a status source"),
    "R10_STATUS_SOURCE_NOT_ACCEPTED": ("policy", "status list is signed by a source other than the one policy names"),
    "R11_STATUS_STALE": ("policy", "status list is older than the policy's maximum status age at decision time"),
    "R12_DELEGATION_REVOKED": ("policy", "status source marks the delegation revoked"),
    "R13_DELEGATION_SUSPENDED": ("policy", "status source marks the delegation suspended"),
    "R14_DELEGATION_NOT_VALID_AT_EVENT": ("policy", "delegation validity interval does not contain the carrier event time"),
    "R15_ACTION_OUTSIDE_SCOPE": ("policy", "action class is not in the delegation's scope"),
    "R16_CO_APPROVAL_REQUIRED": ("policy", "action class requires a co-approval that is absent or from an unlisted approver"),
    "R17_TIMESTAMP_ROOT_NOT_ACCEPTED": ("policy", "timestamp root is not accepted for this action class"),
    "R18_CLOCK_SKEW_EXCEEDED": ("policy", "issuer clock and timestamp authority clock differ by more than the tolerance"),
    "R19_BINDING_AGE_EXCEEDED": ("policy", "timestamp time minus carrier event time exceeds the binding age limit (a replayed or late-bound carrier event)"),
    "R20_TIMESTAMP_OUTSIDE_WINDOW": ("policy", "evidence presented later than the freshness window after its timestamp"),
    "R21_RUNTIME_PROFILE_NOT_ALLOWED": ("policy", "model version, tool profile or prompt profile is not in the allowed set"),
    # re-assurance
    "H01_HOLD_PENDING_REASSESSMENT": ("hold", "a claim the action depends on is pending re-assessment and the action class is high-risk"),
}


def layer_of(code: str) -> str:
    return CODES[code][0]


def describe(code: str) -> str:
    return CODES[code][1]
