# Evidence-packet profile `ecr-packet/0.2`

This is the profile the reference verifier implements. It is a profile for
the article's evaluation, not a proposed standard: the field names are
ours, the encodings are the simplest that make every object self-verifying
(RFC 8785 canonical JSON, Ed25519 detached signatures, SHA-256 digests), and
nothing here is a claim about how a production receipt format should look.
Where a field corresponds to an existing format we say so.

A **packet** is what the relying party appraises for one agent action:

| member | M/O | object | who produces it |
|---|---|---|---|
| `carrier_record` | M for CarrierOK | carrier envelope: the exchange as the governed carrier recorded it | carrier (X-Road message log export) |
| `evidence` | M for EvidenceOK | the receipt, or a broker envelope carrying the receipt | issuer; broker |
| `timestamp_token` | M (this policy) | signed time over the receipt payload digest | timestamp authority |
| `status_list` | M when the delegation names a status source (this policy: always) | signed delegation status entries | status source (delegation registry) |
| `co_approval` | O; M for action classes the policy marks `co_approval` | signed human co-approval over the receipt payload digest | approver |
| `presented_at` | M | the moment the relying party appraises the packet | relying party |

## Receipt `ecr-receipt/0.2` (the evidence envelope)

Signed payload. M = mandatory in the profile (absence fails EvidenceOK with
`V03_REQUIRED_FIELD_MISSING`); O = optional in the profile, and the policy
says whether it is required (absence then fails PolicyOK with the rule
named).

| field | M/O | meaning | policy rule if absent or wrong |
|---|---|---|---|
| `profile` | M | `ecr-receipt/0.2` | — |
| `receipt_id` | M | URN, unique per action | — |
| `issued_at` | M | issuer's clock at issuance | R18 (skew against the timestamp authority) |
| `subject.agent_id` | M | stable identity of the acting agent | — (P17 fails at evidence) |
| `subject.runtime_instance` | O | which deployed instance acted | — |
| `issuer.id`, `issuer.key_id` | M | who signed the receipt; `key_id` = SHA-256 of the raw public key | — |
| `issuer.root` | O (nullable) | the root the issuer claims to chain to | R03 if null and policy requires a root |
| `issuer.endorsements[]` | O | root endorsements of the issuer key (`ecr-key-endorsement/0.2`), each signed by the root it names | R03–R06 (accepted root; accepted for the action class; conflict fails closed) |
| `delegation.id` | M | identifier of the delegated authority | — |
| `delegation.grantor`, `.grantee` | M | who delegated to whom (`grantee` = `subject.agent_id`) | — |
| `delegation.scope[]` | M | action classes delegated | R15 |
| `delegation.valid_from`, `.valid_until` | M | validity interval | R14 (must contain the carrier event time) |
| `delegation.status_source` | M | the status source the relying party must consult | R09–R13 |
| `carrier.carrier` | M | carrier family (`x-road`) | — |
| `carrier.message_id`, `.request_id` | M | the carrier's message identifier and request id (X-Road: `x-road-id`, `x-road-request-id`) | B03 |
| `carrier.request_digest` | M | SHA-256 of the request payload | B04 |
| `carrier.response_digest` | M | SHA-256 of the response body | B05 |
| `action.class` | M | `read`, `enrich` or `mutate` | R15, R16 |
| `action.target`, `action.tool` | M | what the action touched and through which tool | — |
| `action.summary` | O | human-readable summary | — |
| `runtime.model_version` | M | model identifier and version | R21 |
| `runtime.tool_profile_digest`, `.prompt_profile_digest` | M | digests of the tool and prompt profiles in force | R21 |
| `runtime.verifier_profile` | O | the verifier profile the issuer targets | R01 (missing), R02 (mismatch) |

Signature block (all signed objects): `{"alg":"Ed25519","canon":"RFC8785","key_id","public_key","value"}`.

## Broker envelope `ecr-broker-envelope/0.2`

| field | M/O | meaning | rule |
|---|---|---|---|
| `payload.broker` | M | broker identity | R07 |
| `payload.mapping_id`, `payload.mapping[]` | M | the registered mapping (issuer, root → alias) the broker applied | R07, R08 (aliases must be injective over (issuer, root)) |
| `payload.normalized` | M | the broker's normalised view: `issuer_alias`, `root`, and the three binding fields | B06 (binding fields must equal the receipt's) |
| `payload.attached_receipt_digest` | M | SHA-256 over the canonical receipt the broker normalised | V07 |
| `attached_receipt` | M | the receipt itself, outside the broker's signature | V04/V05 verify it as a direct receipt |

The broker's `normalized.root` is informational. Policy takes the issuer's
root from the issuer's own endorsement chain (R03); a broker cannot supply a
root the issuer does not carry.

## Timestamp token `ecr-timestamp/0.2`

`tsa`, `root`, `time`, `digest` (over the receipt payload), `endorsement` of
the TSA key by its root. V08 verifies it; R17 (root accepted for the action
class), R18 (skew), R19 (binding age: `time − carrier.observed_at`), R20
(freshness: `presented_at − time`) appraise it. A production deployment
would carry an RFC 3161 token here.

## Status list `ecr-status-list/0.2`

`source`, `issued_at`, `entries{delegation_id → {status, since?}}` with
`status ∈ {active, revoked, suspended}`. V09 verifies the signature; R10
(the source the delegation names, with the policy-pinned key), R11
(`presented_at − issued_at ≤ status_max_age_s`), R12/R13 appraise it.

## Co-approval `ecr-co-approval/0.2`

`approver`, `receipt_payload_digest`, `approved_at`. V10 verifies it; R16
requires it for action classes the policy marks, from an approver the policy
lists.

## Decision record (verifier output)

`predicates{carrier_ok, binding_ok, evidence_ok, policy_ok}`, `accepted`,
`verdict ∈ {accepted, rejected, hold}`, `first_failure_layer`,
`reason_code`, `checks{layer → [check, result, detail]}`, and
`depends_on{trust_anchors, status, runtime_profile, policy_parameters,
carrier_config}`: five SHA-256 digests, each over the slice of one input
that the checks of this packet read (the accepted-root entries for the
roots the issuer asserts, the timestamp-root entry, the broker registration
and the approver pin; the status entry of the delegation used and the
source pin; the allow-list membership of the receipt's three profile
fields; the thresholds and the rule for this action class; the carrier
configuration membership of this carrier record). The re-assurance log
recomputes the five digests for every standing decision when an input
changes and re-appraises exactly the decisions whose digests differ
(`verifier/ecr/reassure.py`; soundness test in `tests/test_reassure.py`).
The policy result the reviewer asked for is this record; it is appended to
the decision log, never written into the receipt.

## Relation to existing formats

* RATS (RFC 9334): the receipt is Evidence; endorsements are Endorsements;
  `policy/relying-party-policy.json` is the Appraisal Policy for Evidence;
  the decision record is the Attestation Result consumed by the relying
  party. EAT (RFC 9711) could carry the receipt payload as claims; we keep
  JSON so the fixtures read without a CBOR decoder.
* SCITT (RFC 9943) and COSE Receipts (RFC 9942): a transparency service
  would register the receipt as a Signed Statement and return a Receipt of
  inclusion; our binding to the carrier message log plays the role the
  inclusion receipt plays for a log, for one exchange rather than a ledger.
* in-toto / Sigstore: an in-toto attestation would carry the same
  subject/predicate split; Sigstore would replace the endorsement chain
  with keyless signing and a transparency log entry.
