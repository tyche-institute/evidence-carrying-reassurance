# Codebook

Companion to the article *Evidence-Carrying Re-Assurance for Agentic
Incident Response*. Every number in the article's evaluation is a row or a
count in `expected/`, produced by `verifier/run_matrix.py` from the packets
in `fixtures/` under `policy/relying-party-policy.json`.

## 1. The appraisal

For one packet the verifier evaluates four predicates, all of them, in this
order, and records the first that fails:

| layer | predicate | checks | claim |
|---|---|---|---|
| carrier | CarrierOK | K01–K05 | G1 carrier witnessed the event |
| binding | BindingOK | B01–B06 | G2 receipt binds to the carrier event |
| evidence | EvidenceOK | V01–V10 | G3 evidence verifies under its profile |
| policy | PolicyOK | R00–R21 | G4 relying-party policy accepts |

`first_failure_layer ∈ {none, carrier, binding, evidence, policy}`;
`reason_code` is the first failing check inside that layer. R00 makes
PolicyOK false whenever an earlier predicate is false, so `policy_ok` is
never true for a packet that is not witnessed, bound and verified. The
reason codes are listed with their meaning in `expected/reason-codes.csv`,
with the cases that exercise each one.

## 2. Files

| path | what |
|---|---|
| `policy/relying-party-policy.json` | the one relying-party policy all tables use: accepted carrier configuration; accepted roots and the action classes each is accepted for; accepted timestamp roots; status sources; brokers and mapping ids; approvers; required verifier profile; `status_max_age_s` 3600; `clock_skew_tolerance_s` 30; `carrier_binding_max_age_s` 600; `freshness_window_s` 900; action classes (`mutate` needs co-approval and is high-risk); allowed runtime profiles |
| `carrier/local-xroad-dev/message-binding.json` | the observed carrier artifact: one REST exchange through two X-Road Security Servers on 2026-05-27 (pinned images and commit inside), SHA-256 `2a37ffb6…45ba3` |
| `carrier/local-xroad-dev/carrier-record.json` | the carrier envelope derived from it (`observed_at` = the time in the X-Road id) |
| `fixtures/index.json` | one row per case: family, description, threat, intended layer and code, the deviations from P01 that define it |
| `fixtures/policy-cases/P01…P24.json` | the 24 policy cases |
| `fixtures/brokered-evidence-fixtures/E01…E12.json` | the 12 brokered-evidence fixtures |
| `fixtures/carrier-evidence-matrix/C01…C18.json` | the 15 executed rows of the carrier/evidence matrix (C09–C11 are planned and have no packet) |
| `fixtures/coverage-controls/N01…N12.json` | the 12 coverage controls, one per reason code that the three tables do not reach as a first failure (deviation and target code in the index) |
| `fixtures/scenario/S01…S05.json` | packets of the re-assurance scenario (time-shifted copies of the observed carrier record, labelled as such); their intended outcomes are checked against the scenario log, not against the base policy |
| `expected/policy-cases.csv` | Table: 24 rows, four predicates, first-failure layer, reason code, threat, mitigation, fixture path and SHA-256 |
| `expected/brokered-evidence-fixtures.csv` | Table: 12 rows, `receipt_verifies` (= EvidenceOK) and `policy_accepts` (= PolicyOK) plus the four predicates |
| `expected/carrier-evidence-matrix.csv` | Table: 18 rows with `basis` and `executed` |
| `expected/coverage-controls.csv` | 12 rows: `target_code`, the four predicates, first-failure layer and code, the deviation that defines the control |
| `expected/first-failure-summary.csv` | the counts per layer per family, with the case ids behind each count |
| `expected/traceability.csv` | threat → case → fixture → first-failure layer/code → mitigation → claim reopened |
| `expected/baselines.csv` | the weaker acceptance rules A0–A3 and the four-predicate rule A4 on the same packets |
| `expected/decisions/<case>.json` | the full decision record per table or coverage packet (check log and `depends_on` digests) |
| `expected/reason-codes.csv` | the 44 codes: `cases` that reach the code as a first failure, `failing_in_decisions` (recorded decisions whose check log shows the code failing), `note` for the three codes that cannot be a first failure |
| `expected/worked-examples/P01_…md`, `P07_…md` | the two worked examples in full |
| `expected/reassurance/` | the scenario: `log.jsonl` (append-only decision log), `records.json` (one record per event or attachment), `summary.csv`, `strategies.csv` (seven strategies, see below), `sensitivity.csv`, `single-changes.csv`, `decisions/S01…S05.json` (first decision of each scenario packet), `replay-bundle-P01.json` |
| `expected/RUN-SUMMARY.json` | the headline numbers the article quotes |
| `SHA256SUMS` | over `carrier/`, `fixtures/`, `policy/`, `expected/`, `spec/`, `verifier/`, `tests/` |

Added in 0.3.1: `expected/ablation.csv` (rule-family ablation over the
policy-rejected table packets; columns: family, codes, description,
policy_rejected_packets, packets_failing_a_rule_of_the_family,
accepted_if_family_removed, accepted_if_family_removed_ids) and
`expected/reassurance/sensitivity.csv` (one row per seeded random sequence;
columns: seed, events, input_changes, standing_total, selected,
whole_input_selected, outcome_changed, missed, selected_share).
`strategies.csv` has a fourth row, `whole_input_digest`.

Added in 0.3.2: `strategies.csv` has seven rows (`static_verdict`,
`reappraise_all`, `whole_input_digest`, `entries_only_digest`,
`keyed_index`, `keyed_index_fallback`, `digest_selected`); every row except
the first two is measured on the standing decisions at each input change.
`sensitivity.csv` gains `entries_only_selected`, `entries_only_missed`,
`keyed_index_selected`, `keyed_index_missed`, `keyed_fallback_selected`,
`keyed_fallback_missed`. `expected/reassurance/single-changes.csv` has one
row per change category and a `total` row; columns: category, changes,
standing_pairs (decision-change pairs), outcome_changed, then `_selected`
and `_missed` for digest selection (`digest_`), the keyed index, the keyed
index with fallback, the entries-only digest and the whole-input digest, and
`keyed_fallback_disagree` (pairs that exactly one of digest selection and
the keyed index with fallback selects). `traceability.csv` includes the
scenario packets (family `scenario`).

## 3. Columns

`policy-cases.csv`, `brokered-evidence-fixtures.csv`, `carrier-evidence-matrix.csv`:

| column | values |
|---|---|
| `case_id` | `P01_…`, `E01_…`, `C01_…` |
| `carrier_ok`, `binding_ok`, `evidence_ok`, `policy_ok` | `True`/`False`, the four predicates |
| `accepted` | all four true |
| `first_failure_layer` | `none`, `carrier`, `binding`, `evidence`, `policy` (`carrier (planned)` for C09–C11) |
| `reason_code` | first failing check in that layer; empty when accepted |
| `reason` | its meaning (from `reason-codes.csv`) |
| `threat_id` | T0 none; T1 tamper/replay; T2 untrusted or aliased roots; T3 broker opacity; T4 stale authority; T5 action-class escalation; T6 carrier failure or unavailability; T7 profile and clock drift; T8 runtime-profile drift (model, tool or prompt changed outside the relying party's control; high-risk action while a claim is pending) |
| `mitigation_id` | M1 binding; M2 profile verification; M3 accepted-root policy; M4 broker registration and injective alias; M5 status source with maximum age; M6 delegation validity, scope, co-approval; M7 timestamp root, skew, binding age, freshness; M8 carrier acceptance; M9 verifier/runtime profile pins; M10 hold while a reopened claim is pending |
| `claim_strength` | `simulation` (a constructed case that could occur in operation), `synthetic-negative-control` (constructed to fail one check), `observed` / `derived` / `planned` for carrier rows |
| `fixture`, `fixture_sha256` | the packet and its digest |
| `receipt_verifies`, `policy_accepts` | (brokered table) = `evidence_ok`, `policy_ok` |
| `basis`, `executed`, `source_artifact`, `source_sha256` | (carrier table) provenance of the carrier record |

`baselines.csv`: `rule`, `predicates` (the conjunction the rule accepts on),
`packets`, `accepted`, `accepted_also_by_full_chain`,
`accepted_but_rejected_by_full_chain` ("let through"), `let_through_ids`.

`reassurance/summary.csv`: one row per event, attachment or new action:
`kind`, `at`, `reopened_claims` (events), `claims_closed` (attachments),
`inputs_changed` (`policy`, `allowed_runtime_profiles`, `status_list`),
`standing` (decisions the relying party still vouches for at that moment),
`selected` (standing decisions with at least one changed `depends_on`
digest; only these are re-appraised and recorded), `outcome_changed`
(standing decisions whose outcome changes under the new inputs, measured by
appraising all of them), `missed` (outcome changed without a digest change;
always 0), `reaffirmed`, `revoked`, `frozen`, `released`, `held_after`,
`claims_pending_after`, `detail`.

`reassurance/strategies.csv`: `strategy` (`static_verdict`,
`reappraise_all`, `digest_selected`), `input_changes`, `re_appraisals`,
`revocations_caught`, `revocations_missed`.

`coverage-controls.csv`: as the three tables, plus `target_code` (the code
the control is built to reach; equals `reason_code`) and `deviation` (the
catalogue spec as JSON). `tamper` entries are post-signature edits of the
finished packet; `endorsement_tamper` edits an endorsement before the
issuer signs the receipt; `carrier_overrides` edits the carrier record.

## 4. How a case is defined

`fixtures/index.json` (71 rows: 24 + 12 + 18 + 12 + 5) records, per case,
`deviations_from_P01`: the keys of `verifier/ecr/catalogue.DEFAULTS` that
the case overrides. P01 is the
accepted baseline: direct issuer `issuer:soc-agent-platform` endorsed by
`root:municipal-agent-ca`; delegation `del-001` (scope read, enrich; status
active); action `enrich`; timestamp from `tsa:municipal-tsa`; receipt issued
2 s after the carrier event, timestamped 1 s later, presented 2 min after
the event; status list issued 14 min before the event. P07 differs from P01
in one key: `action: mutate`.

## 5. Keys and clocks

Keys are Ed25519, derived as SHA-256(`ecr-fixture-key:` + label); the labels
are in `catalogue.py` (`root-municipal-agent-ca`, `issuer-soc`, …). `key_id`
is SHA-256 over the raw public key. No private key is stored; anyone can
re-derive them, which is the point: the fixtures carry no secret, and a
reader can mint their own cases. All clocks are fixed strings; nothing reads
the wall clock. `carrier_record.observed_at` is the UTC time encoded in the
X-Road message id of the observed exchange (`…20260527T111419Z`), which the
consumer Security Server assigned at request time; the message-log rows
carry the same time.

## 6. What the artifact is not

The 24 cases, 12 fixtures, 12 coverage controls and 5 scenario packets are
constructed, not sampled; the coverage controls exist to reach one code
each and take no part in the baseline comparison. The carrier record is one
exchange on a local two-Security-Server development stack, not national
test or production traffic. Fault strings in the rejected carrier records
(`access-denied: …`, `certificate-status-unavailable: …`,
`timestamping-unavailable: …`) describe the modelled condition; they are
not X-Road fault codes. Rows C09–C11 are planned and have no packet.
