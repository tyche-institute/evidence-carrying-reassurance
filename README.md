# Evidence-carrying re-assurance — reference verifier and evaluation artifact

Companion artifact to the article *Evidence-Carrying Re-Assurance for
Agentic Incident Response* (Anton Sokolov, Tyche Institute, Tallinn).
Version 0.3.1, archived at Zenodo: https://doi.org/10.5281/zenodo.23742865.

The article asks when a relying party should accept an action that an
autonomous agent took on its behalf through a governed data-exchange
carrier, and what it should do with that decision afterwards. Its answer is
a four-predicate acceptance rule:

    Assured(a) = CarrierOK(a) ∧ BindingOK(a) ∧ EvidenceOK(a) ∧ PolicyOK(a)

and a re-assurance discipline: every decision records a digest of each
input slice it read; when an input changes, exactly the decisions whose
digests change are re-appraised. This repository holds the reference
verifier that evaluates the rule, the 68 evidence packets the article's
tables are computed from, the one relying-party policy they are appraised
under, the one observed carrier exchange every packet binds to, the
re-assurance log of a simulated five-week scenario, and the expected
outputs. Every table and every count in the article's evaluation is a file
under `expected/`.

## Headline numbers

Produced by `make all` on the committed tree (`expected/RUN-SUMMARY.json`):

| set | packets | accepted | fail at carrier | at binding | at evidence | at policy |
|---|---|---|---|---|---|---|
| policy cases P01–P24 | 24 | 3 | 2 | 2 | 2 | 15 |
| brokered-evidence fixtures E01–E12 | 12 | 2 | 0 | 2 | 0 | 8 |
| carrier/evidence matrix C01–C18 | 15 executed (3 planned) | 2 | 3 | 5 | 0 | 5 |
| coverage controls N01–N12 | 12 | 0 | 2 | 1 | 7 | 2 |

Baselines on P01–P24 (`expected/baselines.csv`): accepting on the carrier
log alone lets 19 of the 21 rejected packets through; carrier + receipt
verification lets 17 through; carrier + binding + verification lets 15
through; the four-predicate rule lets 0 through. The coverage controls take
no part in the baselines; each exists to reach one reason code.

Reason codes (`expected/reason-codes.csv`): 44 codes; 41 are the first
failure of at least one packet; the other three (B01, V01, R00) cannot be a
first failure by construction and fail in the check log of every packet
that fails upstream.

Re-assurance scenario (`expected/reassurance/`, simulated time, 3 June to
8 July 2026): 3 decisions of the first run, 5 new actions, 9 change events
and 5 evidence attachments. Over the 10 input changes the relying party
held 34 standing decisions in total; the digests selected 7 of them for
re-appraisal: 3 reaffirmed (a status entry re-issued after renewal) and 4
revoked (1 delegation revoked in the status source, R12; 3 decisions whose
runtime profile the policy later withdrew, R21). Re-appraising every
standing decision at every change would have run 34 appraisals and found
the same 4 revocations; never re-appraising would have missed all 4
(`strategies.csv`). One audited decision was frozen and, when the audit
closed, replayed and reaffirmed. Two high-risk actions were held while a
claim was pending and released when the evidence closed it.

## Run it

Python ≥ 3.11 and the `cryptography` package (Ed25519). No network, no
clock, no secrets. Reference run: Python 3.12.3, cryptography 49.0.0,
Ubuntu 24.04.4 LTS.

    make all      # regenerate fixtures, run the verifier, write expected/ and SHA256SUMS
    make check    # verify SHA256SUMS against the tree, then run the 25 tests

`make check` on an untouched checkout passes: the generated tree is
byte-identical on every run because keys derive from fixed labels, ids are
UUIDv5 and all clocks are literals.

To appraise one packet by hand:

    python3 -c "
    import json, sys; sys.path.insert(0, 'verifier')
    from ecr.verify import appraise
    pkt = json.load(open('fixtures/policy-cases/P07_wrong_action_class.json'))
    pol = json.load(open('policy/relying-party-policy.json'))
    d = appraise(pkt, pol)
    print(d['verdict'], d['first_failure_layer'], d['reason_code'], d['reason'])"

## How re-appraisal is selected

Every decision record carries `depends_on`: five SHA-256 digests, each over
the slice of one input that the checks of that packet read (the
accepted-root entries for the roots the issuer asserts, the timestamp-root
entry, the broker registration and the approver pin; the status entry of
the delegation used and the source pin; the allow-list membership of the
receipt's three profile fields; the thresholds and the rule for its action
class; the carrier-configuration membership of its carrier record). When an
input changes, the log recomputes the five digests of every standing
decision under the new inputs and re-appraises those with a changed digest.
A standing decision is the latest decision for a receipt with status
`accepted` or `reaffirmed`; a rejected decision carries no standing claim,
and a held decision is appraised again when the hold is released. The log
also appraises the unselected decisions, as instrumentation only, and
records under `missed` any whose outcome would have changed; the property
test in `tests/test_reassure.py` drives seeded random event sequences over
every table and coverage packet and asserts `missed` stays empty.

## Layout

| path | contents |
|---|---|
| `verifier/ecr/` | the verifier: `canon.py` (RFC 8785 subset), `keys.py` (Ed25519, label-derived), `objects.py` (receipt, endorsement, timestamp, status list, broker envelope, co-approval), `verify.py` (the four predicates, the decision record, `depends_on`), `baselines.py`, `reassure.py` (decision log, digest selection, holds, freezes, replay bundle, strategies), `codes.py` (reason codes), `catalogue.py` (identities, policy, the 71 case definitions) |
| `verifier/gen_fixtures.py` | writes `policy/`, `fixtures/`, `carrier/local-xroad-dev/carrier-record.json` |
| `verifier/run_matrix.py` | appraises every executed packet, runs the scenario, aborts if any observed outcome differs from the intended one, writes `expected/` |
| `policy/relying-party-policy.json` | the relying-party policy `rp-policy:municipal-soc/0.2` |
| `carrier/local-xroad-dev/` | the observed X-Road exchange (`message-binding.json`) and the carrier envelope derived from it |
| `fixtures/` | 68 packets in five families and `index.json` (71 rows: intended outcome, threat, deviations from P01) |
| `expected/` | the tables, decision records, worked examples, traceability matrix, baselines, reason codes and the re-assurance scenario |
| `spec/` | `evidence-packet-profile.md` (field table) and `evidence-packet.schema.json` |
| `tests/test_verifier.py` | 17 tests: canonicalisation, signatures, every table's distribution, every fixture's row, coverage controls, every reason code reached, tamper detection, hold logic, determinism against the committed tree |
| `tests/test_reassure.py` | 8 tests: soundness of digest selection on seeded random event sequences, negative control, per-delegation and per-profile selectivity, policy attached as evidence, hold release, audit replay, the committed scenario |
| `CODEBOOK.md` | columns, codes, families, what the artifact is and is not |

## Provenance of the carrier record

`carrier/local-xroad-dev/message-binding.json` (SHA-256
`2a37ffb62cbc17a38997814ba9c06054abc157c62cdcfe409e23183993e45ba3`) records
one REST exchange on 2026-05-27 through two X-Road Security Servers on a
local development stack assembled from pinned container images
(`ghcr.io/nordic-institute/xrd-*`, X-Road commit
`3c37ca1eced1f0ca46d0171ee0703649db254081`): consumer
`DEV/COM/4321/TestClient` on one server, provider
`DEV/COM/1234/TestService/mock1` on the other. The file carries the X-Road
message id and request id, the SHA-256 of the request payload, response
body and response headers, and the message-log row numbers on both
servers. `carrier-record.json` is derived from it by `gen_fixtures.py`; the
derivation is a field mapping, not a re-run. Its `observed_at` is the UTC
time encoded in the X-Road message id (`…20260527T111419Z`), which the
consumer Security Server assigned at request time.

Every accepted carrier record in `fixtures/` is that record unchanged
(`source.basis` = `observed-local-dev-stack`). The rejected (P19),
validation-unavailable (C12), timestamp-unavailable (C13) and
configuration-mismatch (N01, N02) records are edited copies, marked
`synthetic-negative-control`; their `fault` strings describe the modelled
condition and are not X-Road fault codes. P20 and C16 carry no carrier
record. The scenario packets S01–S05 are time-shifted copies, labelled as
such in `source.basis`. Rows C09–C11 of the matrix are planned
(`future-test-xroad-plan`) and have no packet.

## Keys

Every key in the artifact is synthetic. An Ed25519 private key is derived
as SHA-256 of `ecr-fixture-key:` plus a public label from `catalogue.py`
(`root-municipal-agent-ca`, `issuer-soc`, …); no key material is stored,
and anyone can re-derive every key and mint their own packets. Nothing here
is a credential of any real system.

## What changed from the article's first submission

The first submitted version indexed the 24 cases, the 12 fixtures and the
18-row matrix in hand-labelled tables and named fixture files that were
never released. This artifact replaces those tables with the output of a
verifier run on executable packets. The distributions reproduce the first
version's, with one reclassification: fixtures E06 and E11, which the first
version listed as "do not verify", fail at the binding predicate: the
receipt inside E06 names a carrier message id other than the carrier
record's (B03), and the receipt inside E11 carries a response digest other
than the carrier's (B05). Both receipts verify under their profile. The
count of fixtures that verify but fail policy (8) is unchanged.

Version 0.3.0 (this revision) differs from 0.2.0 in the re-assurance
mechanics: `depends_on` digests are taken over the input slices a decision
read, not over whole inputs; selection compares all five digests at every
input change, including a policy update attached as evidence; frozen
decisions are replayed when an audit closes; the scenario adds a negative
control, a status renewal, an action held during an audit and a withdrawn
runtime profile; `strategies.csv` compares the selection against never
re-appraising and re-appraising everything. It also adds the 12 coverage
controls, checks the scenario packets against the scenario log rather than
the base policy, and renames R19 to `R19_BINDING_AGE_EXCEEDED`.

Version 0.3.1 (revision round 2) adds three comparisons the article's
referees asked for and changes one case. `expected/ablation.csv` removes one
policy rule family at a time from the policy-rejected table packets and
counts which rejections rest on that family alone. `strategies.csv` gains a
fourth row, `whole_input_digest`: selection by a digest over the whole
changed input, without slices, which is what the 0.2.0 verifier did.
`expected/reassurance/sensitivity.csv` runs 100 seeded random sequences of
40 input changes over every executed table and coverage packet and reports,
per seed, standing decisions, slice-selected re-appraisals, outcome changes
and misses (always 0). P07 now carries a listed co-approval, so that its
only failing rule is the scope rule R15 (0.3.0's P07 also failed R16). The
observed carrier record is unchanged, including the message id the exchange
carried.

## Licence and citation

MIT (see `LICENSE`). Cite the article and this repository (`CITATION.cff`).
