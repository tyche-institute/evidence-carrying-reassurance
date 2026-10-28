"""Evidence-carrying re-assurance: reference verifier and fixture generator.

The package implements the four-predicate appraisal described in the article
(CarrierOK, BindingOK, EvidenceOK, PolicyOK), the re-assurance mechanics
(decision log, change events, digest-selected re-appraisal,
hold-pending-reassessment), the weaker baseline rules, and a deterministic
generator for the policy cases, brokered-evidence fixtures, carrier/evidence
matrix rows, coverage controls and scenario packets.

Everything is deterministic: keys are derived from fixed labels, clocks are
fixed, identifiers are UUIDv5 of the case id. Running the generator twice
yields byte-identical fixtures.
"""

__version__ = "0.3.1"
PROFILE_RECEIPT = "ecr-receipt/0.2"
PROFILE_ENDORSEMENT = "ecr-key-endorsement/0.2"
PROFILE_TIMESTAMP = "ecr-timestamp/0.2"
PROFILE_STATUS = "ecr-status-list/0.2"
PROFILE_BROKER = "ecr-broker-envelope/0.2"
PROFILE_COAPPROVAL = "ecr-co-approval/0.2"
PROFILE_VERIFIER = "ecr-verifier/0.2"
