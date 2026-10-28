# Worked example P07_wrong_action_class

Receipt scoped to read and enrich; the action mutates the case file, with a listed co-approver present, so the scope rule is the only failing rule.

* family: policy-cases; claim strength: synthetic-negative-control; threat: T5
* verdict: **rejected**; first-failure layer: policy; reason: R15_ACTION_OUTSIDE_SCOPE — action class is not in the delegation's scope
* predicates: carrier_ok=True, binding_ok=True, evidence_ok=True, policy_ok=False

## carrier_record

```json
{
  "carrier": "x-road",
  "client": "DEV/COM/4321/TestClient",
  "fault": null,
  "http_status": 200,
  "instance": "DEV",
  "message_id": "tyche-real-run-20260527T111419Z",
  "message_log": {
    "consumer_rows": [
      4,
      5
    ],
    "consumer_security_server": "DEV:COM:4321:SS1",
    "provider_rows": [
      9,
      10
    ],
    "provider_security_server": "DEV:COM:1234:SS0",
    "ss0_logrecord_csv_sha256": "168cd2267b4f82c6b5598573eca51d3e8d051fe9586df65aab7ba0d1b14a364a",
    "ss1_logrecord_csv_sha256": "973b7af0d881352fe6045f583cc60afd9826742635a02786abdef82f7aaefba5"
  },
  "observed_at": "2026-05-27T11:14:19Z",
  "request_hash": "g/UXFVSL4VZq6dO+F/FhlYaJP/JWHT/+diOge5vGHJKF016NrhKs8G/xu1KIxK2IxRRFgK1yhn5jovsRyyP7MA==",
  "request_id": "679b103a-b24c-4076-b49d-15cf2f3a71e6",
  "request_payload_sha256": "822d59bc55cfc3d85555b792ccd6036efa55854b5be71408f078c2e0e4cdac6b",
  "response_body_sha256": "2c7713a2b73cc7821c0e9a9b227565161586e7bad09b19f82c21ff53d65192e8",
  "response_headers_sha256": "2645f8434cafe95aef5104eb03eb41b88ceb58022be7940da02cf6a2967dd4b4",
  "service": "DEV/COM/1234/TestService/mock1",
  "source": {
    "artifact": "carrier/local-xroad-dev/message-binding.json",
    "basis": "observed-local-dev-stack",
    "run_date": "2026-05-27",
    "sha256": "2a37ffb62cbc17a38997814ba9c06054abc157c62cdcfe409e23183993e45ba3",
    "xroad_commit": "3c37ca1eced1f0ca46d0171ee0703649db254081"
  },
  "status": "accepted"
}
```

## evidence

```json
{
  "payload": {
    "action": {
      "class": "mutate",
      "summary": "change the case severity and close the ticket",
      "target": "case-file:INC-2026-0427",
      "tool": "case-file.update"
    },
    "carrier": {
      "carrier": "x-road",
      "message_id": "tyche-real-run-20260527T111419Z",
      "request_digest": "822d59bc55cfc3d85555b792ccd6036efa55854b5be71408f078c2e0e4cdac6b",
      "request_id": "679b103a-b24c-4076-b49d-15cf2f3a71e6",
      "response_digest": "2c7713a2b73cc7821c0e9a9b227565161586e7bad09b19f82c21ff53d65192e8"
    },
    "delegation": {
      "grantee": "urn:agent:municipal-soc:ir-enrichment",
      "grantor": "analyst:mara",
      "id": "del-001",
      "scope": [
        "read",
        "enrich"
      ],
      "status_source": "status:municipal-delegation-registry",
      "valid_from": "2026-05-01T00:00:00Z",
      "valid_until": "2026-06-30T23:59:59Z"
    },
    "issued_at": "2026-05-27T11:14:21Z",
    "issuer": {
      "endorsements": [
        {
          "payload": {
            "issuer_status": "active",
            "profile": "ecr-key-endorsement/0.2",
            "root": "root:municipal-agent-ca",
            "root_key_id": "sha256:24e6ca390ce478fb5970fd2ca7e9a8e686ae6e552235962054bcdcdcc3e121f3",
            "subject": "issuer:soc-agent-platform",
            "subject_key_id": "sha256:2a620b7902b930a04913da724a52b163377f69c74627daa85a01a47a7a21372a",
            "subject_public_key": "09ma0VgVwqdmE2KPJoaEZMVSQ2gfb5XcK1Y97+7rYrs=",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z"
          },
          "signature": {
            "alg": "Ed25519",
            "canon": "RFC8785",
            "key_id": "sha256:24e6ca390ce478fb5970fd2ca7e9a8e686ae6e552235962054bcdcdcc3e121f3",
            "public_key": "Sl7s6ow0KprIfHvB0bmXHdnhk0Ky+ilk4SSQBLLp3SI=",
            "value": "qaZhkv8VRGwkC1nNUD/ZkSRRkZnoiJu3xNnFY6fk6G8BefFD7qA4gJrRSeQPdp/PEbGIo7QuS/OJFNHQ49SHCA=="
          }
        }
      ],
      "id": "issuer:soc-agent-platform",
      "key_id": "sha256:2a620b7902b930a04913da724a52b163377f69c74627daa85a01a47a7a21372a",
      "root": "root:municipal-agent-ca"
    },
    "profile": "ecr-receipt/0.2",
    "receipt_id": "urn:uuid:ff997ca7-45eb-514f-b5e6-2c3bb7c6227a",
    "runtime": {
      "model_version": "ir-enrichment-model/2026.05",
      "prompt_profile_digest": "sha256:1f8f068a2b6927de7a2feeb43037db33c723783e80fc3a420ab4ffbfeafec637",
      "tool_profile_digest": "sha256:b5d760f5e703506dcbee22db276fb1759cb71965df463454b4de9fa980ea523e",
      "verifier_profile": "ecr-verifier/0.2"
    },
    "subject": {
      "agent_id": "urn:agent:municipal-soc:ir-enrichment",
      "runtime_instance": "ir-enrichment-01"
    }
  },
  "signature": {
    "alg": "Ed25519",
    "canon": "RFC8785",
    "key_id": "sha256:2a620b7902b930a04913da724a52b163377f69c74627daa85a01a47a7a21372a",
    "public_key": "09ma0VgVwqdmE2KPJoaEZMVSQ2gfb5XcK1Y97+7rYrs=",
    "value": "5Taf3Wc1TEn+78XEtPHEaj0r6VYZvU/3RlvIhrq6Rp8FPp6Tf/shIAK3pe5Rh/8lAnfi01gpnBinCzFK4rmrDw=="
  }
}
```

## timestamp_token

```json
{
  "payload": {
    "digest": "sha256:4a337e4df1a3d633e9b2d420dad757c9a8550875ffde64dde0e9a92fcd12a410",
    "endorsement": {
      "payload": {
        "issuer_status": "active",
        "profile": "ecr-key-endorsement/0.2",
        "root": "root:municipal-tsa-root",
        "root_key_id": "sha256:d8685def003e4bd9f669f3bd6e77de3ec4878be98fc437cb7b25606b44b53634",
        "subject": "tsa:municipal-tsa",
        "subject_key_id": "sha256:fd5955f9e114bbc1ba0c1141b9e2e8bb76c8f903a0784b1fd7842d3f397c9824",
        "subject_public_key": "t6VkcWl7iKrxcox49hF4/pOcM3Wfy0umOy8R5aj18bg=",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z"
      },
      "signature": {
        "alg": "Ed25519",
        "canon": "RFC8785",
        "key_id": "sha256:d8685def003e4bd9f669f3bd6e77de3ec4878be98fc437cb7b25606b44b53634",
        "public_key": "N+VuhZD+g4sQswWZCH3TRH2c/JIgMh8rkJOqjEHdHeM=",
        "value": "uxFU1j0E2hBaw7pG1pXX1RKMe8W8GjqcJbmglhO0Rl8SJgj+UR97/Yv3Bw02PlzAJb6cZdnzVWC9d6NhkfxvAA=="
      }
    },
    "profile": "ecr-timestamp/0.2",
    "root": "root:municipal-tsa-root",
    "time": "2026-05-27T11:14:22Z",
    "tsa": "tsa:municipal-tsa"
  },
  "signature": {
    "alg": "Ed25519",
    "canon": "RFC8785",
    "key_id": "sha256:fd5955f9e114bbc1ba0c1141b9e2e8bb76c8f903a0784b1fd7842d3f397c9824",
    "public_key": "t6VkcWl7iKrxcox49hF4/pOcM3Wfy0umOy8R5aj18bg=",
    "value": "krIeBcqjTNxys/bwO+kFMiq8rEMEgkpUSpyfWhrlQRRbNVta0qD5XUMwYs3vjyHm9MMKTb9VlpTb4CLZ0eqqCw=="
  }
}
```

## status_list

```json
{
  "payload": {
    "entries": {
      "del-001": {
        "status": "active"
      },
      "del-002": {
        "status": "active"
      },
      "del-003": {
        "since": "2026-05-20T09:00:00Z",
        "status": "revoked"
      },
      "del-004": {
        "since": "2026-05-26T16:00:00Z",
        "status": "suspended"
      },
      "del-005": {
        "status": "active"
      },
      "del-006": {
        "status": "active"
      }
    },
    "issued_at": "2026-05-27T11:00:00Z",
    "profile": "ecr-status-list/0.2",
    "source": "status:municipal-delegation-registry"
  },
  "signature": {
    "alg": "Ed25519",
    "canon": "RFC8785",
    "key_id": "sha256:aff5b5ee4a5535e904f5fde7c710937597d677685b0430a377d18d45a3ff5b43",
    "public_key": "BnpYYALYIbXBFrXhPqM24Zq/Vd5oN2GRTazZUVWmnD8=",
    "value": "BE0APs4NlTe31bX2ZFqrJ1vrZH4drcmEqDt0Seq18r0QzxMODfUAlR7GRUob+rCQwqKpdzjX4J7U0nzUXkERCA=="
  }
}
```

## co_approval

```json
{
  "payload": {
    "approved_at": "2026-05-27T11:14:21Z",
    "approver": "approver:soc-lead",
    "profile": "ecr-co-approval/0.2",
    "receipt_payload_digest": "sha256:4a337e4df1a3d633e9b2d420dad757c9a8550875ffde64dde0e9a92fcd12a410"
  },
  "signature": {
    "alg": "Ed25519",
    "canon": "RFC8785",
    "key_id": "sha256:32660c216038aa8ce4f71d221275573fdf130321c921482cf90697bc9658d25c",
    "public_key": "ejAfRZfdeEV2Mkk6u/yZPp1XutH/6KsXJOwj1s7v6uU=",
    "value": "Aw9je7rybH+wwpIEoswyOLStwEGyYK2soKQTrMuRgLGrSus6IVdknj5fp2GJ3OfDJS9Nv+EGh+WhXqmUQ8KLBQ=="
  }
}
```

## check log

| layer | check | result | detail |
|---|---|---|---|
| carrier | K01_CARRIER_RECORD_MISSING | pass | carrier record present |
| carrier | K02_CARRIER_REJECTED | pass | carrier status accepted |
| carrier | K03_CARRIER_CONFIG_MISMATCH | pass | DEV DEV/COM/4321/TestClient -> DEV/COM/1234/TestService/mock1 |
| carrier | K04_MESSAGE_LOG_MISSING | pass | provider rows [9, 10], consumer rows [4, 5] |
| carrier | K05_CARRIER_VALIDATION_UNAVAILABLE | pass | validation and timestamping chains available |
| binding | B01_NO_CARRIER_RECORD | pass | carrier record accepted |
| binding | B02_NO_EVIDENCE | pass | evidence object present |
| binding | B03_MESSAGE_ID_MISMATCH | pass | tyche-real-run-20260527T111419Z |
| binding | B04_REQUEST_DIGEST_MISMATCH | pass | 822d59bc55cfc3d85555b792ccd6036efa55854b5be71408f078c2e0e4cdac6b |
| binding | B05_RESPONSE_DIGEST_MISMATCH | pass | 2c7713a2b73cc7821c0e9a9b227565161586e7bad09b19f82c21ff53d65192e8 |
| binding | B06_BROKER_BINDING_ALTERED | skip | direct receipt |
| evidence | V01_EVIDENCE_MISSING | pass | evidence object present |
| evidence | V02_PROFILE_UNKNOWN | pass | ecr-receipt/0.2 |
| evidence | V03_REQUIRED_FIELD_MISSING | pass | all mandatory fields present |
| evidence | V04_SIGNATURE_INVALID | pass | issuer signature verifies; key_id matches issuer.key_id |
| evidence | V05_ENDORSEMENT_INVALID | pass | 1 endorsement(s) verify |
| evidence | V06_BROKER_SIGNATURE_INVALID | skip | direct receipt |
| evidence | V07_BROKER_DIGEST_MISMATCH | skip | direct receipt |
| evidence | V08_TIMESTAMP_TOKEN_INVALID | pass | tsa:municipal-tsa at 2026-05-27T11:14:22Z over receipt payload digest |
| evidence | V09_STATUS_LIST_INVALID | pass | status:municipal-delegation-registry issued 2026-05-27T11:00:00Z |
| evidence | V10_CO_APPROVAL_INVALID | pass | approver:soc-lead |
| policy | R00_UPSTREAM_PREDICATE_FAILED | pass | carrier, binding and evidence predicates hold |
| policy | R01_VERIFIER_PROFILE_MISSING | pass | ecr-verifier/0.2 |
| policy | R02_VERIFIER_PROFILE_MISMATCH | pass | ecr-verifier/0.2 |
| policy | R03_ISSUER_ROOT_ABSENT | pass | root:municipal-agent-ca |
| policy | R04_ROOT_NOT_ACCEPTED | pass | root:municipal-agent-ca |
| policy | R05_ROOT_NOT_ACCEPTED_FOR_ACTION | pass | root:municipal-agent-ca accepted for mutate |
| policy | R06_ROOT_CONFLICT | pass | accepted roots agree: issuer active |
| policy | R07_BROKER_NOT_ACCEPTED | skip | direct receipt |
| policy | R08_BROKER_ALIAS_NOT_INJECTIVE | skip | direct receipt |
| policy | R09_STATUS_SOURCE_MISSING | pass | status list present |
| policy | R10_STATUS_SOURCE_NOT_ACCEPTED | pass | status:municipal-delegation-registry |
| policy | R11_STATUS_STALE | pass | status age 979 s <= 3600 s |
| policy | R12_DELEGATION_REVOKED | pass | del-001 active |
| policy | R13_DELEGATION_SUSPENDED | pass | del-001 active |
| policy | R14_DELEGATION_NOT_VALID_AT_EVENT | pass | 2026-05-01T00:00:00Z..2026-06-30T23:59:59Z contains 2026-05-27T11:14:19Z |
| policy | R15_ACTION_OUTSIDE_SCOPE | fail | mutate not in ['read', 'enrich'] |
| policy | R16_CO_APPROVAL_REQUIRED | pass | co-approval by approver:soc-lead |
| policy | R17_TIMESTAMP_ROOT_NOT_ACCEPTED | pass | root:municipal-tsa-root |
| policy | R18_CLOCK_SKEW_EXCEEDED | pass | /issued_at - tsa.time/ = 1 s <= 30 s |
| policy | R19_BINDING_AGE_EXCEEDED | pass | tsa.time - carrier.observed_at = 3 s <= 600 s |
| policy | R20_TIMESTAMP_OUTSIDE_WINDOW | pass | presented_at - tsa.time = 117 s <= 900 s |
| policy | R21_RUNTIME_PROFILE_NOT_ALLOWED | pass | ir-enrichment-model/2026.05 |

## decision record (depends_on digests)

```json
{
  "carrier_config": "sha256:552515653da93e3a6a7e4f278fde4d9bc63ff8a78c99da3fe0ab9b41e7a7c7b3",
  "policy_parameters": "sha256:c297e67b21eac9c33b037b0a076ae873f0542fa62345aab150c78a22b7c06a95",
  "runtime_profile": "sha256:037b82a0aac2c86c6df000c6813bda918d8c458be47c3ca32e39053a76fd9925",
  "status": "sha256:98f0c946f5294794460a5916dece24d7763ea3e6e3c124b90688db32371ad2c5",
  "trust_anchors": "sha256:9cf3da9973bdbc604df4eee76ba7df11d975d0a338934a6bd9418e1f31a5a44c"
}
```
