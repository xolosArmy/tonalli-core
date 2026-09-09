# RFC 0001: Tonalli Core Network Domain v1.1 Specification

- **Status**: DRAFT / REVIEW (Strictly Documentary — No Runtime Code Modified)
- **Date**: 2026-09-09
- **Author**: xolosArmy Architecture Working Group
- **Target Repository**: `tonalli-core` (PR #3)
- **Related Program**: Agentes → x402 Security Gates (Gate 2A, Gate 2B, Gate 3)

---

## 1. Context and Motivation

In Tonalli Core v1.0 (frozen at commit `cfe4cb1575b22ed258565717c000ac535aa98c67`), the schemas `agentIntentV1Schema` and `x402ApprovalContextV1Schema` rigidly define the network identifier as:

```ts
network: z.literal("xec:mainnet")
```

Similarly, eCash address validation is pinned strictly to the lowercase `ecash:` prefix with the canonical CashAddr baseline pattern:

```ts
const ecashAddress = z
  .string()
  .regex(/^ecash:[qp][a-z0-9]{41,}$/, "expected a lowercase prefixed eCash address");
```

While this design achieved complete security hardening and zero ambiguity for mainnet operations in Gate 1, it introduces a hard blocker for end-to-end integration testing in local regtest environments (`BLOCKED_BY_CORE_NETWORK_DOMAIN`).

This RFC defines the normative specification for evolving Tonalli Core to v1.1, resolving the 12 canonical architectural points required before any test can be qualified as real regtest execution.

---

## 2. The 12 Canonical Decision Points

### Point 1: Contract Versioning Semantic Strategy (Discriminated Multi-Version Family)

**Decision**: The change belongs to minor release **`1.1`** using an **unequivocal discriminated multi-version schema family**, NOT an in-place mutation of `z.literal("1.0")`.

**Rationale & Specification**:
- Modifying `z.literal("1.0")` directly to `z.literal("1.1")` while asserting backward compatibility is technically invalid, because any parser requiring `"1.1"` will immediately reject valid `"1.0"` envelopes with `invalid_literal`.
- Core v1.1 defines explicit discriminated versions:
  ```ts
  export const AGENTIC_CONTRACT_VERSIONS = ["1.0", "1.1"] as const;
  export type AgenticContractVersion = (typeof AGENTIC_CONTRACT_VERSIONS)[number];
  ```
- **Frozen v1.0 Schemas**: Remain unmodified and continue to enforce `contractVersion: z.literal("1.0")` and `network: z.literal("xec:mainnet")`.
- **v1.1 Schemas**: Define `contractVersion: z.literal("1.1")` and allow `network: z.enum(["xec:mainnet", "xec:regtest"])`.
- **Unified Canonical Parsers**:
  ```ts
  export function parseAgentIntent(input: unknown): AgentIntentV1 | AgentIntentV1_1 {
    // Discriminate based on input.contractVersion:
    // If "1.0", parse using agentIntentV1Schema.
    // If "1.1", parse using agentIntentV1_1Schema.
  }
  ```
- This ensures that legacy v1.0 payloads remain parseable without mutation, while v1.0-only nodes safely reject v1.1 payloads at the parser boundary with `invalid_enum_value`.

---

### Point 2: Exact Canonical Network Identifiers

**Decision**: The exact normative string literal for regtest is:
```ts
"xec:regtest"
```

The supported network enum in v1.1 shall be defined as:
```ts
export const SUPPORTED_NETWORKS = ["xec:mainnet", "xec:regtest"] as const;
export type SupportedNetwork = (typeof SUPPORTED_NETWORKS)[number];
export const networkSchema = z.enum(SUPPORTED_NETWORKS);
```

---

### Point 3: Scope of Testnet (`xec:testnet`)

**Decision**: **`xec:testnet` is deferred and EXCLUDED from v1.1 scope.**

**Rationale**:
- eCash infrastructure relies primarily on local regtest for automated, deterministic, sealed CI/CD environments. Public testnets are subject to external reorgs, faucet exhaustion, and prefix inconsistencies.
- Including testnet at this stage would enlarge the attack surface and require additional prefix bindings without providing immediate value to the Agentes → x402 program.
- If needed in the future, testnet can be introduced in v1.2 under the same binding rules.

---

### Point 4: Valid Address Prefixes and Normative CashAddr Validation

**Decision**: Address validation consists of a two-stage gate: initial lexical regex filtering followed by canonical CashAddr decoding and checksum verification.

#### Stage 1: Initial Lexical Filter
The baseline pattern in Core v1.0 is `^ecash:[qp][a-z0-9]{41,}$`. In v1.1, prefix validation is strictly coupled to the network domain:

| Network Domain | Address Type | Canonical Prefix | Regular Expression |
| :--- | :--- | :--- | :--- |
| `xec:mainnet` | Base32 CashAddr | `ecash:` | `^ecash:[qp][a-z0-9]{41,}$` |
| `xec:regtest` | Base32 CashAddr | `ecregtest:` | `^ecregtest:[qp][a-z0-9]{41,}$` |

#### Stage 2: Canonical CashAddr Decoded Checksum Verification
Regex pattern matching alone is NOT sufficient for canonical address validation. Normative validation MUST execute:
1. **Base32 Character Validation**: Ensures all characters after the colon belong strictly to the CashAddr charset `qpzry9x8gf2tvdw0s3jn54khce6mua7l`.
2. **Prefix Polynomial Checksum**: Verifies the 40-bit BCH polynomial checksum using the network-specific prefix (`ecash` or `ecregtest`) converted to 5-bit integer streams, separated by zero, and yielding a polynomial remainder of `1`.
3. **Payload Type & Size Check**: Verifies that the decoded payload represents a canonical 20-byte hash160 (type 0 for P2PKH, type 1 for P2SH) or an explicitly supported script type.

Any address that fails either Stage 1 or Stage 2 MUST be rejected with `INVALID_CASHADDR_CHECKSUM` or `NETWORK_ADDRESS_PREFIX_MISMATCH`.

---

### Point 5: Mandatory Cross-Field Network Binding

**Decision**: Cross-field consistency MUST be enforced at schema validation time via Zod `superRefine`:

1. **Intent Network vs Addresses**:
   - If `intent.network === "xec:mainnet"`, both `intent.fromAddress` and `intent.toAddress` MUST begin with `ecash:` and pass mainnet CashAddr checksum validation.
   - If `intent.network === "xec:regtest"`, both `intent.fromAddress` and `intent.toAddress` MUST begin with `ecregtest:` and pass regtest CashAddr checksum validation.
2. **Intent Network vs x402 Context**:
   - If `x402` context is present, `intent.network === x402.network` is **MANDATORY**. Mismatch throws `X402_NETWORK_MISMATCH`.
   - `x402.payTo` MUST begin with the prefix corresponding to `intent.network`.
   - `x402.payTo` MUST strictly match `intent.toAddress`.
   - `x402.amountSats` MUST strictly match `intent.amountSats`.

---

### Point 6: Strict Rejection of Cross-Network Combinations

**Decision**: Schema validation MUST fail closed with specific error codes upon any network mismatch:

- An intent with `network: "xec:regtest"` and `toAddress: "ecash:..."` is **FATAL** (`NETWORK_ADDRESS_PREFIX_MISMATCH`).
- An intent with `network: "xec:mainnet"` and `fromAddress: "ecregtest:..."` is **FATAL** (`NETWORK_ADDRESS_PREFIX_MISMATCH`).
- An envelope with `intent.network: "xec:mainnet"` and `x402.network: "xec:regtest"` is **FATAL** (`X402_NETWORK_MISMATCH`).

No automatic address translation, cross-network forwarding, or prefix conversion is permitted at any layer.

---

### Point 7: Backward Compatibility with Core v1.0

**Decision**: Complete forward and backward compatibility for `xec:mainnet`:

- Any valid v1.0 `AgentIntentV1`, `CaePolicyDecisionV1`, `WalletApprovalRequestV1`, or `HumanApprovalV1` payload created under v1.0 continues to be parsed successfully by v1.1.
- Consumers written for v1.0 encountering a `xec:regtest` payload will reject it safely at the parser boundary with `invalid_enum_value`, preventing accidental processing of testnet/regtest funds on mainnet-only systems.

---

### Point 8: Protocol Negotiation and Downgrade Rejection

**Decision**:
- Clients and services advertise supported contract versions during connection establishment.
- A v1.1-aware agent or wallet operating in a regtest environment MUST REJECT any attempt to downgrade to v1.0.
- Silent fallback from `xec:regtest` to `xec:mainnet` (or vice-versa) is strictly prohibited. If a node or wallet does not recognize `xec:regtest`, the operation fails closed immediately.

---

### Point 9: Required Changes in RMZWallet Canonical Binary Codec & Handoff

**Decision**:
- The `agentWalletHandoff` module in `RMZWallet` is a **canonical binary serialization codec** (`encodeAgentWalletHandoffV1` / `decodeAgentWalletHandoffV1` using fixed magic `TNL1\x00\x01`, length-prefixed ASCII/UTF-8 fields, and big-endian numerical values). It is NOT CBOR and NOT arbitrary JSON.
- The binary encoder/decoder will be updated in v1.1 to permit `xec:regtest` and `contractVersion: "1.1"` in addition to `"1.0"`.
- Content hash computation $H(E,C)$ continues using the exact normative universal authorization domain:
  `tonalli.authorization/content-hash/v1`
  operating over the canonical byte stream of the envelope $E$ and the binary handoff bytes $C$. The network field is naturally covered within the serialized bytes of $C$, preserving cryptographic binding without altering the hash scheme.

---

### Point 10: Complete Verifiable Golden Test Vectors (R1–R4)

Core v1.1 introduces normative golden vectors with complete JSON payloads, canonical binary lengths, exact hexadecimal bytes, and SHA-256 hashes.

#### Vector R1: Regtest Minimal Sat Payment
- **Description**: Minimum 1 satoshi payment on `xec:regtest`.
- **JSON Payload**:
```json
{
  "contractVersion": "1.1",
  "kind": "wallet_approval_request",
  "requestId": "req-regtest-r1-001",
  "purpose": "xec_payment",
  "intent": {
    "contractVersion": "1.1",
    "kind": "agent_intent",
    "intentId": "intent-regtest-r1-001",
    "nonce": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NQ",
    "agentId": "agent-regtest-001",
    "agentRole": "service_executor",
    "network": "xec:regtest",
    "fromAddress": "ecregtest:qz2708636snqhsxu8wnlka78h6fdp77ar5r569dklm0",
    "toAddress": "ecregtest:qp3wjpa3tjlj042z2wv7hahvd8whzgcwvutgqw8y6h",
    "amountSats": "1",
    "reason": "Regtest minimal payment test",
    "createdAt": 1770000000,
    "expiresAt": 1770000300
  },
  "policyDecision": {
    "contractVersion": "1.1",
    "kind": "cae_policy_decision",
    "decisionId": "cae-regtest-r1-001",
    "intentId": "intent-regtest-r1-001",
    "decision": "needs_human_approval",
    "reasonCode": "REGTEST_MANUAL_REVIEW",
    "reason": "Regtest integration review check",
    "policyTraceId": "trace-regtest-r1-001",
    "policyVersion": "regtest-constitution-v1.1",
    "evaluatedAt": 1770000001,
    "expiresAt": 1770000300
  },
  "requestedAt": 1770000002,
  "expiresAt": 1770000300
}
```
- **Canonical Binary Length**: `582 bytes`
- **SHA-256 of Canonical Binary Handoff ($C$)**:
  `7bf31650852ffbf11ec68034c52e205dfd99a1191d07661c69c88d08e472ce22`
- **Canonical Binary Hex**:
  `544e4c3100010003312e31001777616c6c65745f617070726f76616c5f72657175657374000b7865635f7061796d656e7400127265712d726567746573742d72312d3030310003312e31000c6167656e745f696e74656e740015696e74656e742d726567746573742d72312d303031001e4d4445794d7a51314e6a63344f5746695932526c5a6a41784d6a4d304e5100116167656e742d726567746573742d3030310010736572766963655f6578656375746f72000b7865633a7265677465737400356563726567746573743a717a32373038363336736e716873787538776e6c6b6137386836666470373761723572353639646b6c6d3000346563726567746573743a717033776a706133746a6c6a3034327a3277763768616876643877687a67637776757467717738793668000131001c52656774657374206d696e696d616c207061796d656e742074657374000000000069800e800000000069800fac0003312e3100136361655f706f6c6963795f6465636973696f6e00126361652d726567746573742d72312d3030310015696e74656e742d726567746573742d72312d30303100146e656564735f68756d616e5f617070726f76616c0015524547544553545f4d414e55414c5f52455649455700205265677465737420696e746567726174696f6e2072657669657720636865636b001474726163652d726567746573742d72312d3030310019726567746573742d636f6e737469747574696f6e2d76312e310000000069800e810000000069800fac000000000069800e820000000069800fac`

---

#### Vector R2: Regtest x402 End-to-End Payment Context
- **Description**: Vector R1 extended with explicit `x402ApprovalContextV1` in `xec:regtest`.
- **JSON Payload**:
```json
{
  "contractVersion": "1.1",
  "kind": "wallet_approval_request",
  "requestId": "req-regtest-r2-001",
  "purpose": "xec_payment",
  "intent": {
    "contractVersion": "1.1",
    "kind": "agent_intent",
    "intentId": "intent-regtest-r1-001",
    "nonce": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NQ",
    "agentId": "agent-regtest-001",
    "agentRole": "service_executor",
    "network": "xec:regtest",
    "fromAddress": "ecregtest:qz2708636snqhsxu8wnlka78h6fdp77ar5r569dklm0",
    "toAddress": "ecregtest:qp3wjpa3tjlj042z2wv7hahvd8whzgcwvutgqw8y6h",
    "amountSats": "1",
    "reason": "Regtest minimal payment test",
    "createdAt": 1770000000,
    "expiresAt": 1770000300
  },
  "policyDecision": {
    "contractVersion": "1.1",
    "kind": "cae_policy_decision",
    "decisionId": "cae-regtest-r1-001",
    "intentId": "intent-regtest-r1-001",
    "decision": "needs_human_approval",
    "reasonCode": "REGTEST_MANUAL_REVIEW",
    "reason": "Regtest integration review check",
    "policyTraceId": "trace-regtest-r1-001",
    "policyVersion": "regtest-constitution-v1.1",
    "evaluatedAt": 1770000001,
    "expiresAt": 1770000300
  },
  "x402": {
    "contractVersion": "1.1",
    "kind": "x402_approval_context",
    "paymentContextId": "ctx-regtest-r2-001",
    "resourceUri": "https://api.regtest.tonalli.app/v1/resource",
    "payTo": "ecregtest:qp3wjpa3tjlj042z2wv7hahvd8whzgcwvutgqw8y6h",
    "amountSats": "1",
    "network": "xec:regtest",
    "challengeNonce": "Y2hhbGxlbmdlX25vbmNlX3JlZ3Rlc3RfMDAx",
    "expiresAt": 1770000300
  },
  "requestedAt": 1770000002,
  "expiresAt": 1770000300
}
```
- **Canonical Binary Length**: `791 bytes`
- **SHA-256 of Canonical Binary Handoff ($C$)**:
  `1127269e1b76b1709143f9857476d8d0234d992d28f23a9d8955ce723f6da127`
- **Canonical Binary Hex**:
  `544e4c3100010003312e31001777616c6c65745f617070726f76616c5f72657175657374000b7865635f7061796d656e7400127265712d726567746573742d72322d3030310003312e31000c6167656e745f696e74656e740015696e74656e742d726567746573742d72312d303031001e4d4445794d7a51314e6a63344f5746695932526c5a6a41784d6a4d304e5100116167656e742d726567746573742d3030310010736572766963655f6578656375746f72000b7865633a7265677465737400356563726567746573743a717a32373038363336736e716873787538776e6c6b6137386836666470373761723572353639646b6c6d3000346563726567746573743a717033776a706133746a6c6a3034327a3277763768616876643877687a67637776757467717738793668000131001c52656774657374206d696e696d616c207061796d656e742074657374000000000069800e800000000069800fac0003312e3100136361655f706f6c6963795f6465636973696f6e00126361652d726567746573742d72312d3030310015696e74656e742d726567746573742d72312d30303100146e656564735f68756d616e5f617070726f76616c0015524547544553545f4d414e55414c5f52455649455700205265677465737420696e746567726174696f6e2072657669657720636865636b001474726163652d726567746573742d72312d3030310019726567746573742d636f6e737469747574696f6e2d76312e310000000069800e810000000069800fac010003312e310015783430325f617070726f76616c5f636f6e7465787400126374782d726567746573742d72322d303031002b68747470733a2f2f6170692e726567746573742e746f6e616c6c692e6170702f76312f7265736f7572636500346563726567746573743a717033776a706133746a6c6a3034327a3277763768616876643877687a67637776757467717738793668000131000b7865633a726567746573740024593268686247786c626d646c58323576626d4e6c58334a6c5a33526c633352664d4441780000000069800fac0000000069800e820000000069800fac`

---

#### Vector R3: Regtest BigInt Precision Preservation (40 digits)
- **Description**: BigInt satoshi amount matching Core Golden Vector B3 under `xec:regtest`.
- **JSON Payload**:
```json
{
  "contractVersion": "1.1",
  "kind": "wallet_approval_request",
  "requestId": "req-regtest-r3-001",
  "purpose": "xec_payment",
  "intent": {
    "contractVersion": "1.1",
    "kind": "agent_intent",
    "intentId": "intent-regtest-r3-001",
    "nonce": "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NQ",
    "agentId": "agent-regtest-001",
    "agentRole": "service_executor",
    "network": "xec:regtest",
    "fromAddress": "ecregtest:qz2708636snqhsxu8wnlka78h6fdp77ar5r569dklm0",
    "toAddress": "ecregtest:qp3wjpa3tjlj042z2wv7hahvd8whzgcwvutgqw8y6h",
    "amountSats": "1234567890123456789012345678901234567890",
    "reason": "Regtest minimal payment test",
    "createdAt": 1770000000,
    "expiresAt": 1770000300
  },
  "policyDecision": {
    "contractVersion": "1.1",
    "kind": "cae_policy_decision",
    "decisionId": "cae-regtest-r3-001",
    "intentId": "intent-regtest-r3-001",
    "decision": "needs_human_approval",
    "reasonCode": "REGTEST_MANUAL_REVIEW",
    "reason": "Regtest integration review check",
    "policyTraceId": "trace-regtest-r1-001",
    "policyVersion": "regtest-constitution-v1.1",
    "evaluatedAt": 1770000001,
    "expiresAt": 1770000300
  },
  "requestedAt": 1770000002,
  "expiresAt": 1770000300
}
```
- **Monetary Formatting**: `12345678901234567890123456789012345678.90 XEC`
- **Canonical Binary Length**: `621 bytes`
- **SHA-256 of Canonical Binary Handoff ($C$)**:
  `70eee17132ab45dc5dca613affab75a6e9d4f077ebef055fb0182232b9b68d84`
- **Canonical Binary Hex**:
  `544e4c3100010003312e31001777616c6c65745f617070726f76616c5f72657175657374000b7865635f7061796d656e7400127265712d726567746573742d72332d3030310003312e31000c6167656e745f696e74656e740015696e74656e742d726567746573742d72332d303031001e4d4445794d7a51314e6a63344f5746695932526c5a6a41784d6a4d304e5100116167656e742d726567746573742d3030310010736572766963655f6578656375746f72000b7865633a7265677465737400356563726567746573743a717a32373038363336736e716873787538776e6c6b6137386836666470373761723572353639646b6c6d3000346563726567746573743a717033776a706133746a6c6a3034327a3277763768616876643877687a67637776757467717738793668002831323334353637383930313233343536373839303132333435363738393031323334353637383930001c52656774657374206d696e696d616c207061796d656e742074657374000000000069800e800000000069800fac0003312e3100136361655f706f6c6963795f6465636973696f6e00126361652d726567746573742d72332d3030310015696e74656e742d726567746573742d72332d30303100146e656564735f68756d616e5f617070726f76616c0015524547544553545f4d414e55414c5f52455649455700205265677465737420696e746567726174696f6e2072657669657720636865636b001474726163652d726567746573742d72312d3030310019726567746573742d636f6e737469747574696f6e2d76312e310000000069800e810000000069800fac000000000069800e820000000069800fac`

---

#### Vector R4: Cross-Network Mismatch Negative Vector (Rejection)
- **Description**: Proves deterministic failure when network domain does not match address prefix.
- **Payload under test**:
  - `intent.network`: `"xec:regtest"`
  - `intent.toAddress`: `"ecash:qp3wjpa3tjlj042z2wv7hahvd8whzgcwvue2swknmw"` (Mainnet address on regtest network)
- **Expected Parser Behavior**:
  - Throws schema validation error with `NETWORK_ADDRESS_PREFIX_MISMATCH`.
  - Canonical handoff codec throws `INVALID_VALUE` and refuses to encode wire bytes.

---

### Point 11: Controlled REGTEST Budgets & Security Policies

**Decision**: The concept of "unconstrained or freely simulated funds" is explicitly rejected. In its place, REGTEST environments MUST enforce deterministic, controlled policy boundaries:

1. **Controlled Budgets**:
   - `REGTEST_DAILY_LIMIT_SATS`: 10,000,000 sats (100,000 XEC).
   - `REGTEST_MAX_TX_SATS`: 1,000,000 sats (10,000 XEC).
2. **Deterministic Operator Arming**:
   - `AGENTIC_KILL_SWITCH = true` by default across ALL environments (Mainnet and Regtest).
   - Autonomous execution on regtest requires explicit, timed operator unsetting of the kill switch.
3. **CAE Policy Traceability**:
   - Even in local regtest, every approval request MUST carry a non-empty `policyTraceId` and `policyVersion`.
   - CAE policy evaluation engines must enforce thresholds before presenting human review.
4. **Visual UI Distinction**:
   - Wallet UI MUST display prominent visual markers (e.g. `REGTEST (SEALED ENVIRONMENT)`) to ensure human operators never conflate regtest requests with mainnet financial actions.

---

### Point 12: Migration Strategy Preserving Core v1.0 FROZEN Baseline

**Decision**:
1. This RFC PR is **DOCUMENTARY ONLY**. No runtime code files (`src/**/*.ts`) are modified in this PR.
2. Core v1.0 remains FROZEN and untainted at Git tag `v1.0.0` / commit `cfe4cb1575b22ed258565717c000ac535aa98c67`.
3. Once this RFC is approved by all stakeholders, an implementation branch `feature/network-domain-v1.1` will be branched from `main`.
4. The implementation will be tagged as `v1.1.0-alpha.1` for consuming repositories to test in staging before any general release.

---

## 3. Implementation Status and Program Guard

Until this RFC is formally reviewed and merged into `tonalli-core`, all repositories MUST adhere to the following rule:

> **NO TEST OR INTEGRATION PASS SHALL BE CHARACTERIZED AS "REAL REGTEST"**.
> All current simulation tests using `xec:mainnet` remain strictly categorized as:
> `schema-only mainnet-shaped simulation under AGENTIC_KILL_SWITCH=true and AGENT_DAILY_LIMIT_SATS=0 without signing or real funds`.
