# RFC 0001: Tonalli Core Network Domain v1.1 Specification

- **Status**: DRAFT / REVIEW (Strictly Documentary — No Runtime Code Modified)
- **Date**: 2026-09-09
- **Author**: xolosArmy Architecture Working Group
- **Target Repository**: `tonalli-core` (PR #3)
- **Related Program**: Agentes → x402 Security Gates (Gate 2A, Gate 2B, Gate 3)

---

## 1. Context and Motivation

In Tonalli Core, the agentic money contract is currently frozen at contract version `1.0` (commit `cfe4cb1575b22ed258565717c000ac535aa98c67`).

It is vital to distinguish the three separate versioning domains that govern the repository:
1. **Agentic Contract Version**: Currently `1.0` (frozen as `AGENTIC_CONTRACT_VERSION = "1.0"` in `src/agentic/index.ts`).
2. **Repository NPM Package Version**: Currently `0.2.0` (in `package.json`).
3. **Repository Git Tags**: The only existing remote git tag in `tonalli-core` is `v0.1.0`. (Tag `v1.0.0` does not exist).
   Any future npm release versioning (e.g. aligning package versions with contract versions or releasing pre-releases) remains subject to formal governance approval.

In the frozen `1.0` agentic contract, schemas rigidly constrain the network identifier:

```ts
network: z.literal("xec:mainnet")
```

Similarly, eCash address validation is pinned strictly to the lowercase `ecash:` prefix with the canonical CashAddr baseline pattern:

```ts
const ecashAddress = z
  .string()
  .regex(/^ecash:[qp][a-z0-9]{41,}$/, "expected a lowercase prefixed eCash address");
```

While this design achieved complete security hardening and zero ambiguity for mainnet operations in Gate 1, it introduces a hard blocker for automated, deterministic regression testing in local regtest environments (`BLOCKED_BY_CORE_NETWORK_DOMAIN`).

This RFC defines the normative architectural specification for evolving the agentic contract domain to version `1.1`, resolving the 12 canonical architectural points required before any test can be qualified as real regtest execution.

---

## 2. The 12 Canonical Decision Points

### Point 1: Contract Versioning Semantic Strategy (Discriminated Multi-Version Family)

**Decision**: The change belongs to agentic contract version **`1.1`** using an **unequivocal discriminated multi-version schema family**, NOT an in-place mutation of `z.literal("1.0")`.

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
- This ensures that legacy v1.0 payloads remain parseable by v1.1 parsers without mutation.

---

### Point 2: Exact Canonical Network Identifiers

**Decision**: The exact normative string literal for regtest is:
```ts
"xec:regtest"
```

The supported network enum in contract v1.1 shall be defined as:
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
- If needed in the future, testnet can be introduced under separate RFC and governance review.

---

### Point 4: Valid Address Prefixes and Normative CashAddr Validation

**Decision**: Address validation consists of a two-stage gate: initial lexical regex filtering followed by canonical CashAddr decoding and checksum verification.

#### Stage 1: Initial Lexical Filter
The baseline pattern in Core v1.0 is `^ecash:[qp][a-z0-9]{41,}$`. In contract v1.1, prefix validation is strictly coupled to the network domain:

| Network Domain | Address Type | Canonical Prefix | Regular Expression |
| :--- | :--- | :--- | :--- |
| `xec:mainnet` | Base32 CashAddr | `ecash:` | `^ecash:[qp][a-z0-9]{41,}$` |
| `xec:regtest` | Base32 CashAddr | `ecregtest:` | `^ecregtest:[qp][a-z0-9]{41,}$` |

#### Stage 2: Canonical CashAddr Decoded Checksum Verification
Regex pattern matching alone is NOT sufficient for canonical address validation. Normative validation MUST execute:
1. **Base32 Character Validation**: Ensures all characters after the colon belong strictly to the CashAddr charset `qpzry9x8gf2tvdw0s3jn54khce6mua7l`.
2. **Prefix Polynomial Checksum**: Verifies the 40-bit BCH polynomial checksum using the network-specific prefix (`ecash` or `ecregtest`) converted to 5-bit integer streams, separated by zero, and yielding a polynomial remainder of `1` (via `decodeCashAddress` / `isValidCashAddress`).
3. **Payload Type & Size Check**: Verifies that the decoded payload represents a canonical 20-byte hash160 (type `p2pkh` or `p2sh`) or an explicitly supported script type.

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

### Point 7: Backward Compatibility (Non-Forward Compatibility)

**Decision**: Asymmetric compatibility model:

- **Backward Compatibility**: The new v1.1 parser will accept and successfully validate legacy contract v1.0 payloads (`xec:mainnet`).
- **No Forward Compatibility**: Existing contract v1.0 consumers will safely reject v1.1 payloads (`invalid_literal` or `invalid_enum_value`), preventing older mainnet systems from mistakenly processing regtest envelopes.

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

### Point 10: Proposed Candidate Test Vectors (R1–R4) for Implementation Verification

> [!NOTE]
> The following vectors are proposed candidate test vectors. Per security governance, they will NOT be designated as "accepted golden vectors" until the future v1.1 codec implementation reproduces them byte-for-byte in automated test suites.
> All eCash addresses used below have been independently verified using `ecashaddrjs` (`isValidCashAddress` and `decodeCashAddress`).

#### Verified Address Constants:
- Regtest Address 1 (fromAddress): `ecregtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcrl5mqkt` (Valid P2PKH, 20 zero bytes payload)
- Regtest Address 2 (toAddress / payTo): `ecregtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygp7v599r` (Valid P2PKH, 20 0x11 bytes payload)
- Mainnet Address (for Negative Cross-Network R4): `ecash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyquz9y96w` (Valid P2PKH, 20 0x11 bytes payload)

---

#### Vector R1: Regtest Minimal Sat Payment Candidate
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
    "fromAddress": "ecregtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcrl5mqkt",
    "toAddress": "ecregtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygp7v599r",
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
- **Canonical Binary Length**: `629 bytes`
- **SHA-256 of Canonical Binary Handoff ($C$)**:
  `b006928c28af6be00ed683c93a77dca30a9069c6e53b4c6a60652791e060509b`
- **Canonical Binary Hex**:
  `544e4c31000100000003312e310000001777616c6c65745f617070726f76616c5f726571756573740000000b7865635f7061796d656e74000000127265712d726567746573742d72312d30303100000003312e310000000c6167656e745f696e74656e7400000015696e74656e742d726567746573742d72312d3030310000001e4d4445794d7a51314e6a63344f5746695932526c5a6a41784d6a4d304e51000000116167656e742d726567746573742d30303100000010736572766963655f6578656375746f720000000b7865633a72656774657374000000346563726567746573743a7171717171717171717171717171717171717171717171717171717171717171717163726c356d716b74000000346563726567746573743a717167337a7967337a7967337a7967337a7967337a7967337a7967337a7967337a79677037763539397200000001310000001c52656774657374206d696e696d616c207061796d656e742074657374000000000069800e800000000069800fac00000003312e31000000136361655f706f6c6963795f6465636973696f6e000000126361652d726567746573742d72312d30303100000015696e74656e742d726567746573742d72312d303031000000146e656564735f68756d616e5f617070726f76616c00000015524547544553545f4d414e55414c5f524556494557000000205265677465737420696e746567726174696f6e2072657669657720636865636b0000001474726163652d726567746573742d72312d30303100000019726567746573742d636f6e737469747574696f6e2d76312e310000000069800e810000000069800fac000000000069800e820000000069800fac`

---

#### Vector R2: Regtest x402 End-to-End Payment Context Candidate
- **Description**: Vector R1 extended with canonical frozen `x402ApprovalContextV1` in `xec:regtest`.
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
    "fromAddress": "ecregtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcrl5mqkt",
    "toAddress": "ecregtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygp7v599r",
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
    "x402Version": 1,
    "scheme": "exact",
    "network": "xec:regtest",
    "invoiceHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "resourceHash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "amountSats": "1",
    "payTo": "ecregtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygp7v599r",
    "nonce": "x402-nonce-1234567890abcdef",
    "issuedAt": 1770000000,
    "expiresAt": 1770000300
  },
  "requestedAt": 1770000002,
  "expiresAt": 1770000300
}
```
- **Canonical Binary Length**: `827 bytes` (full handoff payload; x402 body is `198 bytes`, and x402 segment including presence flag is `199 bytes`)
- **Canonical Schema**: Preserves canonical fields `x402Version`, `scheme`, `network`, `invoiceHash`, `resourceHash`, `amountSats`, `payTo`, `nonce`, `issuedAt`, `expiresAt`.
- **SHA-256 of Canonical Binary Handoff ($C$)**:
  `9506888f6d4cdf040159e539ba92e1792302ada347755d1aedba6fe7a125355b`
- **Canonical Binary Hex**:
  `544e4c31000100000003312e310000001777616c6c65745f617070726f76616c5f726571756573740000000b7865635f7061796d656e74000000127265712d726567746573742d72322d30303100000003312e310000000c6167656e745f696e74656e7400000015696e74656e742d726567746573742d72312d3030310000001e4d4445794d7a51314e6a63344f5746695932526c5a6a41784d6a4d304e51000000116167656e742d726567746573742d30303100000010736572766963655f6578656375746f720000000b7865633a72656774657374000000346563726567746573743a7171717171717171717171717171717171717171717171717171717171717171717163726c356d716b74000000346563726567746573743a717167337a7967337a7967337a7967337a7967337a7967337a7967337a7967337a79677037763539397200000001310000001c52656774657374206d696e696d616c207061796d656e742074657374000000000069800e800000000069800fac00000003312e31000000136361655f706f6c6963795f6465636973696f6e000000126361652d726567746573742d72312d30303100000015696e74656e742d726567746573742d72312d303031000000146e656564735f68756d616e5f617070726f76616c00000015524547544553545f4d414e55414c5f524556494557000000205265677465737420696e746567726174696f6e2072657669657720636865636b0000001474726163652d726567746573742d72312d30303100000019726567746573742d636f6e737469747574696f6e2d76312e310000000069800e810000000069800fac0100010000000565786163740000000b7865633a72656774657374aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb0000000131000000346563726567746573743a717167337a7967337a7967337a7967337a7967337a7967337a7967337a7967337a7967703776353939720000001b783430322d6e6f6e63652d313233343536373839306162636465660000000069800e800000000069800fac0000000069800e820000000069800fac`

---

#### Vector R3: Regtest BigInt Precision Preservation Candidate (40 digits)
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
    "fromAddress": "ecregtest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcrl5mqkt",
    "toAddress": "ecregtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygp7v599r",
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
    "policyTraceId": "trace-regtest-r3-001",
    "policyVersion": "regtest-constitution-v1.1",
    "evaluatedAt": 1770000001,
    "expiresAt": 1770000300
  },
  "requestedAt": 1770000002,
  "expiresAt": 1770000300
}
```
- **Monetary Formatting**: `12345678901234567890123456789012345678.90 XEC`
- **Canonical Binary Length**: `668 bytes`
- **SHA-256 of Canonical Binary Handoff ($C$)**:
  `37f11385935ca487a0d270d9fa5cd017ce5f97e0059c8f862e480353338157ee`
- **Canonical Binary Hex**:
  `544e4c31000100000003312e310000001777616c6c65745f617070726f76616c5f726571756573740000000b7865635f7061796d656e74000000127265712d726567746573742d72332d30303100000003312e310000000c6167656e745f696e74656e7400000015696e74656e742d726567746573742d72332d3030310000001e4d4445794d7a51314e6a63344f5746695932526c5a6a41784d6a4d304e51000000116167656e742d726567746573742d30303100000010736572766963655f6578656375746f720000000b7865633a72656774657374000000346563726567746573743a7171717171717171717171717171717171717171717171717171717171717171717163726c356d716b74000000346563726567746573743a717167337a7967337a7967337a7967337a7967337a7967337a7967337a7967337a79677037763539397200000028313233343536373839303132333435363738393031323334353637383930313233343536373839300000001c52656774657374206d696e696d616c207061796d656e742074657374000000000069800e800000000069800fac00000003312e31000000136361655f706f6c6963795f6465636973696f6e000000126361652d726567746573742d72332d30303100000015696e74656e742d726567746573742d72332d303031000000146e656564735f68756d616e5f617070726f76616c00000015524547544553545f4d414e55414c5f524556494557000000205265677465737420696e746567726174696f6e2072657669657720636865636b0000001474726163652d726567746573742d72332d30303100000019726567746573742d636f6e737469747574696f6e2d76312e310000000069800e810000000069800fac000000000069800e820000000069800fac`

---

#### Vector R4: Cross-Network Mismatch Negative Vector Candidate (Deterministic Rejection)
- **Description**: Proves deterministic failure when network domain does not match address prefix.
- **Payload under test**:
  - `intent.network`: `"xec:regtest"`
  - `intent.toAddress`: `"ecash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyquz9y96w"` (Valid CashAddr mainnet address on regtest network)
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
2. The agentic contract version `1.0` remains FROZEN at commit `cfe4cb1575b22ed258565717c000ac535aa98c67`.
3. The repository versioning domain distinctions (`package.json 0.2.0`, git tag `v0.1.0`) are preserved. Any future package versioning or prerelease tagging remains subject to governance decision.
4. Once this RFC is approved by all stakeholders, an implementation branch `feature/network-domain-v1.1` will be branched from `main`.

---

## 3. Implementation Status and Program Guard

Merging this documentary RFC into `tonalli-core` does **NOT** enable or authorize "real REGTEST".

The prohibition against qualifying any test or execution as "real REGTEST" terminates **ONLY** when:
1. Core v1.1 runtime schemas and binary codec are fully implemented in `tonalli-core`.
2. Exact-head reviews and independent approvals are completed on the implementation PR.
3. The implementation PR is merged to `main` and reproducibly published or pinned.
4. Downstream consumers (`tonalli-agents` and `RMZWallet`) update their dependencies and bind to the strict network domain schemas.

Until all these mandatory milestones are achieved, all repositories MUST adhere strictly to the following normative guard:

> **NO TEST OR INTEGRATION PASS SHALL BE CHARACTERIZED AS "REAL REGTEST"**.
> All current simulation tests using `xec:mainnet` remain strictly categorized as:
> `schema-only mainnet-shaped simulation under AGENTIC_KILL_SWITCH=true and AGENT_DAILY_LIMIT_SATS=0 without signing or real funds`.
