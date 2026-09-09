# RFC 0001: Tonalli Core Network Domain v1.1 Specification

- **Status**: DRAFT / PROPOSED
- **Date**: 2026-09-09
- **Author**: xolosArmy Architecture Working Group
- **Target Repository**: `tonalli-core`
- **Related Program**: Agentes → x402 Security Gates (Gate 2A, Gate 2B, Gate 3)

---

## 1. Context and Motivation

In Tonalli Core v1.0 (frozen at commit `cfe4cb1575b22ed258565717c000ac535aa98c67`), the schemas `agentIntentV1Schema` and `x402ApprovalContextV1Schema` rigidly define the network identifier as:

```ts
network: z.literal("xec:mainnet")
```

Similarly, eCash address validation is pinned strictly to the `ecash:` prefix:

```ts
const ecashAddress = z.string().regex(/^ecash:[a-z0-9]{42}$/, "Must be canonical ecash address");
```

While this design achieved complete security hardening and zero ambiguity for mainnet operations in Gate 1, it introduces a hard blocker for end-to-end integration testing in local regtest environments (`BLOCKED_BY_CORE_NETWORK_DOMAIN`).

This RFC defines the normative specification for evolving Tonalli Core to v1.1, resolving the 12 canonical architectural points required before any test can be qualified as real regtest execution.

---

## 2. The 12 Canonical Decision Points

### Point 1: Contract Versioning Semantic Strategy (Minor v1.1 vs Major v2.0)

**Decision**: The change belongs to minor release **`1.1`** (`AGENTIC_CONTRACT_VERSION = "1.1"` or backward-compatible schema suite).

**Rationale**:
- Existing contracts for `xec:mainnet` remain 100% semantically valid without breaking changes to their payload structure or hash definitions.
- The addition of `xec:regtest` is an additive domain expansion with explicit prefix guards.
- Core v1.0 envelopes containing `xec:mainnet` remain valid under v1.1 parsers.
- A major bump to v2.0 is unwarranted because the serialization format, field names, cryptographic hash constructions ($H(E,C)$), and capability architectures remain unchanged.

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
- eCash infrastructure relies primarily on local regtest for automated, deterministic, and sealed CI/CD environments. Public testnets are subject to external reorgs, faucet exhaustion, and prefix inconsistencies.
- Including testnet at this stage would enlarge the attack surface and require additional prefix bindings without providing immediate value to the Agentes → x402 program.
- If needed in the future, testnet can be introduced in v1.2 under the same binding rules.

---

### Point 4: Valid Address Prefixes per Network

**Decision**: Address prefixes are strictly coupled to the network domain:

| Network Domain | Address Type | Canonical Prefix | Regular Expression |
| :--- | :--- | :--- | :--- |
| `xec:mainnet` | Base32 CashAddr | `ecash:` | `^ecash:[a-z0-9]{42}$` |
| `xec:regtest` | Base32 CashAddr | `ecregtest:` | `^ecregtest:[a-z0-9]{42}$` |

Any address lacking the exact network-matching prefix MUST be rejected during schema parsing.

---

### Point 5: Mandatory Cross-Field Network Binding

**Decision**: Cross-field consistency MUST be enforced at schema validation time via Zod `superRefine`:

1. **Intent Network vs Addresses**:
   - If `intent.network === "xec:mainnet"`, both `intent.fromAddress` and `intent.toAddress` MUST begin with `ecash:`.
   - If `intent.network === "xec:regtest"`, both `intent.fromAddress` and `intent.toAddress` MUST begin with `ecregtest:`.
2. **Intent Network vs x402 Context**:
   - If `x402` context is present, `x402.network` MUST be strictly identical to `intent.network`.
   - `x402.payTo` MUST begin with the prefix corresponding to `intent.network`.
   - `x402.payTo` MUST strictly match `intent.toAddress`.

---

### Point 6: Strict Rejection of Cross-Network Combinations

**Decision**: Schema validation MUST fail closed with specific error codes upon any network mismatch:

- An intent with `network: "xec:regtest"` and `toAddress: "ecash:..."` is **FATAL** (`NETWORK_ADDRESS_PREFIX_MISMATCH`).
- An intent with `network: "xec:mainnet"` and `fromAddress: "ecregtest:..."` is **FATAL** (`NETWORK_ADDRESS_PREFIX_MISMATCH`).
- An envelope with `intent.network: "xec:mainnet"` and `x402.network: "xec:regtest"` is **FATAL** (`X402_NETWORK_MISMATCH`).

No automatic address translation or prefix conversion is permitted at any layer.

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

### Point 9: Required Changes in RMZWallet Codec & Handoff

**Decision**:
- `agentWalletHandoff` CBOR/JSON serializer and parser in `RMZWallet` must accept `xec:regtest` when updating to Core v1.1.
- Content hash computation $H(E,C)$ continues using the exact normative universal authorization domain:
  `tonalli.authorization/content-hash/v1`
  operating over the canonical byte stream of the envelope. The network field is naturally covered within the serialized bytes of $C$, preserving cryptographic binding without altering the hash scheme.

---

### Point 10: New Canonical Golden Vectors (ASCII and Binary)

**Decision**: Core v1.1 test suite shall introduce normative golden vectors:

1. **Vector R1 (Regtest Minimum Sat)**:
   - `network: "xec:regtest"`
   - `amountSats: "1"`
   - `fromAddress: "ecregtest:qz2708636snqhsxu8wnlka78h6fdp77ar5r569dklm0"`
   - `toAddress: "ecregtest:qp3wjpa3tjlj042z2wv7hahvd8whzgcwvutgqw8y6h"`
2. **Vector R2 (Regtest x402 Handoff)**:
   - Full `WalletApprovalRequestV1` with matching `x402ApprovalContextV1` in `xec:regtest`.
3. **Vector R3 (Regtest BigInt Precision)**:
   - Amount matching Vector B3 (`1234567890123456789012345678901234567890 sats`), demonstrating byte-exact preservation under `xec:regtest`.
4. **Vector R4 (Cross-Network Rejection)**:
   - Deliberate mismatch (`network: "xec:regtest"`, address `ecash:...`) verifying deterministic failure.

---

### Point 11: Impact Analysis across Program Components

1. **H2A & Tonalli CAE**:
   - CAE policy evaluation engines must be configured with separate policy limits for `xec:mainnet` (e.g. daily limit 0 until full rollout) vs `xec:regtest` (where integration funds are freely simulated).
2. **`tonalli-agents`**:
   - `WalletApprovalTransport` outbound validator will permit `xec:regtest` when Core v1.1 is adopted.
   - Outbound audit display correctly reflects `network: "xec:regtest"`.
3. **`RMZWallet`**:
   - Receiver UI will display explicit visual distinction (e.g. `REGTEST (SIMULATED)` badge) to prevent user confusion with real funds.
   - Ledger bindings record `network: "xec:regtest"`.
4. **`x402-XEC` Bridge**:
   - HTTP 402 server challenges can emit `network: "xec:regtest"`, unlocking end-to-end integration testing against local Chronik regtest nodes.

---

### Point 12: Migration Strategy Preserving Core v1.0 FROZEN Baseline

**Decision**:
1. This RFC PR is **DOCUMENTARY ONLY**. No code files (`src/**/*.ts`) are modified in this PR.
2. Core v1.0 remains FROZEN and untainted at Git tag `v1.0.0` / commit `cfe4cb1575b22ed258565717c000ac535aa98c67`.
3. Once this RFC is approved by all stakeholders, an implementation branch `feature/network-domain-v1.1` will be branched from `main`.
4. The implementation will be tagged as `v1.1.0-alpha.1` for consuming repositories to test in staging before any general release.

---

## 3. Implementation Status and Program Guard

Until this RFC is formally reviewed and merged into `tonalli-core`, all repositories MUST adhere to the following rule:

> **NO TEST OR INTEGRATION PASS SHALL BE CHARACTERIZED AS "REAL REGTEST"**.
> All current simulation tests using `xec:mainnet` remain strictly categorized as:
> `schema-only mainnet-shaped simulation under AGENTIC_KILL_SWITCH=true and AGENT_DAILY_LIMIT_SATS=0 without signing or real funds`.
