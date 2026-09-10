import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Encodes an RFC 0001 handoff payload per the canonical binary specification
 * (fixed magic TNL1\x00\x01, length-prefixed ASCII/UTF-8 fields, big-endian integers).
 */
function encodeRfcPayload(request: any): Uint8Array {
  const parts: Buffer[] = [];
  function writeFixedAscii(str: string): void {
    parts.push(Buffer.from(str, "ascii"));
  }
  function writeUint16(n: number): void {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n);
    parts.push(b);
  }
  function writeUint64(n: number): void {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n));
    parts.push(b);
  }
  function writeLpAscii(str: string): void {
    const s = Buffer.from(str, "ascii");
    const l = Buffer.alloc(4);
    l.writeUInt32BE(s.length);
    parts.push(l, s);
  }
  function writeLpUtf8(str: string): void {
    const s = Buffer.from(str, "utf8");
    const l = Buffer.alloc(4);
    l.writeUInt32BE(s.length);
    parts.push(l, s);
  }
  function writeDecimal(str: string): void {
    const s = Buffer.from(str, "ascii");
    const l = Buffer.alloc(4);
    l.writeUInt32BE(s.length);
    parts.push(l, s);
  }
  function writeHash(hexStr: string): void {
    parts.push(Buffer.from(hexStr, "hex"));
  }
  function writePresence(present: boolean): void {
    parts.push(Buffer.from([present ? 1 : 0]));
  }

  writeFixedAscii("TNL1");
  writeUint16(1);

  writeLpAscii(request.contractVersion);
  writeLpAscii(request.kind);
  writeLpAscii(request.purpose);
  writeLpAscii(request.requestId);

  writeLpAscii(request.intent.contractVersion);
  writeLpAscii(request.intent.kind);
  writeLpAscii(request.intent.intentId);
  writeLpAscii(request.intent.nonce);
  writeLpAscii(request.intent.agentId);
  writeLpAscii(request.intent.agentRole);
  writeLpAscii(request.intent.network);
  writeLpAscii(request.intent.fromAddress);
  writeLpAscii(request.intent.toAddress);
  writeDecimal(request.intent.amountSats);
  writeLpUtf8(request.intent.reason);
  writePresence(request.intent.memo !== undefined);
  if (request.intent.memo !== undefined) writeLpUtf8(request.intent.memo);
  writeUint64(request.intent.createdAt);
  writeUint64(request.intent.expiresAt);

  writeLpAscii(request.policyDecision.contractVersion);
  writeLpAscii(request.policyDecision.kind);
  writeLpAscii(request.policyDecision.decisionId);
  writeLpAscii(request.policyDecision.intentId);
  writeLpAscii(request.policyDecision.decision);
  writeLpAscii(request.policyDecision.reasonCode);
  writeLpUtf8(request.policyDecision.reason);
  writeLpAscii(request.policyDecision.policyTraceId);
  writeLpUtf8(request.policyDecision.policyVersion);
  writeUint64(request.policyDecision.evaluatedAt);
  writeUint64(request.policyDecision.expiresAt);

  writePresence(request.x402 !== undefined);
  if (request.x402 !== undefined) {
    writeUint16(request.x402.x402Version);
    writeLpAscii(request.x402.scheme);
    writeLpAscii(request.x402.network);
    writeHash(request.x402.invoiceHash);
    writeHash(request.x402.resourceHash);
    writeDecimal(request.x402.amountSats);
    writeLpAscii(request.x402.payTo);
    writeLpAscii(request.x402.nonce);
    writeUint64(request.x402.issuedAt);
    writeUint64(request.x402.expiresAt);
  }

  writeUint64(request.requestedAt);
  writeUint64(request.expiresAt);

  return new Uint8Array(Buffer.concat(parts));
}

function parseRfcVector(rfcContent: string, vectorHeader: string, nextHeader: string) {
  const section = rfcContent.split(vectorHeader)[1].split(nextHeader)[0];
  const jsonMatch = section.match(/```json\n([\s\S]*?)\n```/);
  if (!jsonMatch) throw new Error(`Missing JSON in ${vectorHeader}`);
  const json = JSON.parse(jsonMatch[1]);

  const hexMatch = section.match(/\*\*Canonical Binary Hex\*\*:\s*\n?\s*`([0-9a-fA-F]+)`/);
  if (!hexMatch) throw new Error(`Missing Canonical Binary Hex in ${vectorHeader}`);
  const hex = hexMatch[1].trim();

  const hashMatch = section.match(/SHA-256 of Canonical Binary Handoff[^\n]*\n\s*`([0-9a-fA-F]+)`/);
  if (!hashMatch) throw new Error(`Missing SHA-256 in ${vectorHeader}`);
  const hash = hashMatch[1].trim();

  const lengthMatch = section.match(/\*\*Canonical Binary Length\*\*:\s*`(\d+)\s*bytes`/);
  if (!lengthMatch) throw new Error(`Missing Canonical Binary Length in ${vectorHeader}`);
  const length = parseInt(lengthMatch[1], 10);

  return { json, hex, hash, length };
}

describe("RFC 0001 Vector R3 Canonical Binary Verification", () => {
  const rfcPath = resolve(__dirname, "../docs/rfcs/0001-network-domain-v1.1.md");
  const rfcContent = readFileSync(rfcPath, "utf8");

  it("Vector R3 JSON matches published canonical binary bytes, length, and SHA-256", () => {
    const vector = parseRfcVector(rfcContent, "#### Vector R3:", "#### Vector R4:");

    // Verify published JSON policyTraceId matches trace-regtest-r3-001
    expect(vector.json.policyDecision.policyTraceId).toBe("trace-regtest-r3-001");

    // Encode JSON via canonical binary codec
    const encoded = encodeRfcPayload(vector.json);

    // Assert length
    expect(encoded.length).toBe(vector.length);
    expect(encoded.length).toBe(668);

    // Assert exact wire hex
    const encodedHex = Buffer.from(encoded).toString("hex");
    expect(encodedHex).toBe(vector.hex);

    // Assert SHA-256
    const computedHash = createHash("sha256").update(encoded).digest("hex");
    expect(computedHash).toBe(vector.hash);
    expect(computedHash).toBe("37f11385935ca487a0d270d9fa5cd017ce5f97e0059c8f862e480353338157ee");
  });

  it("Vector R1 and R2 JSON also match published binary bytes, length, and SHA-256", () => {
    const r1 = parseRfcVector(rfcContent, "#### Vector R1:", "#### Vector R2:");
    const r1Encoded = encodeRfcPayload(r1.json);
    expect(r1Encoded.length).toBe(r1.length);
    expect(Buffer.from(r1Encoded).toString("hex")).toBe(r1.hex);
    expect(createHash("sha256").update(r1Encoded).digest("hex")).toBe(r1.hash);

    const r2 = parseRfcVector(rfcContent, "#### Vector R2:", "#### Vector R3:");
    const r2Encoded = encodeRfcPayload(r2.json);
    expect(r2Encoded.length).toBe(r2.length);
    expect(Buffer.from(r2Encoded).toString("hex")).toBe(r2.hex);
    expect(createHash("sha256").update(r2Encoded).digest("hex")).toBe(r2.hash);
  });
});
