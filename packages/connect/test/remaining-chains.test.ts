import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { describe, expect, it } from 'vitest';
import { cborDecode } from '../src/cbor/decode';
import { cborEncode } from '../src/cbor/encode';
import { asBytes, asMap, asText, asUint, cbBytes, cbMap, cbTag, mapGet } from '../src/cbor/model';
import { suiIntentDigest } from '../src/chains/sui';
import { bytesToHex, concatBytes, utf8Encode } from '../src/core/bytes';
import { EraConnect, Ur } from '../src/index';
import { verifyCosmosSignature } from '../src/verify/cosmos';
import { verifySuiSignature } from '../src/verify/sui';
import { verifyXrpSignature } from '../src/verify/xrp';

const era = new EraConnect({ origin: 'Rest Test' });
const requestId = new Uint8Array(Array.from({ length: 16 }, (_, i) => i + 1));

describe('Sui', () => {
  const priv = new Uint8Array(32).fill(3);
  const pub = ed25519.getPublicKey(priv);
  const intentMessage = new Uint8Array([0, 0, 0, ...Array.from({ length: 60 }, (_, i) => i)]);
  const request = era.sui.generateSignRequest({
    requestId,
    intentMessage,
    path: "m/44'/784'/0'/0'/0'",
    xfp: 'deadbeef',
  });

  it('wire shape: uuid37, bytes, [keypath], origin; hash variant uses a hex STRING', () => {
    const map = asMap(cborDecode(request.ur.cbor))!;
    expect(request.ur.type).toBe('sui-sign-request');
    expect(asBytes(mapGet(map, 2))).toEqual(intentMessage);
    const hashReq = era.sui.generateSignHashRequest({
      requestId,
      messageHash: suiIntentDigest(intentMessage),
      path: "m/44'/784'/0'/0'/0'",
      xfp: 'deadbeef',
    });
    const hashMap = asMap(cborDecode(hashReq.ur.cbor))!;
    expect(hashReq.ur.type).toBe('sui-sign-hash-request');
    expect(asText(mapGet(hashMap, 2))).toBe(bytesToHex(suiIntentDigest(intentMessage)));
  });

  it('refuses soft path components', () => {
    expect(() =>
      era.sui.generateSignRequest({ intentMessage, path: "m/44'/784'/0'/0/0", xfp: 1 }),
    ).toThrowError(/hardened/);
  });

  it('round-trips a reply and verifies the intent digest', () => {
    const signature = ed25519.sign(suiIntentDigest(intentMessage), priv);
    const reply = new Ur(
      'sui-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, cbBytes(requestId))],
          [2, cbBytes(signature)],
          [3, cbBytes(pub)],
        ]),
      ),
    );
    const scanner = request.scanner();
    scanner.receivePart(reply.toWireString());
    const parsed = scanner.parse();
    expect(
      verifySuiSignature({
        intentMessage,
        signature: parsed.signature,
        publicKey: parsed.publicKey,
        expectedPublicKey: pub,
      }),
    ).toEqual({ ok: true, checked: true });
    const wrongKey = verifySuiSignature({
      intentMessage,
      signature: parsed.signature,
      publicKey: parsed.publicKey,
      expectedPublicKey: ed25519.getPublicKey(new Uint8Array(32).fill(9)),
    });
    expect(wrongKey.ok).toBe(false);
  });
});

describe('Cosmos', () => {
  const priv = new Uint8Array(32).fill(5);
  const pub = secp256k1.getPublicKey(priv, true);
  const aminoDoc = utf8Encode(JSON.stringify({ chain_id: 'cosmoshub-4', msgs: [] }));

  it('cosmos request shape + roundtrip with sha256 digest', () => {
    const request = era.cosmos.generateSignRequest({
      requestId,
      signData: aminoDoc,
      dataType: 1,
      path: "m/44'/118'/0'/0/0",
      xfp: 'deadbeef',
      address: 'cosmos1xyz',
    });
    const map = asMap(cborDecode(request.ur.cbor))!;
    expect(request.ur.type).toBe('cosmos-sign-request');
    expect(Number(asUint(mapGet(map, 3)))).toBe(1);

    const sig = secp256k1.sign(sha256(aminoDoc), priv);
    const reply = new Ur(
      'cosmos-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, cbBytes(requestId))],
          [2, cbBytes(sig.toCompactRawBytes())],
          [3, cbBytes(pub)],
        ]),
      ),
    );
    const scanner = request.scanner();
    scanner.receivePart(reply.toWireString());
    const parsed = scanner.parse();
    expect(
      verifyCosmosSignature({
        signData: aminoDoc,
        digest: 'sha256',
        signature: parsed.signature,
        publicKey: parsed.publicKey!,
        expectedPublicKey: pub,
      }),
    ).toEqual({ ok: true, checked: true });
  });

  it('ethermint request maps dataType and rides evm-sign-request with keccak', () => {
    const request = era.cosmos.generateEthermintSignRequest({
      requestId,
      signData: aminoDoc,
      dataType: 1, // amino → wire 2
      path: "m/44'/60'/0'/0/0",
      xfp: 'deadbeef',
      address: '0x1111111111111111111111111111111111111111',
    });
    const map = asMap(cborDecode(request.ur.cbor))!;
    expect(request.ur.type).toBe('evm-sign-request');
    expect(Number(asUint(mapGet(map, 3)))).toBe(2);
    expect(asBytes(mapGet(map, 6))!.length).toBe(42); // ASCII of the 0x string

    const sig = secp256k1.sign(keccak_256(aminoDoc), priv);
    const reply = new Ur(
      'evm-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, cbBytes(requestId))],
          [2, cbBytes(sig.toCompactRawBytes())],
        ]),
      ),
    );
    const parsed = era.cosmos.parseSignature(reply, { requestId });
    expect(
      verifyCosmosSignature({
        signData: aminoDoc,
        digest: 'keccak256',
        signature: parsed.signature,
        publicKey: pub,
      }),
    ).toEqual({ ok: true, checked: true });
  });
});

describe('XRP', () => {
  it('validates the request JSON gate', () => {
    expect(() =>
      era.xrp.generateSignRequest({ transaction: { TransactionType: 'Payment' } }),
    ).toThrowError(/Account/);
    const request = era.xrp.generateSignRequest({
      transaction: {
        TransactionType: 'Payment',
        Account: 'rMYQaEBLwyvSmDoRnH2tsqGE2LK4S3Rdap',
        Destination: 'rGWrZyQqhTp9Xu7G5Pkayo7bXjH4k4QYpf',
        Amount: '1000',
        Fee: '12',
        Sequence: 1,
        SigningPubKey: bytesToHex(secp256k1.getPublicKey(new Uint8Array(32).fill(8), true)),
      },
    });
    expect(request.ur.type).toBe('bytes');
    expect(request.requestId).toBeUndefined(); // honestly no request id on this wire
  });

  it('verifies a hand-built signed binary (walker + signing hash + DER)', () => {
    const priv = new Uint8Array(32).fill(8);
    const pub = secp256k1.getPublicKey(priv, true);
    // Build a minimal canonical tx: TransactionType(0x12 UInt16), Sequence
    // (0x24 UInt32), Amount(0x61), Fee(0x68), SigningPubKey(0x73 VL),
    // Account(0x81 VL), Destination(0x83 VL) — signature inserted as 0x74.
    const fields: Uint8Array[] = [];
    fields.push(new Uint8Array([0x12, 0x00, 0x00])); // Payment
    fields.push(new Uint8Array([0x24, 0, 0, 0, 1])); // Sequence 1
    fields.push(new Uint8Array([0x61, 0x40, 0, 0, 0, 0, 0, 0x03, 0xe8])); // 1000 drops
    fields.push(new Uint8Array([0x68, 0x40, 0, 0, 0, 0, 0, 0, 12])); // fee 12
    fields.push(new Uint8Array([0x73, 33, ...pub]));
    fields.push(new Uint8Array([0x81, 20, ...new Uint8Array(20).fill(0xaa)]));
    fields.push(new Uint8Array([0x83, 20, ...new Uint8Array(20).fill(0xbb)]));

    const signingPayload = concatBytes(new Uint8Array([0x53, 0x54, 0x58, 0x00]), ...fields);
    const digest = sha512(signingPayload).slice(0, 32);
    const der = secp256k1.sign(digest, priv, { lowS: true }).toDERRawBytes();
    // Canonical order: TxnSignature (0x74) sits after SigningPubKey (0x73).
    const signed = concatBytes(
      ...fields.slice(0, 5),
      new Uint8Array([0x74, der.length, ...der]),
      ...fields.slice(5),
    );

    const good = verifyXrpSignature({ signedTx: signed, expectedSigningPubKey: bytesToHex(pub) });
    expect(good).toEqual({ ok: true, checked: true });

    const tampered = signed.slice();
    tampered[4] = 2; // Sequence 1 → 2
    const bad = verifyXrpSignature({ signedTx: tampered, expectedSigningPubKey: bytesToHex(pub) });
    expect(bad.ok).toBe(false);
  });
});

describe('Bitcoin family via crypto-psbt-extend', () => {
  const psbt = new Uint8Array([
    0x70,
    0x73,
    0x62,
    0x74,
    0xff,
    ...Array.from({ length: 40 }, (_, i) => i),
  ]);

  it('doge/ltc/dash requests carry the PSBT plus the coin id', () => {
    for (const [coin, id] of [
      ['doge', 3],
      ['ltc', 2],
      ['dash', 5],
    ] as const) {
      const request = era.btc.generatePsbtSignRequest({ psbt, coin });
      expect(request.ur.type).toBe('crypto-psbt-extend');
      const map = asMap(cborDecode(request.ur.cbor))!;
      expect(asBytes(mapGet(map, 1))).toEqual(psbt);
      expect(Number(asUint(mapGet(map, 2)))).toBe(id);
      expect(request.replyTypes).toContain('crypto-psbt-extend');
    }
  });

  it('parses both reply shapes (bare bytes and the extend map)', () => {
    const request = era.btc.generatePsbtSignRequest({ psbt, coin: 'doge' });
    const extendReply = new Ur(
      'crypto-psbt-extend',
      cborEncode(
        cbMap([
          [1, cbBytes(psbt)],
          [2, { kind: 'uint', value: 3n }],
        ]),
      ),
    );
    const scanner = request.scanner();
    scanner.receivePart(extendReply.toWireString());
    expect(scanner.parse().psbt).toEqual(psbt);

    const plain = era.btc.parsePsbt(new Ur('crypto-psbt', cborEncode(cbBytes(psbt))));
    expect(plain.psbt).toEqual(psbt);
  });

  it('plain btc still rides crypto-psbt', () => {
    const request = era.btc.generatePsbtSignRequest({ psbt });
    expect(request.ur.type).toBe('crypto-psbt');
  });
});
