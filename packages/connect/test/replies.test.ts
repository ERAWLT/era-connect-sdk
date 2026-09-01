import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { base64 } from '@scure/base';
import { describe, expect, it } from 'vitest';
import { tronAddressFromPublicKey } from '../src/accounts/derive';
import { cborEncode } from '../src/cbor/encode';
import { cbBytes, cbMap, cbTag } from '../src/cbor/model';
import { EvmDataType } from '../src/chains/evm';
import { bytesToHex, concatBytes } from '../src/core/bytes';
import { EraConnect, EraSdkError, Ur } from '../src/index';
import { gzipCompress } from '../src/tron-proto/gzip';
import { ProtoWriter } from '../src/tron-proto/wire';
import { verifyBtcMessageHeader, verifySignedPsbt } from '../src/verify/btc';
import { verifyEvmSignature } from '../src/verify/evm';
import { verifySolanaSignature } from '../src/verify/solana';
import { verifyTronSignature } from '../src/verify/tron';

/**
 * Device replies synthesized with test keys: the exact CBOR/protobuf shapes
 * the firmware emits, signed so the verification helpers have something real
 * to recover. No fixture material from any private source.
 */

const era = new EraConnect({ origin: 'Test Wallet' });
const requestId = new Uint8Array(Array.from({ length: 16 }, (_, i) => i + 1));
const otherRequestId = new Uint8Array(16).fill(9);

const privKey = new Uint8Array(32).fill(7);
const pubKeyCompressed = secp256k1.getPublicKey(privKey, true);
const pubKeyUncompressed = secp256k1.getPublicKey(privKey, false);
const evmAddress = keccak_256(pubKeyUncompressed.slice(1)).slice(12);
const signData = new Uint8Array(Array.from({ length: 48 }, (_, i) => i * 3));

function evmReply(id: Uint8Array, signature: Uint8Array, type = 'eth-signature'): Ur {
  return new Ur(
    type,
    cborEncode(
      cbMap([
        [1, cbTag(37, cbBytes(id))], // the device ALWAYS wraps the echo in tag 37
        [2, cbBytes(signature)],
      ]),
    ),
  );
}

describe('EVM reply parsing + verification', () => {
  const request = era.evm.generateSignRequest({
    requestId,
    signData,
    dataType: EvmDataType.transaction,
    path: "m/44'/60'/0'/0/0",
    xfp: '11111111',
    chainId: 137,
    address: evmAddress,
  });

  const digest = keccak_256(signData);
  const sig = secp256k1.sign(digest, privKey);

  it('round-trips a typed-tx reply through the request scanner', () => {
    const signature = concatBytes(sig.toCompactRawBytes(), new Uint8Array([sig.recovery]));
    const scanner = request.scanner();
    const feed = scanner.receivePart(evmReply(requestId, signature).toWireString());
    expect(feed.kind).toBe('complete');
    const parsed = scanner.parse();
    expect(parsed.recoveryId).toBe(sig.recovery);
    expect(parsed.v).toBe(BigInt(sig.recovery));
    expect(
      verifyEvmSignature({
        signData,
        dataType: EvmDataType.transaction,
        signature: parsed.signature,
        address: evmAddress,
      }),
    ).toEqual({ ok: true, checked: true });
  });

  it('accepts a legacy EIP-155 multi-byte v for chainId 137 (v = 309/310)', () => {
    const v = BigInt(sig.recovery) + 137n * 2n + 35n; // 309 or 310 — two bytes
    const vBytes = new Uint8Array([Number(v >> 8n), Number(v & 0xffn)]);
    const signature = concatBytes(sig.toCompactRawBytes(), vBytes);
    const parsed = era.evm.parseSignature(evmReply(requestId, signature), { requestId });
    expect(parsed.signature.length).toBe(66);
    expect(parsed.recoveryId).toBe(sig.recovery);
    expect(
      verifyEvmSignature({
        signData,
        dataType: EvmDataType.transaction,
        signature: parsed.signature,
        address: evmAddress,
      }),
    ).toEqual({ ok: true, checked: true });
  });

  it('refuses a reply echoing a different request id', () => {
    const signature = concatBytes(sig.toCompactRawBytes(), new Uint8Array([sig.recovery]));
    const scanner = request.scanner();
    scanner.receivePart(evmReply(otherRequestId, signature).toWireString());
    expect(() => scanner.parse()).toThrowError(EraSdkError);
    try {
      scanner.parse();
    } catch (e) {
      expect((e as EraSdkError).code).toBe('request-id-mismatch');
    }
  });

  it('pins the reply type before the decoder: a wallet-export frame is rejected', () => {
    const scanner = request.scanner();
    const stray = new Ur('crypto-multi-accounts', cborEncode(cbMap([[1, cbBytes(requestId)]])));
    const first = scanner.receivePart(stray.toWireString());
    expect(first.kind).toBe('rejected');
    // Rejected frames are deliberately NOT remembered (junk must not fill
    // the dedup budget) — the repeat counter is what keeps the noise down.
    const second = scanner.receivePart(stray.toWireString());
    expect(second.kind).toBe('rejected');
    if (second.kind === 'rejected') expect(second.rejection.repeated).toBe(2);
  });

  it('verification catches a signature by the wrong key', () => {
    const wrongSig = secp256k1.sign(digest, new Uint8Array(32).fill(8));
    const signature = concatBytes(
      wrongSig.toCompactRawBytes(),
      new Uint8Array([wrongSig.recovery]),
    );
    const result = verifyEvmSignature({
      signData,
      dataType: EvmDataType.transaction,
      signature,
      address: evmAddress,
    });
    expect(result.ok).toBe(false);
  });

  it('personal_sign digest includes the EIP-191 prefix', () => {
    const prefixed = concatBytes(
      new Uint8Array([0x19]),
      new Uint8Array(
        [...`Ethereum Signed Message:\n${signData.length}`].map((c) => c.charCodeAt(0)),
      ),
      signData,
    );
    const msgSig = secp256k1.sign(keccak_256(prefixed), privKey);
    const signature = concatBytes(
      msgSig.toCompactRawBytes(),
      new Uint8Array([27 + msgSig.recovery]),
    );
    expect(
      verifyEvmSignature({
        signData,
        dataType: EvmDataType.personalMessage,
        signature,
        address: evmAddress,
      }),
    ).toEqual({ ok: true, checked: true });
  });

  it('EIP-712 is honestly unverifiable client-side', () => {
    const result = verifyEvmSignature({
      signData,
      dataType: EvmDataType.typedData,
      signature: new Uint8Array(65),
      address: evmAddress,
    });
    expect(result.ok).toBe(true);
    expect(result.ok && 'checked' in result && result.checked).toBe(false);
  });
});

describe('Solana reply parsing + verification', () => {
  const solPriv = new Uint8Array(32).fill(5);
  const solPub = ed25519.getPublicKey(solPriv);
  const request = era.solana.generateSignRequest({
    requestId,
    signData,
    path: "m/44'/501'/0'",
    xfp: '33333333',
    publicKey: solPub,
  });
  const signature = ed25519.sign(signData, solPriv);

  function solReply(sigValue: Parameters<typeof cbMap>[0][number][1]): Ur {
    return new Ur(
      'sol-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, cbBytes(requestId))],
          [2, sigValue],
        ]),
      ),
    );
  }

  it('round-trips and verifies', () => {
    const scanner = request.scanner();
    scanner.receivePart(solReply(cbBytes(signature)).toWireString());
    const parsed = scanner.parse();
    expect(parsed.signature).toEqual(signature);
    expect(
      verifySolanaSignature({ signData, signature: parsed.signature, publicKey: solPub }),
    ).toEqual({ ok: true, checked: true });
  });

  it('accepts the legacy hex-text signature shape', () => {
    const parsed = era.solana.parseSignature(
      solReply({ kind: 'text', value: bytesToHex(signature) }),
      { requestId },
    );
    expect(parsed.signature).toEqual(signature);
  });

  it('a broadcast/signed message divergence is a failure', () => {
    const drifted = signData.slice();
    drifted[0] = 0xff;
    const result = verifySolanaSignature({
      signData,
      signature,
      publicKey: solPub,
      broadcastMessageBytes: drifted,
    });
    expect(result.ok).toBe(false);
  });
});

describe('BTC message reply parsing', () => {
  const request = era.btc.generateMessageSignRequest({
    requestId,
    message: signData,
    path: "m/84'/0'/0'/0/0",
    xfp: '22222222',
    address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
  });
  const rawSignature = new Uint8Array([31, ...new Array(64).fill(0x44)]); // compressed P2PKH header

  function btcReply(sigBytes: Uint8Array): Ur {
    return new Ur(
      'btc-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, cbBytes(requestId))],
          [2, cbBytes(sigBytes)],
          [3, cbBytes(pubKeyCompressed)],
        ]),
      ),
    );
  }

  it('decodes the base64-in-ASCII device quirk', () => {
    const wire = new Uint8Array([...base64.encode(rawSignature)].map((c) => c.charCodeAt(0)));
    const scanner = request.scanner();
    scanner.receivePart(btcReply(wire).toWireString());
    const parsed = scanner.parse();
    expect(parsed.signature).toEqual(rawSignature);
    expect(parsed.signatureBase64).toBe(base64.encode(rawSignature));
    expect(parsed.publicKey).toEqual(pubKeyCompressed);
  });

  it('an empty signature is the typed segwit refusal, not zero bytes', () => {
    const scanner = request.scanner();
    scanner.receivePart(btcReply(new Uint8Array(0)).toWireString());
    try {
      scanner.parse();
      expect.unreachable();
    } catch (e) {
      expect((e as EraSdkError).code).toBe('empty-signature');
    }
  });

  it('BIP-137 header ranges match address kinds', () => {
    expect(
      verifyBtcMessageHeader({
        address: '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2',
        signature: rawSignature,
      }).ok,
    ).toBe(true);
    const wrongForSegwit = verifyBtcMessageHeader({
      address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
      signature: rawSignature,
    });
    expect(wrongForSegwit.ok).toBe(false);
    const taproot = verifyBtcMessageHeader({
      address: 'bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297',
      signature: rawSignature,
    });
    expect(taproot.ok && !('checked' in taproot && taproot.checked)).toBe(true);
  });
});

// --- Minimal PSBT construction helpers (BIP-174 v0) ------------------------

function compactSize(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  return new Uint8Array([0xfd, n & 0xff, n >> 8]);
}

function keyValue(keyType: number, keyData: Uint8Array, value: Uint8Array): Uint8Array {
  const key = concatBytes(new Uint8Array([keyType]), keyData);
  return concatBytes(compactSize(key.length), key, compactSize(value.length), value);
}

function unsignedTx(outputScript: Uint8Array): Uint8Array {
  return concatBytes(
    new Uint8Array([2, 0, 0, 0]), // version
    compactSize(1), // one input
    new Uint8Array(32).fill(0xaa), // prev txid
    new Uint8Array([0, 0, 0, 0]), // vout
    compactSize(0), // empty scriptSig
    new Uint8Array([0xff, 0xff, 0xff, 0xff]), // sequence
    compactSize(1), // one output
    new Uint8Array([0x40, 0x42, 0x0f, 0, 0, 0, 0, 0]), // 1_000_000 sats
    concatBytes(compactSize(outputScript.length), outputScript),
    new Uint8Array([0, 0, 0, 0]), // locktime
  );
}

function psbtOf(
  tx: Uint8Array,
  inputMaps: Uint8Array[][],
  outputMaps: Uint8Array[][] = [[]],
): Uint8Array {
  const sep = new Uint8Array([0]);
  return concatBytes(
    new Uint8Array([0x70, 0x73, 0x62, 0x74, 0xff]),
    keyValue(0x00, new Uint8Array(0), tx),
    sep,
    ...inputMaps.flatMap((entries) => [...entries, sep]),
    ...outputMaps.flatMap((entries) => [...entries, sep]),
  );
}

describe('PSBT verification', () => {
  const script = new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x11)]);
  const tx = unsignedTx(script);
  const sent = psbtOf(tx, [[]]);
  const partialSig = keyValue(0x02, pubKeyCompressed, new Uint8Array(71).fill(0x30));
  const signed = psbtOf(tx, [[partialSig]]);

  it('accepts the same transaction with a signature added', () => {
    expect(verifySignedPsbt({ sentPsbt: sent, signedPsbt: signed })).toEqual({
      ok: true,
      checked: true,
    });
  });

  it('refuses a returned PSBT whose unsigned tx differs (the anti-replay binding)', () => {
    const otherTx = unsignedTx(new Uint8Array([0x00, 0x14, ...new Array(20).fill(0x22)]));
    const swapped = psbtOf(otherTx, [[partialSig]]);
    const result = verifySignedPsbt({ sentPsbt: sent, signedPsbt: swapped });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/different transaction/);
  });

  it('refuses an input that came back finalized when it was not sent that way', () => {
    const finalScript = keyValue(0x07, new Uint8Array(0), new Uint8Array([0xde, 0xad]));
    const finalized = psbtOf(tx, [[partialSig, finalScript]]);
    const result = verifySignedPsbt({ sentPsbt: sent, signedPsbt: finalized });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/finalized/);
  });

  it('refuses a substituted finalized script even when one was sent', () => {
    const sentFinal = keyValue(0x07, new Uint8Array(0), new Uint8Array([0x01, 0x02]));
    const returnedFinal = keyValue(0x07, new Uint8Array(0), new Uint8Array([0x0e, 0x0f]));
    const result = verifySignedPsbt({
      sentPsbt: psbtOf(tx, [[sentFinal]]),
      signedPsbt: psbtOf(tx, [[returnedFinal, partialSig]]),
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/different finalized/);
  });

  it('refuses a reply that signed nothing', () => {
    const result = verifySignedPsbt({ sentPsbt: sent, signedPsbt: psbtOf(tx, [[]]) });
    expect(result.ok).toBe(false);
  });

  it('parses PSBT replies through the chain module', () => {
    const request = era.btc.generatePsbtSignRequest({ psbt: sent });
    const scanner = request.scanner();
    scanner.receivePart(new Ur('crypto-psbt', cborEncode(cbBytes(signed))).toWireString());
    expect(scanner.parse().psbt).toEqual(signed);
  });
});

// --- Tron ------------------------------------------------------------------

const tronOwner = tronAddressFromPublicKey(pubKeyCompressed);
const TRANSFER_URL = 'type.googleapis.com/protocol.TransferContract';

function transferContractParam(owner: Uint8Array, to: Uint8Array, amount: number): Uint8Array {
  return new ProtoWriter().bytesField(1, owner).bytesField(2, to).varintField(3, amount).finish();
}

function tronRawData(args: {
  owner: Uint8Array;
  to: Uint8Array;
  amount: number;
  timestamp: number;
  expiration: number;
}): Uint8Array {
  const contract = new ProtoWriter()
    .varintField(1, 1) // TransferContract
    .messageField(
      2,
      new ProtoWriter()
        .stringField(1, TRANSFER_URL)
        .bytesField(2, transferContractParam(args.owner, args.to, args.amount))
        .finish(),
    )
    .finish();
  return new ProtoWriter()
    .bytesField(1, new Uint8Array([0x12, 0x34])) // ref_block_bytes
    .bytesField(4, new Uint8Array(8).fill(0x56)) // ref_block_hash
    .varintField(8, args.expiration)
    .messageField(11, contract)
    .varintField(14, args.timestamp)
    .finish();
}

function tronReply(id: string, rawData: Uint8Array): Ur {
  const digest = sha256(rawData);
  const sig = secp256k1.sign(digest, privKey);
  const signature = concatBytes(sig.toCompactRawBytes(), new Uint8Array([sig.recovery]));
  const frame = new ProtoWriter().bytesField(1, rawData).bytesField(2, signature).finish();
  const result = new ProtoWriter()
    .stringField(1, id)
    .stringField(2, bytesToHex(digest))
    .stringField(3, bytesToHex(frame))
    .finish();
  const payload = new ProtoWriter().varintField(1, 9).messageField(7, result).finish();
  const base = new ProtoWriter()
    .varintField(1, 1)
    .stringField(2, 'keystone qrcode')
    .messageField(3, payload)
    .finish();
  return new Ur('keystone-sign-result', cborEncode(cbMap([[1, cbBytes(gzipCompress(base))]])));
}

describe('Tron reply parsing + verification', () => {
  const ownerRaw = new Uint8Array(21).fill(0x41);
  const toRaw = new Uint8Array(21).fill(0x42);
  const blockTimestamp = 1_721_908_800_000;
  const latestBlock = {
    hash: '00000000045bcdc4c2ff1c56cf2b7ecdb60e0e26e3859ca9ff0a80b2f5502424',
    number: 73256388,
    timestamp: blockTimestamp,
  };
  const rawData = tronRawData({
    owner: ownerRaw,
    to: toRaw,
    amount: 1_000_000,
    timestamp: 1_721_908_801_234,
    expiration: 1_721_908_801_234 + 60_000,
  });
  const request = era.tron.generateSignRequest({
    requestId,
    rawData,
    path: "m/44'/195'/0'/0/0",
    xfp: '00abcdef',
    latestBlock,
  });

  it('round-trips through the scanner and validates the signId echo', () => {
    const scanner = request.scanner();
    const id = '01020304-0506-0708-090a-0b0c0d0e0f10';
    scanner.receivePart(tronReply(id, rawData).toWireString());
    const parsed = scanner.parse();
    expect(parsed.txId).toBe(bytesToHex(sha256(rawData)));
    expect(parsed.signedTx.rawData).toEqual(rawData);
    expect(parsed.signedTx.signatures.length).toBe(1);
    expect(
      verifyTronSignature({ rawData, from: tronOwner, latestBlock, signedTx: parsed.signedTx }),
    ).toEqual({ ok: true, checked: true });
  });

  it('refuses a stale signId (the only Tron anti-replay)', () => {
    const scanner = request.scanner();
    scanner.receivePart(tronReply('99999999-0506-0708-090a-0b0c0d0e0f10', rawData).toWireString());
    try {
      scanner.parse();
      expect.unreachable();
    } catch (e) {
      expect((e as EraSdkError).code).toBe('request-id-mismatch');
    }
  });

  it('rebuild fallback: same contract + in-window timestamps pass', () => {
    const rebuilt = tronRawData({
      owner: ownerRaw,
      to: toRaw,
      amount: 1_000_000,
      timestamp: blockTimestamp, // stamped with the reference block, firmware-style
      expiration: blockTimestamp + 10 * 60 * 1000,
    });
    expect(
      verifyTronSignature({
        rawData,
        from: tronOwner,
        latestBlock,
        signedTx: { rawData: rebuilt, signatures: signOf(rebuilt) },
      }),
    ).toEqual({ ok: true, checked: true });
  });

  it('rebuild fallback: a different recipient is refused', () => {
    const diverted = tronRawData({
      owner: ownerRaw,
      to: new Uint8Array(21).fill(0x66),
      amount: 1_000_000,
      timestamp: blockTimestamp,
      expiration: blockTimestamp + 10 * 60 * 1000,
    });
    const result = verifyTronSignature({
      rawData,
      from: tronOwner,
      latestBlock,
      signedTx: { rawData: diverted, signatures: signOf(diverted) },
    });
    expect(result.ok).toBe(false);
  });

  it('rebuild fallback: a stretched validity window is refused', () => {
    const stretched = tronRawData({
      owner: ownerRaw,
      to: toRaw,
      amount: 1_000_000,
      timestamp: blockTimestamp,
      expiration: blockTimestamp + 11 * 60 * 60 * 1000, // 11h > 10h ceiling
    });
    const result = verifyTronSignature({
      rawData,
      from: tronOwner,
      latestBlock,
      signedTx: { rawData: stretched, signatures: signOf(stretched) },
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/window|valid for/);
  });

  function signOf(bytes: Uint8Array): Uint8Array[] {
    const sig = secp256k1.sign(sha256(bytes), privKey);
    return [concatBytes(sig.toCompactRawBytes(), new Uint8Array([sig.recovery]))];
  }
});
