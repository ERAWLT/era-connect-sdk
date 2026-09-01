import { secp256k1 } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha2';
import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import { EraAccounts } from '../src/accounts/accounts';
import { bchAddressFromPublicKey } from '../src/accounts/derive';
import { cborDecode } from '../src/cbor/decode';
import { cborEncode } from '../src/cbor/encode';
import type { CborValue } from '../src/cbor/model';
import {
  asBytes,
  cbArray,
  cbBool,
  cbBytes,
  cbMap,
  cbTag,
  cbText,
  cbUint,
  mapGet,
} from '../src/cbor/model';
import { BchChain } from '../src/chains/bch';
import { decodeCashAddr, encodeCashAddr } from '../src/chains/cashaddr';
import { bytesToHex, concatBytes, hexToBytes } from '../src/core/bytes';
import { EraSdkError } from '../src/core/errors';
import { gunzipCapped, gzipCompress } from '../src/tron-proto/gzip';
import { ProtoWriter, readFields } from '../src/tron-proto/wire';
import { Ur } from '../src/ur/ur';
import { computeBchSighash, decodeBchRawTx, verifyBchSignedTx } from '../src/verify/bch';

const TEST_SEED = hexToBytes(
  '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
);

// ---------------------------------------------------------------------------
// CashAddr codec
// ---------------------------------------------------------------------------

describe('cashaddr codec', () => {
  // The spec's own legacy-translation examples (hash160 extracted via
  // base58check and cross-checked against an independent implementation).
  const SPEC_VECTORS: Array<['p2pkh' | 'p2sh', string, string]> = [
    [
      'p2pkh',
      '76a04053bda0a88bda5177b86a15c3b29f559873',
      'qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a',
    ],
    [
      'p2pkh',
      'cb481232299cd5743151ac4b2d63ae198e7bb0a9',
      'qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy',
    ],
    [
      'p2sh',
      '76a04053bda0a88bda5177b86a15c3b29f559873',
      'ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq',
    ],
  ];

  it('encodes the spec vectors', () => {
    for (const [type, hash, expected] of SPEC_VECTORS) {
      expect(encodeCashAddr(type, hexToBytes(hash))).toBe(expected);
      expect(encodeCashAddr(type, hexToBytes(hash), { withPrefix: true })).toBe(
        `bitcoincash:${expected}`,
      );
    }
  });

  it('decodes bare, prefixed and uppercase forms to the same payload', () => {
    for (const [type, hash, addr] of SPEC_VECTORS) {
      for (const form of [addr, `bitcoincash:${addr}`, addr.toUpperCase()]) {
        const decoded = decodeCashAddr(form);
        expect(decoded.type).toBe(type);
        expect(bytesToHex(decoded.hash)).toBe(hash);
      }
    }
  });

  it('refuses mixed case, a corrupted checksum, and a foreign prefix', () => {
    const addr = SPEC_VECTORS[0]![2];
    expect(() => decodeCashAddr(`${addr.slice(0, -1)}A`)).toThrow(EraSdkError);
    const flipped = addr.slice(0, -1) + (addr.endsWith('a') ? 'q' : 'a');
    expect(() => decodeCashAddr(flipped)).toThrow(/checksum/);
    expect(() => decodeCashAddr(`bchtest:${addr}`)).toThrow(/prefix/);
  });

  it('round-trips random hashes through both script types', () => {
    for (let i = 0; i < 32; i++) {
      const hash = sha256(new Uint8Array([i])).slice(0, 20);
      for (const type of ['p2pkh', 'p2sh'] as const) {
        const decoded = decodeCashAddr(encodeCashAddr(type, hash));
        expect(decoded.type).toBe(type);
        expect(bytesToHex(decoded.hash)).toBe(bytesToHex(hash));
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Envelope construction
// ---------------------------------------------------------------------------

const RECEIVE_PATH = "m/44'/145'/0'/0/0";
const CHANGE_PATH = "m/44'/145'/0'/1/0";

function testKeys() {
  const master = HDKey.fromMasterSeed(TEST_SEED);
  return {
    receive: master.derive(RECEIVE_PATH),
    change: master.derive(CHANGE_PATH),
  };
}

function baseProps(chain: { receive: HDKey; change: HDKey }) {
  const receiveAddr = bchAddressFromPublicKey(chain.receive.publicKey!);
  const changeAddr = bchAddressFromPublicKey(chain.change.publicKey!);
  return {
    requestId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
    inputs: [
      {
        txid: '142f52b7d109437403e50b1ff738b5ba5d1dc80c71b7d48c9eca347ca66a144a',
        index: 0,
        value: 250000,
        publicKey: chain.receive.publicKey!,
        path: RECEIVE_PATH,
      },
    ],
    outputs: [
      { address: receiveAddr, value: 80000 },
      { address: changeAddr, value: 169000, isChange: true, changeAddressPath: CHANGE_PATH },
    ],
    fee: 1000,
    xfp: 0x12345678,
    timestamp: 1700000000000,
  };
}

function protoOf(ur: Ur): Uint8Array {
  const map = cborDecode(ur.cbor);
  return gunzipCapped(asBytes(mapGet(map, 1))!, 64 * 1024);
}

describe('bch sign request envelope', () => {
  const chain = new BchChain();
  const keys = testKeys();

  it('emits the Base/Payload/SignTransaction/BchTx protobuf shape', () => {
    const request = chain.generateSignRequest(baseProps(keys));
    expect(request.ur.type).toBe('keystone-sign-request');
    const proto = protoOf(request.ur);

    const base = readFields(proto);
    expect(base.find((f) => f.field === 1)?.value).toBe(2n);
    const payload = readFields(base.find((f) => f.field === 3)!.bytes);
    expect(payload.find((f) => f.field === 1)?.value).toBe(2n);
    expect(new TextDecoder().decode(payload.find((f) => f.field === 2)!.bytes)).toBe('12345678');
    const signTx = readFields(payload.find((f) => f.field === 4)!.bytes);
    expect(new TextDecoder().decode(signTx.find((f) => f.field === 1)!.bytes)).toBe('BCH');
    expect(new TextDecoder().decode(signTx.find((f) => f.field === 2)!.bytes)).toBe(
      '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
    );
    expect(signTx.find((f) => f.field === 3)).toBeUndefined(); // no hdPath — per-input paths rule
    expect(signTx.find((f) => f.field === 4)?.value).toBe(1700000000000n);
    expect(signTx.find((f) => f.field === 5)?.value).toBe(8n);

    const bchTx = readFields(signTx.find((f) => f.field === 10)!.bytes);
    expect(bchTx.find((f) => f.field === 1)?.value).toBe(1000n);
    expect(bchTx.find((f) => f.field === 2)?.value).toBe(546n);
    const props = baseProps(keys);
    const input = readFields(bchTx.find((f) => f.field === 4)!.bytes);
    expect(new TextDecoder().decode(input.find((f) => f.field === 1)!.bytes)).toBe(
      props.inputs[0]!.txid,
    );
    expect(input.find((f) => f.field === 2)).toBeUndefined(); // index 0 omitted (proto3)
    expect(input.find((f) => f.field === 3)?.value).toBe(250000n);
    expect(new TextDecoder().decode(input.find((f) => f.field === 4)!.bytes)).toBe(
      bytesToHex(keys.receive.publicKey!),
    );
    expect(new TextDecoder().decode(input.find((f) => f.field === 5)!.bytes)).toBe(RECEIVE_PATH);
    const outputs = bchTx.filter((f) => f.field === 5);
    expect(outputs).toHaveLength(2);
    const first = readFields(outputs[0]!.bytes);
    expect(new TextDecoder().decode(first.find((f) => f.field === 1)!.bytes)).toBe(
      props.outputs[0]!.address,
    );
    expect(first.find((f) => f.field === 2)?.value).toBe(80000n);
    const change = readFields(outputs[1]!.bytes);
    expect(new TextDecoder().decode(change.find((f) => f.field === 1)!.bytes)).toBe(
      props.outputs[1]!.address,
    );
    expect(change.find((f) => f.field === 2)?.value).toBe(169000n);
    expect(change.find((f) => f.field === 3)?.value).toBe(1n);
    expect(new TextDecoder().decode(change.find((f) => f.field === 4)!.bytes)).toBe(CHANGE_PATH);
  });

  it('refuses a fee that does not equal inputs minus outputs', () => {
    expect(() => chain.generateSignRequest({ ...baseProps(keys), fee: 1001 })).toThrow(
      /fee mismatch/,
    );
  });

  it('refuses malformed inputs and outputs', () => {
    const props = baseProps(keys);
    expect(() =>
      chain.generateSignRequest({
        ...props,
        inputs: [{ ...props.inputs[0]!, txid: 'nope' }],
      }),
    ).toThrow(/txid/);
    expect(() =>
      chain.generateSignRequest({
        ...props,
        inputs: [{ ...props.inputs[0]!, publicKey: new Uint8Array(32) }],
      }),
    ).toThrow(/public key/);
    // Fee-consistent sums, so ONLY the address gate can be what throws — a
    // bare EraSdkError assert here was satisfiable by the fee check alone.
    expect(() =>
      chain.generateSignRequest({
        ...props,
        outputs: [
          { address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', value: 80000 },
          props.outputs[1]!,
        ],
      }),
    ).toThrow(/cashaddr/);
    // Unicode case-folding trick: U+212A KELVIN SIGN folds to 'k' but is not ASCII.
    expect(() =>
      chain.generateSignRequest({
        ...props,
        outputs: [
          { address: 'qpm2qsznhKs23z7629mms6s4cwef74vcwvy22gdx6a', value: 80000 },
          props.outputs[1]!,
        ],
      }),
    ).toThrow(/character/);
    expect(() => chain.generateSignRequest({ ...props, inputs: [] })).toThrow(/input/);
    expect(() => chain.generateSignRequest({ ...props, outputs: [] })).toThrow(/output/);
  });
});

// ---------------------------------------------------------------------------
// Reply parsing + verification (device emulation)
// ---------------------------------------------------------------------------

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function p2pkhScript(pubkeyHash: Uint8Array): Uint8Array {
  return concatBytes(new Uint8Array([0x76, 0xa9, 0x14]), pubkeyHash, new Uint8Array([0x88, 0xac]));
}

function le32(value: number): Uint8Array {
  return new Uint8Array([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
}

function le64(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/**
 * Emulate the device's FORKID signer: version 1, locktime 0, sequence
 * 0xfffffffd, P2PKH outputs from the request addresses, per-input BIP-143
 * sighash with FORKID, DER + 0x41 scriptSig.
 */
function emulateDeviceSigning(
  props: ReturnType<typeof baseProps>,
  keys: ReturnType<typeof testKeys>,
): string {
  const txStructure = {
    version: 1,
    inputs: props.inputs.map((input) => ({
      txidLE: hexToBytes(input.txid).reverse(),
      index: input.index,
      scriptSig: new Uint8Array(0),
      sequence: 0xfffffffd,
    })),
    outputs: props.outputs.map((output) => ({
      value: BigInt(output.value),
      script: p2pkhScript(decodeCashAddr(output.address).hash),
    })),
    locktime: 0,
  };

  const scriptSigs = props.inputs.map((input, i) => {
    const key = keys.receive; // single-input fixture: the receive key owns it
    const sighash = computeBchSighash({
      tx: txStructure,
      inputIndex: i,
      scriptCode: p2pkhScript(hash160(key.publicKey!)),
      value: BigInt(input.value),
    });
    const der = secp256k1.sign(sighash, key.privateKey!, { lowS: true }).toDERRawBytes();
    const sigWithType = concatBytes(der, new Uint8Array([0x41]));
    return concatBytes(
      new Uint8Array([sigWithType.length]),
      sigWithType,
      new Uint8Array([33]),
      key.publicKey!,
    );
  });

  const parts: Uint8Array[] = [le32(1), new Uint8Array([props.inputs.length])];
  for (let i = 0; i < props.inputs.length; i++) {
    parts.push(
      txStructure.inputs[i]!.txidLE,
      le32(props.inputs[i]!.index),
      new Uint8Array([scriptSigs[i]!.length]),
      scriptSigs[i]!,
      le32(0xfffffffd),
    );
  }
  parts.push(new Uint8Array([props.outputs.length]));
  for (const output of txStructure.outputs) {
    parts.push(le64(output.value), new Uint8Array([output.script.length]), output.script);
  }
  parts.push(le32(0));
  return bytesToHex(concatBytes(...parts));
}

function buildReplyUr(signId: string, txId: string, rawTx: string): Ur {
  const result = new ProtoWriter()
    .stringField(1, signId)
    .stringField(2, txId)
    .stringField(3, rawTx)
    .finish();
  const payload = new ProtoWriter()
    .varintField(1, 9)
    .stringField(2, '12345678')
    .messageField(7, result)
    .finish();
  const proto = new ProtoWriter()
    .varintField(1, 1)
    .stringField(2, 'keystone qrcode')
    .messageField(3, payload)
    .finish();
  return new Ur('keystone-sign-result', cborEncode(cbMap([[1, cbBytes(gzipCompress(proto))]])));
}

function sha256d(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

describe('bch reply parsing and verification', () => {
  const chain = new BchChain();
  const keys = testKeys();
  const props = baseProps(keys);
  const rawTx = emulateDeviceSigning(props, keys);
  const txId = bytesToHex(sha256d(hexToBytes(rawTx)).reverse());

  it('parses the reply and enforces the signId echo', () => {
    const reply = buildReplyUr(props.requestId, txId, rawTx);
    const result = chain.parseSignature(reply, { requestId: props.requestId });
    expect(result.rawTx).toBe(rawTx);
    expect(result.txId).toBe(txId);

    expect(() =>
      chain.parseSignature(reply, { requestId: '00000000-0000-4000-8000-000000000000' }),
    ).toThrow(/request id/);
  });

  it('accepts an uppercase signId echo (the device echoes verbatim)', () => {
    const reply = buildReplyUr(props.requestId.toUpperCase(), txId, rawTx);
    const result = chain.parseSignature(reply, { requestId: props.requestId });
    expect(result.txId).toBe(txId);
  });

  it('verifies the emulated device transaction end-to-end', () => {
    const result = verifyBchSignedTx({ rawTx, inputs: props.inputs, outputs: props.outputs, txId });
    expect(result).toEqual({ ok: true, checked: true });
  });

  it('decodes the raw transaction into the expected structure', () => {
    const tx = decodeBchRawTx(rawTx);
    expect(tx.version).toBe(1);
    expect(tx.locktime).toBe(0);
    expect(tx.inputs[0]!.sequence).toBe(0xfffffffd);
    expect(tx.outputs.map((o) => o.value)).toEqual([80000n, 169000n]);
  });

  it('fails on a tampered output value', () => {
    const outputs = [{ ...props.outputs[0]!, value: 80001 }, props.outputs[1]!];
    const result = verifyBchSignedTx({ rawTx, inputs: props.inputs, outputs });
    expect(result.ok).toBe(false);
  });

  it('fails on a substituted destination address', () => {
    const outputs = [
      { ...props.outputs[0]!, address: props.outputs[1]!.address },
      props.outputs[1]!,
    ];
    const result = verifyBchSignedTx({ rawTx, inputs: props.inputs, outputs });
    expect(result.ok).toBe(false);
  });

  it('fails when the request named a different owner key', () => {
    const inputs = [{ ...props.inputs[0]!, publicKey: keys.change.publicKey! }];
    const result = verifyBchSignedTx({ rawTx, inputs, outputs: props.outputs });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/different public key/);
  });

  it('fails on a different outpoint', () => {
    const inputs = [{ ...props.inputs[0]!, index: 1 }];
    const result = verifyBchSignedTx({ rawTx, inputs, outputs: props.outputs });
    expect(result.ok).toBe(false);
  });

  it('fails on a corrupted signature and on a wrong sighash type byte', () => {
    const bytes = hexToBytes(rawTx);
    // The DER signature starts at offset 4 (version) + 32 (txid) + 4 (vout) +
    // 1 (script len) + 1 (sig push len); flip a byte deep inside it.
    const sigStart = 4 + 32 + 4 + 2;
    const corrupted = Uint8Array.from(bytes);
    corrupted[sigStart + 10]! ^= 0x01;
    expect(
      verifyBchSignedTx({
        rawTx: bytesToHex(corrupted),
        inputs: props.inputs,
        outputs: props.outputs,
      }).ok,
    ).toBe(false);

    const tx = decodeBchRawTx(rawTx);
    const sigLen = tx.inputs[0]!.scriptSig[0]!;
    const typeByteOffset = sigStart + sigLen - 1;
    const wrongType = Uint8Array.from(bytes);
    wrongType[typeByteOffset] = 0x01; // SIGHASH_ALL without FORKID
    const result = verifyBchSignedTx({
      rawTx: bytesToHex(wrongType),
      inputs: props.inputs,
      outputs: props.outputs,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/sighash/);
  });

  it('refuses parameters the device signer cannot have produced', () => {
    // locktime is the last 4 bytes of the serialization; the pin must fire
    // BEFORE any signature math, catching a reply no ERA signer built.
    const bytes = hexToBytes(rawTx);
    bytes[bytes.length - 4] = 0x01;
    const result = verifyBchSignedTx({
      rawTx: bytesToHex(bytes),
      inputs: props.inputs,
      outputs: props.outputs,
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/locktime/);
  });

  it('fails when the reply txId does not match the raw bytes', () => {
    const result = verifyBchSignedTx({
      rawTx,
      inputs: props.inputs,
      outputs: props.outputs,
      txId: txId.replace(/^../, '00'),
    });
    expect(result.ok).toBe(false);
  });
});

describe('address canonicalization on the wire', () => {
  const chain = new BchChain();
  const keys = testKeys();

  function wireAddresses(props: ReturnType<typeof baseProps>): string[] {
    const proto = protoOf(chain.generateSignRequest(props).ur);
    const base = readFields(proto);
    const payload = readFields(base.find((f) => f.field === 3)!.bytes);
    const signTx = readFields(payload.find((f) => f.field === 4)!.bytes);
    const bchTx = readFields(signTx.find((f) => f.field === 10)!.bytes);
    return bchTx
      .filter((f) => f.field === 5)
      .map((f) => {
        const fields = readFields(f.bytes);
        return new TextDecoder().decode(fields.find((x) => x.field === 1)!.bytes);
      });
  }

  it('rewrites an uppercase (QR alphanumeric) address to the lowercase form', () => {
    // The device's parser reads ONLY lowercase: its prefix rebuild makes an
    // uppercase body mixed-case, the decode fails, and the failure falls
    // open into a zero pubkey hash — a signed burn. The SDK must therefore
    // never forward the caller's spelling.
    const props = baseProps(keys);
    const upper = props.outputs[0]!.address.toUpperCase();
    const addresses = wireAddresses({
      ...props,
      outputs: [{ ...props.outputs[0]!, address: upper }, props.outputs[1]!],
    });
    expect(addresses[0]).toBe(props.outputs[0]!.address);
  });

  it('keeps the prefix presence but canonicalizes its case', () => {
    const props = baseProps(keys);
    const prefixedUpper = `BITCOINCASH:${props.outputs[0]!.address.toUpperCase()}`;
    const addresses = wireAddresses({
      ...props,
      outputs: [{ ...props.outputs[0]!, address: prefixedUpper }, props.outputs[1]!],
    });
    expect(addresses[0]).toBe(`bitcoincash:${props.outputs[0]!.address}`);
  });
});

describe('sighash known-answer test', () => {
  it('matches an independently computed BIP-143 FORKID digest', () => {
    // Frozen from an implementation written separately from this codebase —
    // the committed regression pin for the one digest the SDK computes
    // itself. (Correctness against the real device is proven by the
    // env-gated firmware-corpus leg.)
    const digest = computeBchSighash({
      tx: {
        version: 1,
        inputs: [
          {
            txidLE: hexToBytes('22'.repeat(32)).reverse(),
            index: 3,
            scriptSig: new Uint8Array(0),
            sequence: 0xfffffffd,
          },
        ],
        outputs: [{ value: 100000n, script: hexToBytes(`76a914${'44'.repeat(20)}88ac`) }],
        locktime: 0,
      },
      inputIndex: 0,
      scriptCode: hexToBytes(`76a914${'33'.repeat(20)}88ac`),
      value: 123456n,
    });
    expect(bytesToHex(digest)).toBe(
      '15df3f55c278d29e17d7b93e7f790516703b76c823f3ed1abdc7998e68da75b0',
    );
  });
});

// ---------------------------------------------------------------------------
// Accounts view
// ---------------------------------------------------------------------------

function pathComponents(levels: [number, boolean][]): CborValue {
  const items: CborValue[] = [];
  for (const [index, hardened] of levels) items.push(cbUint(index), cbBool(hardened));
  return cbArray(items);
}

describe('bch account view', () => {
  const master = HDKey.fromMasterSeed(TEST_SEED);
  const account = master.derive("m/44'/145'/0'");
  const walletCbor = cborEncode(
    cbMap([
      [1, cbUint(master.fingerprint >>> 0)],
      [
        2,
        cbArray([
          cbMap([
            [3, cbBytes(account.publicKey!)],
            [4, cbBytes(account.chainCode!)],
            [
              6,
              cbTag(
                304,
                cbMap([
                  [
                    1,
                    pathComponents([
                      [44, true],
                      [145, true],
                      [0, true],
                    ]),
                  ],
                  [2, cbUint(master.fingerprint >>> 0)],
                ]),
              ),
            ],
            [8, cbUint(account.parentFingerprint >>> 0)],
          ]),
        ]),
      ],
      [3, cbText('ERA Wallet')],
    ]),
  );
  const accounts = EraAccounts.fromUr(new Ur('crypto-multi-accounts', walletCbor));

  it('derives the published first addresses of the test seed', () => {
    const bch = accounts.bch()!;
    // The first BIP-44 coin-145 receive address of the standard test seed —
    // cross-checked against an independent CashAddr implementation.
    expect(bch.deriveAddress(0)).toBe('qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6');
    expect(bch.deriveAddress(1)).toBe('qp8sfdhgjlq68hlzka9lcsxtcnvuvnd0xqxugfzzc5');
    expect(bch.deriveAddress(0, { change: true })).toBe(
      'qr8aeharupyrmhfu0d4tdmsnc5y8cfk47y6qrsjsrx',
    );
    expect(bch.deriveAddress(0, { withPrefix: true })).toBe(
      'bitcoincash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnq5tahq3q6',
    );
    expect(bch.receivePath(0)).toBe("m/44'/145'/0'/0/0");
    expect(bch.changePath(0)).toBe("m/44'/145'/0'/1/0");
  });

  it('exposes the compressed public key a sign-request input names', () => {
    const bch = accounts.bch()!;
    expect(bytesToHex(bch.derivePublicKey(0))).toBe(
      bytesToHex(master.derive("m/44'/145'/0'/0/0").publicKey!),
    );
  });
});
