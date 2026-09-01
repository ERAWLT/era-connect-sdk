import { blake2b } from '@noble/hashes/blake2b';
import { describe, expect, it } from 'vitest';
import { cardanoSoftDerivePath } from '../src/accounts/derive';
import { cborDecode } from '../src/cbor/decode';
import { cborEncode } from '../src/cbor/encode';
import {
  asArray,
  asBytes,
  asMap,
  asText,
  asUint,
  cbArray,
  cbBytes,
  cbMap,
  cbTag,
  cbText,
  cbUint,
  mapGet,
  stripTags,
} from '../src/cbor/model';
import { parseWitnessSet } from '../src/chains/cardano';
import { bytesToHex, utf8Encode } from '../src/core/bytes';
import { EraConnect, type EraSdkError, Ur } from '../src/index';
import { firstArrayItemBytes, verifyCardanoSignature } from '../src/verify/cardano';
import { derivePath, extendedSign, icarusMasterFromEntropy, publicKeyOf } from './helpers/icarus';

const era = new EraConnect({ origin: 'ADA Test' });
const requestId = new Uint8Array(Array.from({ length: 16 }, (_, i) => i + 1));
const txHash32 = new Uint8Array(32).fill(0xaa);

/** A tiny plausible tx CBOR: [bodyMap, {}, true, null]. */
const txBody = cbMap([
  [0, cbArray([cbArray([cbBytes(txHash32), cbUint(0)])])],
  [2, cbUint(170000)],
]);
const signData = cborEncode(
  cbArray([txBody, cbMap([]), { kind: 'bool', value: true }, { kind: 'null' }]),
);

describe('Cardano request wire shape', () => {
  const request = era.cardano.generateSignRequest({
    requestId,
    signData,
    utxos: [
      {
        transactionHash: txHash32,
        index: 0,
        amount: '2000000',
        path: "m/1852'/1815'/0'/0/0",
        xfp: 'deadbeef',
        address: 'addr1qtestaddress',
      },
    ],
    certKeys: [{ path: "m/1852'/1815'/0'/2/0", xfp: 'deadbeef' }],
  });

  it('emits {1: uuid37, 2: signData, 3: [2201 utxo], 4: [2204 certKey], 5: origin}', () => {
    const map = asMap(cborDecode(request.ur.cbor))!;
    expect(request.ur.type).toBe('cardano-sign-request');
    const utxoList = asArray(mapGet(map, 3))!;
    const utxoTagged = utxoList[0]!;
    expect(utxoTagged.kind === 'tag' && utxoTagged.tag).toBe(2201);
    const utxo = asMap(utxoTagged)!;
    expect(asBytes(mapGet(utxo, 1))).toEqual(txHash32);
    expect(Number(asUint(mapGet(utxo, 2)))).toBe(0);
    expect(asText(mapGet(utxo, 3))).toBe('2000000');
    expect(asText(mapGet(utxo, 5))).toBe('addr1qtestaddress');
    const certList = asArray(mapGet(map, 4))!;
    expect(certList[0]!.kind === 'tag' && certList[0]!.tag).toBe(2204);
    expect(asText(mapGet(map, 5))).toBe('ADA Test');
    expect(request.replyTypes).toEqual(['cardano-signature']);
  });

  it('pins the request CBOR golden', () => {
    expect(bytesToHex(request.ur.cbor)).toMatchInlineSnapshot(
      `"a501d825500102030405060708090a0b0c0d0e0f1002583184a20081825820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00021a00029810a0f5f60381d90899a5015820aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa020003673230303030303004d90130a2018a19073cf5190717f500f500f400f4021adeadbeef057161646472317174657374616464726573730481d9089ca102d90130a2018a19073cf5190717f500f502f400f4021adeadbeef05684144412054657374"`,
    );
  });
});

describe('the tx-body digest walker', () => {
  it('extracts the encoded first element of a definite array', () => {
    const body = firstArrayItemBytes(signData);
    expect(bytesToHex(body)).toBe(bytesToHex(cborEncode(txBody)));
  });

  it('handles an indefinite-length outer array', () => {
    const definiteBody = cborEncode(txBody);
    const indefinite = new Uint8Array([0x9f, ...definiteBody, ...cborEncode(cbMap([])), 0xff]);
    expect(bytesToHex(firstArrayItemBytes(indefinite))).toBe(bytesToHex(definiteBody));
  });

  it('refuses non-arrays and empty arrays', () => {
    expect(() => firstArrayItemBytes(cborEncode(cbMap([])))).toThrowError(/array/);
    expect(() => firstArrayItemBytes(cborEncode(cbArray([])))).toThrowError(/empty/);
  });
});

describe('Icarus end-to-end: private-side signing vs SDK public-side verification', () => {
  // Deterministic entropy → account xprv → child 0/0 signs; the SDK, holding
  // only the PUBLIC account key material (like a linked wallet), must derive
  // the same child vkey and verify the witness.
  const entropy = new Uint8Array(Array.from({ length: 32 }, (_, i) => (i * 11) % 251));
  const master = icarusMasterFromEntropy(entropy);
  const account = derivePath(master, [
    { index: 1852, hardened: true },
    { index: 1815, hardened: true },
    { index: 0, hardened: true },
  ]);
  const accountPub = publicKeyOf(account.kL);
  const digest = blake2b(firstArrayItemBytes(signData), { dkLen: 32 });

  const paymentKey = derivePath(account, [
    { index: 0, hardened: false },
    { index: 0, hardened: false },
  ]);
  const witness = { vkey: publicKeyOf(paymentKey.kL), signature: extendedSign(paymentKey, digest) };

  it('public soft derivation matches private derivation', () => {
    const derived = cardanoSoftDerivePath(accountPub, account.chainCode, [0, 0]);
    expect(bytesToHex(derived)).toBe(bytesToHex(witness.vkey));
  });

  it('verifies a bound witness set end to end', () => {
    const witnessSet = cborEncode(
      cbMap([
        [0, cbTag(258, cbArray([cbArray([cbBytes(witness.vkey), cbBytes(witness.signature)])]))],
      ]),
    );
    expect(
      verifyCardanoSignature({
        signData,
        witnessSet,
        account: {
          publicKey: accountPub,
          chainCode: account.chainCode,
          accountPath: "m/1852'/1815'/0'",
        },
        signerPaths: ["m/1852'/1815'/0'/0/0"],
      }),
    ).toEqual({ ok: true, checked: true });
  });

  it('accepts an untagged witness array too', () => {
    const untagged = cborEncode(
      cbMap([[0, cbArray([cbArray([cbBytes(witness.vkey), cbBytes(witness.signature)])])]]),
    );
    expect(parseWitnessSet(untagged).length).toBe(1);
  });

  it('refuses a witness from a key the request did not ask for', () => {
    const foreignKey = derivePath(account, [
      { index: 0, hardened: false },
      { index: 7, hardened: false },
    ]);
    const foreign = {
      vkey: publicKeyOf(foreignKey.kL),
      signature: extendedSign(foreignKey, digest),
    };
    const result = verifyCardanoSignature({
      signData,
      witnesses: [witness, foreign],
      account: {
        publicKey: accountPub,
        chainCode: account.chainCode,
        accountPath: "m/1852'/1815'/0'",
      },
      signerPaths: ["m/1852'/1815'/0'/0/0"],
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/did not ask for/);
  });

  it('refuses when a requested signer path has no witness', () => {
    const result = verifyCardanoSignature({
      signData,
      witnesses: [witness],
      account: {
        publicKey: accountPub,
        chainCode: account.chainCode,
        accountPath: "m/1852'/1815'/0'",
      },
      signerPaths: ["m/1852'/1815'/0'/0/0", "m/1852'/1815'/0'/2/0"],
    });
    expect(result.ok).toBe(false);
    expect(!result.ok && result.reason).toMatch(/no witness/);
  });

  it('refuses a tampered transaction', () => {
    const tampered = signData.slice();
    tampered[tampered.length - 4] = (tampered[tampered.length - 4] ?? 0) ^ 0x01;
    const result = verifyCardanoSignature({ signData: tampered, witnesses: [witness] });
    expect(result.ok).toBe(false);
  });
});

describe('Cardano reply roundtrip through the scanner', () => {
  it('parses the witness set and validates the echo', () => {
    const entropy = new Uint8Array(32).fill(9);
    const master = icarusMasterFromEntropy(entropy);
    const account = derivePath(master, [
      { index: 1852, hardened: true },
      { index: 1815, hardened: true },
      { index: 0, hardened: true },
    ]);
    const request = era.cardano.generateSignRequest({
      requestId,
      signData,
      utxos: [
        { transactionHash: txHash32, index: 1, path: "m/1852'/1815'/0'/0/0", xfp: 'cafebabe' },
      ],
    });
    const digest = blake2b(firstArrayItemBytes(signData), { dkLen: 32 });
    const child = derivePath(account, [
      { index: 0, hardened: false },
      { index: 0, hardened: false },
    ]);
    const witnessSet = cborEncode(
      cbMap([
        [
          0,
          cbTag(
            258,
            cbArray([
              cbArray([cbBytes(publicKeyOf(child.kL)), cbBytes(extendedSign(child, digest))]),
            ]),
          ),
        ],
      ]),
    );
    const reply = new Ur(
      'cardano-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, cbBytes(requestId))],
          [2, cbBytes(witnessSet)],
        ]),
      ),
    );
    const scanner = request.scanner();
    scanner.receivePart(reply.toWireString());
    const parsed = scanner.parse();
    expect(parsed.witnesses.length).toBe(1);
    expect(parsed.witnessSet).toEqual(witnessSet);

    const stale = new Ur(
      'cardano-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, cbBytes(new Uint8Array(16).fill(7)))],
          [2, cbBytes(witnessSet)],
        ]),
      ),
    );
    try {
      era.cardano.parseSignature(stale, { requestId });
      expect.unreachable();
    } catch (e) {
      expect((e as EraSdkError).code).toBe('request-id-mismatch');
    }
  });
});

describe('Cardano linking (path-only origin falls back to the master fingerprint)', () => {
  it('parses a Vespr-style entry {3,4,6(path-only)}', () => {
    const entropy = new Uint8Array(32).fill(4);
    const master = icarusMasterFromEntropy(entropy);
    const account = derivePath(master, [
      { index: 1852, hardened: true },
      { index: 1815, hardened: true },
      { index: 0, hardened: true },
    ]);
    const wallet = cborEncode(
      cbMap([
        [1, cbUint(0xdeadbeef)],
        [
          2,
          cbArray([
            cbMap([
              [3, cbBytes(publicKeyOf(account.kL))],
              [4, cbBytes(account.chainCode)],
              [
                6,
                cbTag(
                  304,
                  cbMap([
                    [
                      1,
                      cbArray([
                        cbUint(1852),
                        { kind: 'bool', value: true },
                        cbUint(1815),
                        { kind: 'bool', value: true },
                        cbUint(0),
                        { kind: 'bool', value: true },
                      ]),
                    ],
                  ]),
                ),
              ], // origin[1]-only: NO source fingerprint — the device's real shape
            ]),
          ]),
        ],
        [3, cbText('ERA Wallet')],
        [5, cbText('9.9.9')],
      ]),
    );
    const accounts = era.parseAccounts(new Ur('crypto-multi-accounts', wallet));
    const ada = accounts.cardano()!;
    expect(ada.accountPath).toBe("m/1852'/1815'/0'");
    expect(ada.xfp).toBe('deadbeef'); // fell back to the wrapper master fingerprint
    expect(bytesToHex(ada.deriveKey(0, 0))).toBe(
      bytesToHex(
        publicKeyOf(
          derivePath(account, [
            { index: 0, hardened: false },
            { index: 0, hardened: false },
          ]).kL,
        ),
      ),
    );
  });
});
