import { ed25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import { cborDecode } from '../src/cbor/decode';
import { cborEncode } from '../src/cbor/encode';
import {
  asBytes,
  asMap,
  asText,
  asUint,
  cbArray,
  cbBool,
  cbBytes,
  cbMap,
  cbTag,
  cbText,
  cbUint,
  mapGet,
} from '../src/cbor/model';
import { TonDataType } from '../src/chains/ton';
import { bytesToHex, concatBytes, utf8Encode } from '../src/core/bytes';
import { EraAccounts, EraConnect, type EraSdkError, Ur } from '../src/index';
import { verifyTonSignature } from '../src/verify/ton';
import { bocRootHash } from '../src/verify/ton-boc';

const era = new EraConnect({ origin: 'TON Test' });
const requestId = new Uint8Array(Array.from({ length: 16 }, (_, i) => i + 1));
const UUID_STRING = '01020304-0506-0708-090a-0b0c0d0e0f10';

// --- hand-built BoC helpers (test-side only) --------------------------------

/** Serialize a tiny generic BoC (refSize 1, offSize 1, no index/crc). */
function bocOf(cells: { bits: number; data: number[]; refs: number[] }[]): Uint8Array {
  const body: number[] = [];
  for (const c of cells) {
    const dataBytes = (c.bits + 7) >> 3;
    const incomplete = c.bits % 8 !== 0;
    body.push(c.refs.length, dataBytes * 2 - (incomplete ? 1 : 0));
    const data = [...c.data];
    if (incomplete) {
      const shift = 7 - (c.bits % 8);
      const last = dataBytes - 1;
      data[last] = ((data[last] ?? 0) | (1 << shift)) & (0xff << shift) & 0xff;
    }
    body.push(...data.slice(0, dataBytes), ...c.refs);
  }
  return new Uint8Array([
    0xb5,
    0xee,
    0x9c,
    0x72, // magic
    0x01, // flags: no idx/crc, refSize 1
    0x01, // offSize 1
    cells.length,
    0x01,
    0x00, // cells, roots, absent
    body.length, // tot cell size (unchecked)
    0x00, // root index 0
    ...body,
  ]);
}

/** Independent representation-hash computation for the KAT (no shared code path). */
function reprHash(
  cell: { bits: number; data: number[] },
  children: { depth: number; hash: Uint8Array }[],
): { depth: number; hash: Uint8Array } {
  const dataBytes = (cell.bits + 7) >> 3;
  const incomplete = cell.bits % 8 !== 0;
  const repr = [
    children.length,
    dataBytes * 2 - (incomplete ? 1 : 0),
    ...cell.data.slice(0, dataBytes),
  ];
  if (incomplete) {
    const shift = 7 - (cell.bits % 8);
    const last = repr.length - 1;
    repr[last] = ((repr[last] ?? 0) | (1 << shift)) & (0xff << shift) & 0xff;
  }
  for (const child of children) repr.push(child.depth >> 8, child.depth & 0xff);
  let bytes: Uint8Array = new Uint8Array(repr);
  for (const child of children) bytes = concatBytes(bytes, child.hash);
  const depth = children.length === 0 ? 0 : Math.max(...children.map((c) => c.depth)) + 1;
  return { depth, hash: sha256(bytes) };
}

describe('TON request wire shape', () => {
  const request = era.ton.generateSignRequest({
    requestId,
    signData: bocOf([{ bits: 16, data: [0xab, 0xcd], refs: [] }]),
    path: "m/44'/607'/0'",
    xfp: 'deadbeef',
    address: 'UQABCDEFtestaddress',
  });

  it('carries the request id as tag-37 ASCII UUID-string bytes (the ecosystem quirk)', () => {
    const map = asMap(cborDecode(request.ur.cbor))!;
    const idValue = mapGet(map, 1)!;
    expect(idValue.kind === 'tag' && idValue.tag).toBe(37);
    const idBytes = asBytes(idValue)!;
    expect(idBytes.length).toBe(36);
    expect(String.fromCharCode(...idBytes)).toBe(UUID_STRING);
    expect(Number(asUint(mapGet(map, 3)))).toBe(TonDataType.transaction);
    expect(asText(mapGet(map, 5))).toBe('UQABCDEFtestaddress');
    expect(asText(mapGet(map, 6))).toBe('TON Test');
    expect(request.ur.type).toBe('ton-sign-request');
    expect(request.replyTypes).toEqual(['ton-signature']);
  });

  it('pins the request CBOR golden', () => {
    // Self-golden: any byte change here is a wire-format change and must be deliberate.
    expect(bytesToHex(request.ur.cbor)).toMatchInlineSnapshot(
      `"a601d825582430313032303330342d303530362d303730382d303930612d306230633064306530663130024fb5ee9c72010101010004000004abcd030104d90130a20186182cf519025ff500f5021adeadbeef0573555141424344454674657374616464726573730668544f4e2054657374"`,
    );
  });
});

describe('TON reply parsing', () => {
  const priv = new Uint8Array(32).fill(6);
  const pub = ed25519.getPublicKey(priv);
  const boc = bocOf([{ bits: 16, data: [0xab, 0xcd], refs: [] }]);
  const request = era.ton.generateSignRequest({
    requestId,
    signData: boc,
    path: "m/44'/607'/0'",
    xfp: 'deadbeef',
  });

  function reply(echo: Parameters<typeof cbTag>[1], sig: Uint8Array): Ur {
    return new Ur(
      'ton-signature',
      cborEncode(
        cbMap([
          [1, cbTag(37, echo)],
          [2, cbBytes(sig)],
          [3, cbText('ERA Wallet')],
        ]),
      ),
    );
  }

  const signature = ed25519.sign(bocRootHash(boc), priv);

  it('accepts the string-bytes echo and verifies the BoC root hash signature', () => {
    const scanner = request.scanner();
    scanner.receivePart(reply(cbBytes(utf8Encode(UUID_STRING)), signature).toWireString());
    const parsed = scanner.parse();
    expect(parsed.requestId).toEqual(requestId);
    expect(
      verifyTonSignature({
        signData: boc,
        dataType: TonDataType.transaction,
        signature: parsed.signature,
        publicKey: pub,
      }),
    ).toEqual({ ok: true, checked: true });
  });

  it('accepts a raw 16-byte binary echo (forward compatibility)', () => {
    const parsed = era.ton.parseSignature(reply(cbBytes(requestId), signature), { requestId });
    expect(parsed.signature).toEqual(signature);
  });

  it('refuses a stale echo', () => {
    const stale = reply(cbBytes(utf8Encode('99999999-0506-0708-090a-0b0c0d0e0f10')), signature);
    try {
      era.ton.parseSignature(stale, { requestId });
      expect.unreachable();
    } catch (e) {
      expect((e as EraSdkError).code).toBe('request-id-mismatch');
    }
  });

  it('verifies the TON Connect proof digest', () => {
    const payload = utf8Encode('ton-proof-item-v2/example');
    const digest = sha256(
      concatBytes(new Uint8Array([0xff, 0xff]), utf8Encode('ton-connect'), sha256(payload)),
    );
    const proofSig = ed25519.sign(digest, priv);
    expect(
      verifyTonSignature({
        signData: payload,
        dataType: TonDataType.tonProof,
        signature: proofSig,
        publicKey: pub,
      }),
    ).toEqual({ ok: true, checked: true });
    const wrong = verifyTonSignature({
      signData: utf8Encode('other payload'),
      dataType: TonDataType.tonProof,
      signature: proofSig,
      publicKey: pub,
    });
    expect(wrong.ok).toBe(false);
  });
});

describe('BoC root hash (KAT against an independent computation)', () => {
  it('single incomplete-byte cell', () => {
    const cell = { bits: 13, data: [0xf0, 0xf0], refs: [] };
    expect(bytesToHex(bocRootHash(bocOf([cell])))).toBe(bytesToHex(reprHash(cell, []).hash));
  });

  it('root with two children (depths + hashes concatenated)', () => {
    const childA = { bits: 8, data: [0x11], refs: [] };
    const childB = { bits: 4, data: [0x20], refs: [] };
    const root = { bits: 16, data: [0xde, 0xad], refs: [1, 2] };
    const ha = reprHash(childA, []);
    const hb = reprHash(childB, []);
    const expected = reprHash(root, [ha, hb]).hash;
    expect(bytesToHex(bocRootHash(bocOf([root, childA, childB])))).toBe(bytesToHex(expected));
  });

  it('refuses malformed input: magic, backward refs, truncation, size bombs', () => {
    expect(() => bocRootHash(new Uint8Array([1, 2, 3]))).toThrow();
    expect(() => bocRootHash(new Uint8Array(12).fill(0xaa))).toThrowError(/generic BoC/);
    // backward reference (cell 1 refers to cell 0)
    const backward = bocOf([
      { bits: 8, data: [0x01], refs: [1] },
      { bits: 8, data: [0x02], refs: [0] },
    ]);
    expect(() => bocRootHash(backward)).toThrowError(/non-topological/);
    const truncated = bocOf([{ bits: 64, data: [1, 2, 3, 4, 5, 6, 7, 8], refs: [] }]).slice(0, 14);
    expect(() => bocRootHash(truncated)).toThrow();
  });
});

describe('TON linking (Tonkeeper-style standalone crypto-hdkey)', () => {
  const pub = ed25519.getPublicKey(new Uint8Array(32).fill(3));
  const hdkey = cborEncode(
    cbMap([
      [3, cbBytes(pub)],
      [
        6,
        cbTag(
          304,
          cbMap([
            [
              1,
              cbArray([
                cbUint(44),
                cbBool(true),
                cbUint(607),
                cbBool(true),
                cbUint(0),
                cbBool(true),
              ]),
            ],
            [2, cbUint(0xdeadbeef)],
          ]),
        ),
      ],
      [10, cbText('ERA_Main')],
    ]),
  );

  it('parses the {3,6,10} minimal shape into a TON view', () => {
    const accounts = EraAccounts.fromUr(new Ur('crypto-hdkey', hdkey));
    expect(accounts.masterFingerprint).toBe('deadbeef');
    const ton = accounts.ton()!;
    expect(ton.accountPath).toBe("m/44'/607'/0'");
    expect(ton.xfp).toBe('deadbeef');
    expect(ton.publicKey).toEqual(pub);
    expect(ton.name).toBe('ERA_Main');
    expect(accounts.keys[0]?.chain).toBe('ton');
  });
});
