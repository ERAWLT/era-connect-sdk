import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hmac } from '@noble/hashes/hmac';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { keccak_256 } from '@noble/hashes/sha3';
import { HDKey } from '@scure/bip32';
import { describe, expect, it } from 'vitest';
import { cborDecode } from '../src/cbor/decode';
import { asArray, asBool, asBytes, asMap, asUint, mapGet } from '../src/cbor/model';
import { TonDataType } from '../src/chains/ton';
import {
  bytesToHex,
  concatBytes,
  equalBytes,
  hexToBytes,
  u32be,
  utf8Encode,
} from '../src/core/bytes';
import { gunzipCapped } from '../src/tron-proto/gzip';
import { splitSignedTronTx } from '../src/tron-proto/messages';
import { UrDecoder } from '../src/ur/decoder';
import { verifyCardanoSignature } from '../src/verify/cardano';
import { parsePsbt } from '../src/verify/psbt-reader';
import { verifyTonSignature } from '../src/verify/ton';
import { verifyXrpSignature } from '../src/verify/xrp';

/**
 * LOCAL-ONLY cross-check against a device-firmware signing-fixture corpus:
 * real request URs plus reference replies, with a per-case test seed. The
 * corpus is private and NOT committed here — point ERA_FIRMWARE_FIXTURES_DIR at
 * a local copy to enable; the suite is skipped otherwise.
 *
 * The oracle is the SEED: the signer key is derived from the case's seed by
 * the request's own `crypto-keypath`, and the reply's signature must
 * recover/verify against exactly that key. (Some fixture display fields —
 * the EVM key-6 address, the Solana key-4 pubkey — reflect other derivation
 * schemes and are deliberately not the oracle.)
 */
/** Loose ASCII decode for fixture JSON payloads. */
function utf8DecodeLoose(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += String.fromCharCode(b);
  return out;
}

const dir = process.env.ERA_FIRMWARE_FIXTURES_DIR;
const enabled = dir !== undefined && existsSync(dir);

interface FixtureCase {
  name: string;
  seed: string;
  ur: string;
  expected_signature: string;
}

function loadCases(file: string): FixtureCase[] {
  return (JSON.parse(readFileSync(join(dir!, file), 'utf8')) as { cases: FixtureCase[] }).cases;
}

function decodeUrText(text: string): { type: string; cbor: Uint8Array } | null {
  const match = /ur:[a-z0-9-]+\/[a-z/0-9-]+/i.exec(text);
  if (!match) return null;
  try {
    const decoder = new UrDecoder();
    if (!decoder.receivePart(match[0])) return null;
    const ur = decoder.result();
    return { type: ur.type, cbor: ur.cbor };
  } catch {
    // The corpus carries a couple of truncated request URs (cases whose
    // reference replies are also absent); skip rather than fail on them.
    return null;
  }
}

interface Level {
  index: number;
  hardened: boolean;
}

function keypathLevels(value: ReturnType<typeof mapGet>): Level[] {
  const kp = asMap(value);
  const comps = kp ? asArray(mapGet(kp, 1)) : undefined;
  if (!comps) throw new Error('request carries no keypath');
  const out: Level[] = [];
  for (let i = 0; i < comps.length; i += 2) {
    out.push({ index: Number(asUint(comps[i])), hardened: asBool(comps[i + 1]) ?? false });
  }
  return out;
}

function secp256k1KeyFromSeed(seed: Uint8Array, path: Level[]): Uint8Array {
  let node = HDKey.fromMasterSeed(seed);
  for (const level of path) {
    node = node.deriveChild(level.hardened ? level.index + 0x80000000 : level.index);
  }
  if (!node.publicKey) throw new Error('no derived public key');
  return node.publicKey;
}

/**
 * SLIP-10 Ed25519 — how the device derives Solana signers. Ed25519 has no
 * non-hardened derivation, so the device signs with the key at the LEADING
 * HARDENED RUN of the request path: a 5-level `m/44'/501'/0'/0/x` request is
 * signed by the `m/44'/501'/0'` account key (verified against this corpus).
 */
function ed25519KeyFromSeed(seed: Uint8Array, path: Level[]): Uint8Array {
  let key = hmac(sha512, utf8Encode('ed25519 seed'), seed);
  for (const level of path) {
    if (!level.hardened) break; // the hardened prefix is the signer
    const data = concatBytes(
      new Uint8Array([0]),
      key.slice(0, 32),
      u32be((level.index >>> 0) + 0x80000000),
    );
    key = hmac(sha512, key.slice(32), data);
  }
  return ed25519.getPublicKey(key.slice(0, 32));
}

describe.skipIf(!enabled)('firmware fixture corpus (local, env-gated)', () => {
  it('every ethereum reply recovers to the seed-derived key at the request keypath', () => {
    let checked = 0;
    for (const c of loadCases('ethereum.json')) {
      const request = decodeUrText(c.ur);
      const reply = decodeUrText(c.expected_signature);
      if (!request || !reply) continue;
      expect(request.type).toBe('eth-sign-request');
      expect(reply.type).toBe('eth-signature');
      const reqMap = cborDecode(request.cbor);
      const signData = asBytes(mapGet(reqMap, 2))!;
      const dataType = Number(asUint(mapGet(reqMap, 3)));

      let digest: Uint8Array;
      if (dataType === 1 || dataType === 4) {
        digest = keccak_256(signData);
      } else if (dataType === 3) {
        digest = keccak_256(
          concatBytes(
            new Uint8Array([0x19]),
            utf8Encode(`Ethereum Signed Message:\n${signData.length}`),
            signData,
          ),
        );
      } else {
        continue; // EIP-712: device-only digest
      }

      const sig = asBytes(mapGet(cborDecode(reply.cbor), 2))!;
      let v = 0n;
      for (const b of sig.slice(64)) v = (v << 8n) | BigInt(b);
      const recovery = v >= 35n ? Number((v - 35n) & 1n) : v >= 27n ? Number(v - 27n) : Number(v);
      const point = secp256k1.Signature.fromCompact(sig.slice(0, 64))
        .addRecoveryBit(recovery)
        .recoverPublicKey(digest);
      const recovered = keccak_256(point.toRawBytes(false).slice(1)).slice(12);

      const seedPub = secp256k1KeyFromSeed(hexToBytes(c.seed), keypathLevels(mapGet(reqMap, 5)));
      const seedAddr = keccak_256(
        secp256k1.ProjectivePoint.fromHex(seedPub).toRawBytes(false).slice(1),
      ).slice(12);
      expect(bytesToHex(recovered), c.name).toBe(bytesToHex(seedAddr));
      checked += 1;
    }
    expect(checked).toBeGreaterThan(5);
  });

  it('every solana reply verifies against the SLIP-10 seed key at the request keypath', () => {
    let checked = 0;
    for (const c of loadCases('solana.json')) {
      const request = decodeUrText(c.ur);
      const reply = decodeUrText(c.expected_signature);
      if (!request || !reply) continue;
      const reqMap = cborDecode(request.cbor);
      const signData = asBytes(mapGet(reqMap, 2))!;
      const sig = asBytes(mapGet(cborDecode(reply.cbor), 2))!;
      const pub = ed25519KeyFromSeed(hexToBytes(c.seed), keypathLevels(mapGet(reqMap, 3)));
      expect(ed25519.verify(sig, signData, pub), c.name).toBe(true);
      checked += 1;
    }
    expect(checked).toBeGreaterThan(10);
  });

  it('bitcoin fixtures decode and the echoed PSBT is transaction-identical', () => {
    // This corpus's expected_signature for PSBTs is the request echoed (the
    // firmware test suite validates signing elsewhere), so what is provable
    // here is the decode path plus unsigned-tx equality — the same comparison
    // verifySignedPsbt builds its anti-replay binding on.
    for (const c of loadCases('bitcoin.json')) {
      const request = decodeUrText(c.ur);
      if (request?.type !== 'crypto-psbt') continue;
      const sent = parsePsbt(asBytes(cborDecode(request.cbor))!);
      const reply = decodeUrText(c.expected_signature);
      if (!reply) continue; // some cases carry no reference reply at all
      const echoed = parsePsbt(asBytes(cborDecode(reply.cbor))!);
      expect(equalBytes(sent.unsignedTx, echoed.unsignedTx), c.name).toBe(true);
    }
  });

  it('every TON reply verifies against the seed key over OUR BoC/proof digest', () => {
    const file = JSON.parse(readFileSync(join(dir!, 'ton_cases.json'), 'utf8')) as {
      seed: string;
      sign_cases: (FixtureCase & { status: string })[];
    };
    let checked = 0;
    for (const c of file.sign_cases) {
      if (c.status !== 'ready') continue;
      const request = decodeUrText(c.ur);
      const reply = decodeUrText(c.expected_signature);
      if (!request || !reply) continue;
      expect(request.type).toBe('ton-sign-request');
      expect(reply.type).toBe('ton-signature');
      const reqMap = cborDecode(request.cbor);
      const signData = asBytes(mapGet(reqMap, 2))!;
      const dataType = Number(asUint(mapGet(reqMap, 3)) ?? 1n);
      const sig = asBytes(mapGet(cborDecode(reply.cbor), 2))!;
      const pub = ed25519KeyFromSeed(
        hexToBytes(c.seed ?? file.seed),
        keypathLevels(mapGet(reqMap, 4)),
      );

      // Recompute the digest with the SDK's own implementation — this is the
      // cross-check that our BoC root hash / TON Connect proof digest agree
      // with what the device actually signed.
      const result = verifyTonSignature({
        signData,
        dataType: dataType === 2 ? TonDataType.tonProof : TonDataType.transaction,
        signature: sig,
        publicKey: pub,
      });
      expect(result.ok, `${c.name}: ${!result.ok ? result.reason : ''}`).toBe(true);
      checked += 1;
    }
    expect(checked).toBeGreaterThanOrEqual(6);
  });

  it('every synthetic cardano reply verifies with FULL binding from its entropy', async () => {
    const { icarusMasterFromEntropy, derivePath, publicKeyOf } = await import('./helpers/icarus');
    const cases = (
      JSON.parse(readFileSync(join(dir!, 'cardano.json'), 'utf8')) as {
        cases: (FixtureCase & { entropy?: string })[];
      }
    ).cases;
    let checked = 0;
    for (const c of cases) {
      if (!c.entropy || !/ur:/i.test(c.expected_signature)) continue; // real-wallet captures carry no reply
      const request = decodeUrText(c.ur);
      const reply = decodeUrText(c.expected_signature);
      if (!request || !reply) continue;
      expect(request.type).toBe('cardano-sign-request');
      const reqMap = cborDecode(request.cbor);
      const signData = asBytes(mapGet(reqMap, 2))!;

      // Collect signer paths from utxos (key 3) + certKeys (key 4).
      const paths: string[] = [];
      for (const key of [3, 4] as const) {
        const listValue = mapGet(reqMap, key);
        const list = listValue === undefined ? undefined : asArray(listValue);
        if (!list) continue;
        for (const item of list) {
          const entry = asMap(item);
          const kp = entry ? asMap(mapGet(entry, key === 3 ? 4 : 2)) : undefined;
          const comps = kp ? asArray(mapGet(kp, 1)) : undefined;
          if (!comps) continue;
          const levels: string[] = [];
          for (let i = 0; i < comps.length; i += 2) {
            levels.push(`${Number(asUint(comps[i]))}${asBool(comps[i + 1]) ? "'" : ''}`);
          }
          paths.push(`m/${levels.join('/')}`);
        }
      }
      expect(paths.length).toBeGreaterThan(0);

      const master = icarusMasterFromEntropy(hexToBytes(c.entropy));
      const account = derivePath(master, [
        { index: 1852, hardened: true },
        { index: 1815, hardened: true },
        { index: 0, hardened: true },
      ]);
      const witnessSet = asBytes(mapGet(cborDecode(reply.cbor), 2))!;
      const result = verifyCardanoSignature({
        signData,
        witnessSet,
        account: {
          publicKey: publicKeyOf(account.kL),
          chainCode: account.chainCode,
          accountPath: "m/1852'/1815'/0'",
        },
        signerPaths: paths,
      });
      expect(result.ok, `${c.name}: ${!result.ok ? result.reason : ''}`).toBe(true);
      checked += 1;
    }
    expect(checked).toBeGreaterThanOrEqual(4);
  });

  it('the real XRP reply verifies through the STObject walker (gold vector)', () => {
    const { cases } = JSON.parse(readFileSync(join(dir!, 'xrp.json'), 'utf8')) as {
      cases: FixtureCase[];
    };
    let checked = 0;
    for (const c of cases) {
      const request = decodeUrText(c.ur);
      const reply = decodeUrText(c.expected_signature);
      if (!request || !reply) continue;
      expect(request.type).toBe('bytes');
      const txJson = JSON.parse(utf8DecodeLoose(asBytes(cborDecode(request.cbor))!)) as {
        SigningPubKey: string;
      };
      const signedTx = asBytes(cborDecode(reply.cbor))!;
      const result = verifyXrpSignature({
        signedTx,
        expectedSigningPubKey: txJson.SigningPubKey,
      });
      expect(result.ok, `${c.name}: ${!result.ok ? result.reason : ''}`).toBe(true);
      expect('checked' in result && result.checked).toBe(true);
      checked += 1;
    }
    expect(checked).toBeGreaterThanOrEqual(1);
  });

  it('cosmos and sui corpus requests decode into the expected shapes', () => {
    const cosmos = JSON.parse(readFileSync(join(dir!, 'cosmos.json'), 'utf8')) as {
      cases: FixtureCase[];
    };
    let cosmosChecked = 0;
    for (const c of cosmos.cases) {
      const request = decodeUrText(c.ur);
      if (!request) continue;
      expect(['cosmos-sign-request', 'evm-sign-request']).toContain(request.type);
      const map = cborDecode(request.cbor);
      expect(asBytes(mapGet(map, 2))!.length).toBeGreaterThan(0);
      cosmosChecked += 1;
    }
    expect(cosmosChecked).toBeGreaterThanOrEqual(30);

    const sui = JSON.parse(readFileSync(join(dir!, 'sui.json'), 'utf8')) as {
      cases: FixtureCase[];
    };
    for (const c of sui.cases) {
      const request = decodeUrText(c.ur);
      if (!request) continue;
      expect(request.type).toBe('sui-sign-request');
      expect(asBytes(mapGet(cborDecode(request.cbor), 2))!.length).toBeGreaterThan(0);
    }
  });

  it('the dogecoin psbt-extend request rebuilds byte-for-byte', async () => {
    const { EraConnect } = await import('../src/index');
    const { cases } = JSON.parse(readFileSync(join(dir!, 'dogecoin.json'), 'utf8')) as {
      cases: FixtureCase[];
    };
    for (const c of cases) {
      const request = decodeUrText(c.ur);
      if (!request || request.type !== 'crypto-psbt-extend') continue;
      const map = cborDecode(request.cbor);
      const psbt = asBytes(mapGet(map, 1))!;
      const coinId = Number(asUint(mapGet(map, 2)));
      expect(coinId).toBe(3); // DOGE
      const rebuilt = new EraConnect().btc.generatePsbtSignRequest({ psbt, coin: 'doge' });
      expect(bytesToHex(rebuilt.ur.cbor)).toBe(bytesToHex(request.cbor));
    }
  });

  it('the tron rawData corpus round-trips: layouts, reply frame, txid, caps', () => {
    const raw = JSON.parse(readFileSync(join(dir!, 'tron_rawdata.json'), 'utf8')) as {
      raw_data_hex: string;
      txid: string;
      raw_tx_hex: string;
      reference_result_ur: string;
      swap_request_ur: string;
    };
    const rawData = hexToBytes(raw.raw_data_hex);
    expect(bytesToHex(sha256(rawData))).toBe(raw.txid.toLowerCase());

    const signedTx = splitSignedTronTx(raw.raw_tx_hex);
    expect(equalBytes(signedTx.rawData, rawData)).toBe(true);
    expect(signedTx.signatures.length).toBeGreaterThan(0);

    const reply = decodeUrText(raw.reference_result_ur)!;
    expect(reply.type).toBe('keystone-sign-result');
    const compressed = asBytes(mapGet(cborDecode(reply.cbor), 1))!;
    expect(compressed.length).toBeLessThanOrEqual(8 * 1024);
    expect(gunzipCapped(compressed, 64 * 1024).length).toBeGreaterThan(0);

    const request = decodeUrText(raw.swap_request_ur)!;
    expect(request.type).toBe('keystone-sign-request');
    const reqCompressed = asBytes(mapGet(cborDecode(request.cbor), 1))!;
    expect(gunzipCapped(reqCompressed, 64 * 1024).length).toBeGreaterThan(0);
  });
});
