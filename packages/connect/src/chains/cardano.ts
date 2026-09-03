import { cborDecode } from '../cbor/decode';
import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import {
  asBytes,
  cbArray,
  cbBytes,
  cbMap,
  cbTag,
  cbText,
  cbUint,
  mapGet,
  stripTags,
} from '../cbor/model';
import { EraSdkError } from '../core/errors';
import { normalizeRequestId } from '../core/rand';
import { keypath304, normalizeXfp, parsePath } from '../registry/keypath';
import type { Ur } from '../ur/ur';
import { Ur as UrValue } from '../ur/ur';
import type { ChainContext, EraConnectConfig, ExpectedReply, SignRequest } from './shared';
import {
  makeSignRequest,
  requireReplyMap,
  requireRequestIdEcho,
  requireUrType,
  resolveContext,
  resolveRequestId,
  toUr,
} from './shared';

/** One transaction input the device must sign for. */
export interface CardanoUtxoRef {
  /** 32-byte hash of the transaction that created the UTXO. */
  readonly transactionHash: Uint8Array;
  readonly index: number;
  /** Full signing path for this input, e.g. `m/1852'/1815'/0'/0/0`. */
  readonly path: string;
  readonly xfp: string | number;
  /** Lovelace amount as a decimal string — device display. */
  readonly amount?: string;
  /** Bech32 address of the UTXO — device display. */
  readonly address?: string;
}

/** A certificate/withdrawal key the transaction additionally needs a witness from. */
export interface CardanoCertKeyRef {
  /** Full signing path, e.g. the stake key `m/1852'/1815'/0'/2/0`. */
  readonly path: string;
  readonly xfp: string | number;
  /** 28-byte key hash — device display/matching. */
  readonly keyHash?: Uint8Array;
}

export interface CardanoSignRequestProps {
  readonly requestId?: Uint8Array | string;
  /**
   * The FULL transaction CBOR (`[body, witness_set, is_valid, aux_data]`) as
   * your Cardano tooling serializes it. The device extracts the body (first
   * array element) and signs its BLAKE2b-256 hash.
   */
  readonly signData: Uint8Array;
  /** At least one; the device signs once per UNIQUE path across utxos + certKeys. */
  readonly utxos: readonly CardanoUtxoRef[];
  readonly certKeys?: readonly CardanoCertKeyRef[];
  readonly origin?: string;
}

export interface CardanoWitness {
  /** 32-byte verification key. */
  readonly vkey: Uint8Array;
  /** 64-byte Ed25519 signature over the tx-body BLAKE2b-256 hash. */
  readonly signature: Uint8Array;
}

export interface CardanoSignatureResult {
  readonly requestId: Uint8Array;
  /** The witness-set CBOR verbatim (`{0: #6.258([[vkey, sig]…])}`) — merge it into your tx. */
  readonly witnessSet: Uint8Array;
  /** The `[vkey, signature]` pairs parsed out of the witness set. */
  readonly witnesses: readonly CardanoWitness[];
}

const REPLY_TYPES = ['cardano-signature'] as const;
const UTXO_TAG = 2201;
const CERT_KEY_TAG = 2204;

export class CardanoChain {
  private readonly context: ChainContext;

  constructor(config?: EraConnectConfig) {
    this.context = resolveContext(config);
  }

  /** Build a `cardano-sign-request` (2202). Reply: `cardano-signature` (2203). */
  generateSignRequest(props: CardanoSignRequestProps): SignRequest<CardanoSignatureResult> {
    const requestId = resolveRequestId(this.context, props.requestId);
    if (props.signData.length === 0) {
      throw new EraSdkError('invalid-props', 'signData must not be empty');
    }
    if (props.utxos.length === 0) {
      throw new EraSdkError('invalid-props', 'at least one utxo is required');
    }

    const utxos = props.utxos.map((utxo) => {
      if (utxo.transactionHash.length !== 32) {
        throw new EraSdkError('invalid-props', 'utxo transactionHash must be 32 bytes');
      }
      if (!Number.isSafeInteger(utxo.index) || utxo.index < 0) {
        throw new EraSdkError('invalid-props', 'utxo index must be a non-negative integer');
      }
      const entries: [number, CborValue][] = [
        [1, cbBytes(utxo.transactionHash)],
        [2, cbUint(utxo.index)],
      ];
      if (utxo.amount !== undefined) entries.push([3, cbText(utxo.amount)]);
      entries.push([4, keypath304(parsePath(utxo.path), normalizeXfp(utxo.xfp))]);
      if (utxo.address !== undefined) entries.push([5, cbText(utxo.address)]);
      return cbTag(UTXO_TAG, cbMap(entries));
    });

    const certKeys = (props.certKeys ?? []).map((certKey) => {
      const entries: [number, CborValue][] = [];
      if (certKey.keyHash !== undefined) entries.push([1, cbBytes(certKey.keyHash)]);
      entries.push([2, keypath304(parsePath(certKey.path), normalizeXfp(certKey.xfp))]);
      return cbTag(CERT_KEY_TAG, cbMap(entries));
    });

    const entries: [number, CborValue][] = [
      [1, cbTag(37, cbBytes(requestId))],
      [2, cbBytes(props.signData)],
      [3, cbArray(utxos)],
    ];
    if (certKeys.length > 0) entries.push([4, cbArray(certKeys)]);
    entries.push([5, cbText(props.origin ?? this.context.origin)]);

    const ur = new UrValue('cardano-sign-request', cborEncode(cbMap(entries)));
    return makeSignRequest({
      ur,
      requestId,
      replyTypes: REPLY_TYPES,
      context: this.context,
      parse: (reply) => parseCardanoSignature(reply, requestId),
    });
  }

  /** Parse a `cardano-signature` standalone. Prefer `SignRequest.scanner().parse()`. */
  parseSignature(input: Ur | string, expect?: ExpectedReply): CardanoSignatureResult {
    return parseCardanoSignature(
      toUr(input),
      expect?.requestId === undefined ? undefined : normalizeRequestId(expect.requestId),
    );
  }
}

function parseCardanoSignature(
  ur: Ur,
  expectedRequestId: Uint8Array | undefined,
): CardanoSignatureResult {
  requireUrType(ur, [...REPLY_TYPES], 'cardano-signature');
  const map = requireReplyMap(ur, 'cardano-signature');
  const requestId = requireRequestIdEcho(map, 1, expectedRequestId, 'cardano-signature');

  const witnessSet = asBytes(mapGet(map, 2));
  if (!witnessSet || witnessSet.length === 0) {
    throw new EraSdkError(
      'malformed-reply',
      'cardano-signature is missing the witness set (key 2)',
    );
  }
  return { requestId, witnessSet, witnesses: parseWitnessSet(witnessSet) };
}

/** `[vkey, signature]` pairs from a witness-set CBOR `{0: #6.258([...])}` (the set tag is optional). */
export function parseWitnessSet(witnessSet: Uint8Array): CardanoWitness[] {
  let decoded: CborValue;
  try {
    decoded = cborDecode(witnessSet);
  } catch (e) {
    throw new EraSdkError(
      'malformed-reply',
      `witness set is not readable CBOR: ${(e as Error).message}`,
    );
  }
  const root = stripTags(decoded);
  if (root.kind !== 'map') {
    throw new EraSdkError('malformed-reply', 'witness set is not a CBOR map');
  }
  const vkeyWitnesses = mapGet(root, 0);
  const list = vkeyWitnesses === undefined ? undefined : stripTags(vkeyWitnesses);
  if (list?.kind !== 'array') {
    throw new EraSdkError('malformed-reply', 'witness set carries no vkey witnesses (key 0)');
  }
  const witnesses: CardanoWitness[] = [];
  for (const item of list.items) {
    const pair = stripTags(item);
    if (pair.kind !== 'array' || pair.items.length < 2) {
      throw new EraSdkError('malformed-reply', 'malformed vkey witness');
    }
    const vkey = asBytes(pair.items[0]);
    const signature = asBytes(pair.items[1]);
    if (vkey?.length !== 32 || !signature || signature.length !== 64) {
      throw new EraSdkError(
        'malformed-reply',
        'vkey witness is not [32-byte key, 64-byte signature]',
      );
    }
    witnesses.push({ vkey, signature });
  }
  if (witnesses.length === 0) {
    throw new EraSdkError('malformed-reply', 'witness set is empty');
  }
  return witnesses;
}
