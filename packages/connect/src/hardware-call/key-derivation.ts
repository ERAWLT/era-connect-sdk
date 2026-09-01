import { cborEncode } from '../cbor/encode';
import type { CborValue } from '../cbor/model';
import { cbArray, cbMap, cbTag, cbText, cbUint } from '../cbor/model';
import { EraSdkError } from '../core/errors';
import type { EraAccounts } from '../accounts/accounts';
import { EraAccounts as EraAccountsClass } from '../accounts/accounts';
import type { AnimatedUrOptions } from '../qr/animated-ur';
import { AnimatedUr } from '../qr/animated-ur';
import { keypath304, parsePath } from '../registry/keypath';
import { WALLET_UR_TYPES } from '../registry/multi-accounts';
import { TypedUrScanner } from '../scan/ur-scanner';
import type { Ur } from '../ur/ur';
import { Ur as UrValue } from '../ur/ur';
import type { ChainContext } from '../chains/shared';

export type DerivationCurve = 'secp256k1' | 'ed25519';
export type DerivationAlgorithm = 'slip10' | 'bip32ed25519';

export interface KeyDerivationSchema {
  /** The derivation path to request, e.g. `m/44'/60'/0'`. */
  readonly path: string;
  /** Defaults to `secp256k1`. */
  readonly curve?: DerivationCurve;
  /** Defaults to `slip10`. */
  readonly algo?: DerivationAlgorithm;
  /** Optional chain hint shown by the device. */
  readonly chainType?: string;
}

export interface KeyDerivationCallProps {
  readonly schemas: readonly KeyDerivationSchema[];
  readonly origin?: string;
}

/** The pull-model linking request: display it, then scan the device's account export back. */
export interface HardwareCallRequest {
  readonly ur: Ur;
  readonly replyTypes: readonly string[];
  toAnimated(options?: AnimatedUrOptions): AnimatedUr;
  scanner(): TypedUrScanner<EraAccounts>;
}

const CURVES: Record<DerivationCurve, number> = { secp256k1: 0, ed25519: 1 };
const ALGOS: Record<DerivationAlgorithm, number> = { slip10: 0, bip32ed25519: 1 };

/**
 * Build a `qr-hardware-call` (1201) wrapping a `key-derivation-call` (1301):
 * the WALLET asks the device for specific derivation paths, curves and
 * algorithms instead of accepting whatever the device's sync screen
 * volunteers. The device answers with a `crypto-multi-accounts` export, which
 * closes the loop through `parseAccounts`.
 *
 * Registry shape (Keystone-standard):
 * `1201({1: type=0, 2: 1301({1: [1302({1: 304(keypath), 2: curve, 3: algo, 4?: chainType})...]}), 3?: origin})`.
 */
export function generateKeyDerivationCall(
  context: ChainContext,
  props: KeyDerivationCallProps,
): HardwareCallRequest {
  if (props.schemas.length === 0) {
    throw new EraSdkError('invalid-props', 'at least one derivation schema is required');
  }
  const schemas: CborValue[] = props.schemas.map((schema) => {
    const levels = parsePath(schema.path);
    const entries: [number, CborValue][] = [
      [1, keypath304(levels)],
      [2, cbUint(CURVES[schema.curve ?? 'secp256k1'])],
      [3, cbUint(ALGOS[schema.algo ?? 'slip10'])],
    ];
    if (schema.chainType !== undefined) entries.push([4, cbText(schema.chainType)]);
    return cbTag(1302, cbMap(entries));
  });

  const call = cbTag(1301, cbMap([[1, cbArray(schemas)]]));
  const root = cbMap([
    [1, cbUint(0)], // type: KeyDerivation
    [2, call],
    [3, cbText(props.origin ?? context.origin)],
  ]);

  const ur = new UrValue('qr-hardware-call', cborEncode(root));
  const replyTypes = [...WALLET_UR_TYPES];
  return {
    ur,
    replyTypes,
    toAnimated: (options?: AnimatedUrOptions) =>
      new AnimatedUr(ur, {
        maxFragmentLength: options?.maxFragmentLength ?? context.maxFragmentLength,
      }),
    scanner: () =>
      new TypedUrScanner<EraAccounts>({ expectedTypes: replyTypes }, (reply) =>
        EraAccountsClass.fromUr(reply),
      ),
  };
}
