import { EraSdkError } from '../core/errors';

/**
 * Minimal CBOR value model for the ERA wire protocol.
 *
 * Maps are ENTRY LISTS, not JS Maps: insertion order is preserved for
 * byte-exact re-encoding, and the decoder can reject duplicate keys.
 */
export type CborValue =
  | { readonly kind: 'uint'; readonly value: bigint }
  | { readonly kind: 'nint'; readonly value: bigint } // encoded as -1 - value
  | { readonly kind: 'bytes'; readonly value: Uint8Array }
  | { readonly kind: 'text'; readonly value: string }
  | { readonly kind: 'array'; readonly items: readonly CborValue[] }
  | { readonly kind: 'map'; readonly entries: readonly (readonly [CborValue, CborValue])[] }
  | { readonly kind: 'bool'; readonly value: boolean }
  | { readonly kind: 'null' }
  | { readonly kind: 'tag'; readonly tag: number; readonly value: CborValue };

export const cbUint = (value: number | bigint): CborValue => {
  const v = typeof value === 'number' ? BigInt(value) : value;
  if (v < 0n) throw new EraSdkError('invalid-props', 'cbUint: negative value');
  return { kind: 'uint', value: v };
};
export const cbBytes = (value: Uint8Array): CborValue => ({ kind: 'bytes', value });
export const cbText = (value: string): CborValue => ({ kind: 'text', value });
export const cbArray = (items: CborValue[]): CborValue => ({ kind: 'array', items });
export const cbBool = (value: boolean): CborValue => ({ kind: 'bool', value });
export const cbTag = (tag: number, value: CborValue): CborValue => ({ kind: 'tag', tag, value });

/** Integer-keyed map in the given entry order (the shape every ERA payload uses). */
export const cbMap = (entries: [number, CborValue][]): CborValue => ({
  kind: 'map',
  entries: entries.map(([k, v]) => [cbUint(k), v] as const),
});

/** Strip any tag wrappers (tag-37 UUID echoes, tag-304 keypaths, ...). */
export function stripTags(value: CborValue): CborValue {
  let v = value;
  while (v.kind === 'tag') v = v.value;
  return v;
}

/** Look up an integer key in a map value. Tag-agnostic on the VALUE is the caller's choice. */
export function mapGet(map: CborValue, key: number): CborValue | undefined {
  if (map.kind !== 'map') return undefined;
  const k = BigInt(key);
  for (const [ek, ev] of map.entries) {
    if (ek.kind === 'uint' && ek.value === k) return ev;
  }
  return undefined;
}

export function asUint(value: CborValue | undefined): bigint | undefined {
  if (!value) return undefined;
  const v = stripTags(value);
  return v.kind === 'uint' ? v.value : undefined;
}

export function asBytes(value: CborValue | undefined): Uint8Array | undefined {
  if (!value) return undefined;
  const v = stripTags(value);
  return v.kind === 'bytes' ? v.value : undefined;
}

export function asText(value: CborValue | undefined): string | undefined {
  if (!value) return undefined;
  const v = stripTags(value);
  return v.kind === 'text' ? v.value : undefined;
}

export function asArray(value: CborValue | undefined): readonly CborValue[] | undefined {
  if (!value) return undefined;
  const v = stripTags(value);
  return v.kind === 'array' ? v.items : undefined;
}

export function asMap(value: CborValue | undefined): CborValue | undefined {
  if (!value) return undefined;
  const v = stripTags(value);
  return v.kind === 'map' ? v : undefined;
}

export function asBool(value: CborValue | undefined): boolean | undefined {
  if (!value) return undefined;
  const v = stripTags(value);
  return v.kind === 'bool' ? v.value : undefined;
}
