/** Outcome of a verification helper. Helpers return, never throw, on mismatches. */
export type VerifyResult =
  /** Verified cryptographically / byte-for-byte. */
  | { readonly ok: true; readonly checked: true }
  /**
   * Nothing client-side is verifiable for this input (EIP-712 typed data:
   * the digest is the hash of the structure, which only the device computes).
   * The UR-type pin and the request-id echo are the whole binding.
   */
  | { readonly ok: true; readonly checked: false; readonly reason: string }
  | { readonly ok: false; readonly reason: string };

export const verified: VerifyResult = { ok: true, checked: true };
export const failed = (reason: string): VerifyResult => ({ ok: false, reason });
export const unverifiable = (reason: string): VerifyResult => ({
  ok: true,
  checked: false,
  reason,
});
