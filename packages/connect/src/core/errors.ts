/**
 * Closed set of error codes the SDK can produce. Integrators branch on
 * `code`, never on message text — messages are for humans and may change.
 */
export type EraErrorCode =
  /** No CSPRNG available: neither `globalThis.crypto.getRandomValues` nor an injected `randomBytes`. */
  | 'no-secure-random'
  /** The scanned text is not a `ur:` string at all. */
  | 'not-a-ur'
  /** A UR of a type this operation does not accept. */
  | 'wrong-ur-type'
  /** Bytewords body malformed (unknown letter pair, too short). */
  | 'malformed-bytewords'
  /** Bytewords or reassembly CRC32 does not match. */
  | 'checksum-mismatch'
  /** CBOR payload malformed or outside the hardened decoder's policy. */
  | 'malformed-cbor'
  /** The `<seq>` path segment of a multi-part UR is unreadable. */
  | 'malformed-sequence'
  /** A fragment that does not belong to the stream being assembled. */
  | 'fragment-mismatch'
  /** A size/count cap was exceeded (fragment count, message size, inflate ceiling). */
  | 'limit-exceeded'
  /** `result()`/`parse()` called before the scan completed. */
  | 'incomplete-scan'
  /** The reply echoes a different request id — it answers another sign request. */
  | 'request-id-mismatch'
  /** The linked wallet carries no account for the requested path. */
  | 'account-not-found'
  /** Invalid request properties (bad path string, chainId over the device's 32-bit ceiling, ...). */
  | 'invalid-props'
  /** The device refused to sign (e.g. a Bitcoin message for a non-legacy address). */
  | 'empty-signature'
  /** Reply CBOR/protobuf decoded but its shape is not the expected reply. */
  | 'malformed-reply'
  /** gzip payload malformed, truncated, or a decompression bomb. */
  | 'gzip-error'
  /** Protobuf payload malformed. */
  | 'protobuf-error'
  /** A verification helper found a mismatch between request and reply. */
  | 'verification-failed';

/** Every error thrown by this SDK. `code` is stable API; `message` is not. */
export class EraSdkError extends Error {
  readonly code: EraErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: EraErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'EraSdkError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}
