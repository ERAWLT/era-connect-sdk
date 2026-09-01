/**
 * Subpath entry: `@era-wallet/connect/verify`.
 *
 * "Did the device sign exactly what I sent?" — run these between parsing a
 * reply and broadcasting it. Kept out of the root entry so the curve
 * arithmetic is bundled only by apps that import it (do).
 */

export type { VerifyBtcMessageHeaderArgs, VerifySignedPsbtArgs } from './verify/btc';
export { verifyBtcMessageHeader, verifySignedPsbt } from './verify/btc';
export type { VerifyEvmSignatureArgs } from './verify/evm';
export { verifyEvmSignature } from './verify/evm';
export type { ParsedPsbt, PsbtKeyValue } from './verify/psbt-reader';
export { PsbtInputType, parsePsbt } from './verify/psbt-reader';
export type { VerifyResult } from './verify/result';
export type { VerifySolanaSignatureArgs } from './verify/solana';
export { verifySolanaSignature } from './verify/solana';
export type { VerifyTronSignatureArgs } from './verify/tron';
export { verifyTronSignature } from './verify/tron';
