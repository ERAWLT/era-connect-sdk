/**
 * Subpath entry: `@era-wallet/connect/verify`.
 *
 * "Did the device sign exactly what I sent?" — run these between parsing a
 * reply and broadcasting it. Kept out of the root entry so the curve
 * arithmetic is bundled only by apps that import it (do).
 */
export type { VerifyResult } from './verify/result';
export { verifyEvmSignature } from './verify/evm';
export type { VerifyEvmSignatureArgs } from './verify/evm';
export { verifySignedPsbt, verifyBtcMessageHeader } from './verify/btc';
export type { VerifyBtcMessageHeaderArgs, VerifySignedPsbtArgs } from './verify/btc';
export { verifySolanaSignature } from './verify/solana';
export type { VerifySolanaSignatureArgs } from './verify/solana';
export { verifyTronSignature } from './verify/tron';
export type { VerifyTronSignatureArgs } from './verify/tron';
export { parsePsbt, PsbtInputType } from './verify/psbt-reader';
export type { ParsedPsbt, PsbtKeyValue } from './verify/psbt-reader';
