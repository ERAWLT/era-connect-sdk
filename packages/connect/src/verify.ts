/**
 * Subpath entry: `@hwlt/era-connect/verify`.
 *
 * "Did the device sign exactly what I sent?" — run these between parsing a
 * reply and broadcasting it. Kept out of the root entry so the curve
 * arithmetic is bundled only by apps that import it (do).
 */

// Every type an argument object DECLARES is exported here, so an app that
// imports this entry alone can name the values it hands the verifiers.
// `CardanoWitness` is the declared type of `VerifyCardanoSignatureArgs.witnesses`.
export type { CardanoWitness } from './chains/cardano';
// `VerifyEvmSignatureArgs.dataType` is one of these.
export { EvmDataType } from './chains/evm';
// `VerifyTonSignatureArgs.dataType` is one of these.
export { TonDataType } from './chains/ton';
// `parsePsbt`, `decodeBchRawTx` and `bocRootHash` throw this; catching it by
// type needs the class, and this entry is importable on its own.
export type { EraErrorCode } from './core/errors';
export { EraSdkError } from './core/errors';
// `VerifyTronSignatureArgs.latestBlock` is a TronLatestBlock, and its
// `signedTx` is a SignedTronTx (or the raw hex of one).
export type { SignedTronTx, TronLatestBlock } from './tron-proto/messages';
export type {
  DecodedBchInput,
  DecodedBchOutput,
  DecodedBchTx,
  VerifyBchInput,
  VerifyBchOutput,
  VerifyBchSignedTxArgs,
} from './verify/bch';
export { computeBchSighash, decodeBchRawTx, verifyBchSignedTx } from './verify/bch';
export type { VerifyBtcMessageHeaderArgs, VerifySignedPsbtArgs } from './verify/btc';
export { verifyBtcMessageHeader, verifySignedPsbt } from './verify/btc';
export type { VerifyCardanoSignatureArgs } from './verify/cardano';
export { verifyCardanoSignature } from './verify/cardano';
export type { VerifyCosmosSignatureArgs } from './verify/cosmos';
export { verifyCosmosSignature } from './verify/cosmos';
export type { VerifyEvmSignatureArgs } from './verify/evm';
export { verifyEvmSignature } from './verify/evm';
export type { ParsedPsbt, PsbtKeyValue } from './verify/psbt-reader';
export { PsbtInputType, parsePsbt } from './verify/psbt-reader';
export type { VerifyResult } from './verify/result';
export type { VerifySolanaSignatureArgs } from './verify/solana';
export { verifySolanaSignature } from './verify/solana';
export type { VerifySuiSignatureArgs } from './verify/sui';
export { verifySuiSignature } from './verify/sui';
export type { VerifyTonSignatureArgs } from './verify/ton';
export { verifyTonSignature } from './verify/ton';
export { bocRootHash } from './verify/ton-boc';
export type { VerifyTronSignatureArgs } from './verify/tron';
export { verifyTronSignature } from './verify/tron';
export type { VerifyXrpSignatureArgs } from './verify/xrp';
export { verifyXrpSignature } from './verify/xrp';
