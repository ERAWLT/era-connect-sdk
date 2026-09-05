/** Subpath entry: `@hwlt/era-connect/tron`. */

export type { EraConnectConfig, ExpectedReply, SignRequest } from './chains/shared';
export { DEFAULT_ORIGIN } from './chains/shared';
export type { TronLatestBlock, TronSignatureResult, TronSignRequestProps } from './chains/tron';
export { TronChain } from './chains/tron';
export type { EraErrorCode } from './core/errors';
export { EraSdkError } from './core/errors';
export type { AnimatedUrOptions } from './qr/animated-ur';
export { AnimatedUr } from './qr/animated-ur';
export type { ScanFeedResult, ScanRejection, UrScannerOptions } from './scan/ur-scanner';
export { TypedUrScanner, UrScanner } from './scan/ur-scanner';
export type { SignedTronTx } from './tron-proto/messages';
export { splitSignedTronTx } from './tron-proto/messages';
export { Ur } from './ur/ur';
