/** Subpath entry: `@hwlt/era-connect/evm`. */

export type { EvmSignatureResult, EvmSignRequestProps } from './chains/evm';
export { EvmChain, EvmDataType, foldRecoveryId } from './chains/evm';
export type { EraConnectConfig, ExpectedReply, SignRequest } from './chains/shared';
export { DEFAULT_ORIGIN } from './chains/shared';
export type { EraErrorCode } from './core/errors';
export { EraSdkError } from './core/errors';
export type { AnimatedUrOptions } from './qr/animated-ur';
export { AnimatedUr } from './qr/animated-ur';
export type { ScanFeedResult, ScanRejection, UrScannerOptions } from './scan/ur-scanner';
export { TypedUrScanner, UrScanner } from './scan/ur-scanner';
export { Ur } from './ur/ur';
