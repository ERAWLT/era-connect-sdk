/** Subpath entry: `@hwlt/era-connect/sui`. */

export type { EraConnectConfig, ExpectedReply, SignRequest } from './chains/shared';
export { DEFAULT_ORIGIN } from './chains/shared';
export type {
  SuiSignatureResult,
  SuiSignHashRequestProps,
  SuiSignRequestProps,
} from './chains/sui';
export { SuiChain, suiIntentDigest } from './chains/sui';
export type { EraErrorCode } from './core/errors';
export { EraSdkError } from './core/errors';
export type { AnimatedUrOptions } from './qr/animated-ur';
export { AnimatedUr } from './qr/animated-ur';
export type { ScanFeedResult, ScanRejection, UrScannerOptions } from './scan/ur-scanner';
export { TypedUrScanner, UrScanner } from './scan/ur-scanner';
export { Ur } from './ur/ur';
