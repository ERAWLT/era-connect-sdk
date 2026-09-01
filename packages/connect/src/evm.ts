/** Subpath entry: `@era-wallet/connect/evm`. */
export { EvmChain, EvmDataType, foldRecoveryId } from './chains/evm';
export type { EvmSignRequestProps, EvmSignatureResult } from './chains/evm';
export type { EraConnectConfig, ExpectedReply, SignRequest } from './chains/shared';
export { EraSdkError } from './core/errors';
export type { EraErrorCode } from './core/errors';
export { Ur } from './ur/ur';
export { AnimatedUr } from './qr/animated-ur';
export { TypedUrScanner, UrScanner } from './scan/ur-scanner';
