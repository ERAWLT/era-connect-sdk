/** Subpath entry: `@era-wallet/connect/solana`. */
export { SolanaChain, SolSignType } from './chains/solana';
export type { SolSignRequestProps, SolSignatureResult } from './chains/solana';
export type { EraConnectConfig, ExpectedReply, SignRequest } from './chains/shared';
export { EraSdkError } from './core/errors';
export type { EraErrorCode } from './core/errors';
export { Ur } from './ur/ur';
export { AnimatedUr } from './qr/animated-ur';
export { TypedUrScanner, UrScanner } from './scan/ur-scanner';
