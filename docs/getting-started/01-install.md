# 1. Install & set up

```sh
npm install @era-wallet/connect
# or: pnpm add / yarn add / bun add
```

The SDK is pure TypeScript with no native modules, no Node built-ins and no
network access. It runs unchanged in React Native (Hermes), Expo, browsers,
extensions and Node ≥ 18.

## React Native

Two things, both one-time:

**1. A secure random source.** Request ids are minted from a CSPRNG. On
React Native install the polyfill and import it before anything else:

```sh
npm install react-native-get-random-values
```

```ts
// index.js — FIRST import
import 'react-native-get-random-values';
```

Alternatively inject a source explicitly (works with `expo-crypto` too):

```ts
import * as Crypto from 'expo-crypto';
const era = new EraConnect({
  origin: 'MyWallet',
  randomBytes: (n) => Crypto.getRandomBytes(n),
});
```

Without either, the first `generateSignRequest` throws
`EraSdkError('no-secure-random')` with these same instructions.

**2. Metro & subpath imports.** On React Native ≥ 0.79 package `exports` are
resolved natively — `@era-wallet/connect/evm` just works. On older RN
versions the package ships classic `main`/`react-native` fields plus proxy
folders, so both the root and subpath imports resolve there too.

## Construct once

```ts
import { EraConnect } from '@era-wallet/connect';

export const era = new EraConnect({
  origin: 'MyWallet', // the wallet name the DEVICE shows on every request
});
```

`origin` is worth setting properly: the user sees it on the hardware screen
("Sign for MyWallet?") on every request. Individual requests can override it.

Next: [Link the device →](02-link-device.md)
