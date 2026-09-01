# ERA Connect SDK

Air-gapped **ERA hardware wallet** integration for software wallets over
animated QR codes (BC-UR / Keystone-compatible registry) — account linking
and transaction signing for **EVM, Bitcoin, Solana and Tron**.

- **npm package:** [`@era-wallet/connect`](packages/connect) — headless,
  TypeScript, React-Native-first, zero I/O.
- **Documentation:** [`docs/`](docs) — a 15-minute getting-started funnel,
  per-chain guides, device specifics and the normative wire spec.
- **Demo app:** [`examples/expo-demo`](examples) — link + sign, fully offline.

```ts
import { EraConnect } from '@era-wallet/connect';

const era = new EraConnect({ origin: 'MyWallet' });
const accounts = era.parseAccounts(scannedUr);      // link once
const request = era.evm.generateSignRequest({ ... }); // sign anytime
```

Start here → [docs/getting-started/01-install.md](docs/getting-started/01-install.md)

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
