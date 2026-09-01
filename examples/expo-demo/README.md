# ERA Connect — Expo demo

A minimal, fully **offline** React Native app showing the whole integration:

1. **Link** — scan the device's `crypto-multi-accounts` QR, derive EVM /
   Bitcoin / Solana / Tron addresses locally.
2. **Sign** — `personal_sign` round trip: build the request, render the
   animated QR, scan the device's reply, verify the recovered address.

Nothing here touches the network; everything travels over the camera.

```sh
pnpm install          # from the repository root
cd examples/expo-demo
pnpm start            # then run on a physical device (camera needed)
```

The two files worth copying into a real integration:

- [`src/AnimatedQrView.tsx`](expo-demo/src/AnimatedQrView.tsx) — the entire
  animated-QR renderer (~30 lines).
- [`src/UrScannerView.tsx`](expo-demo/src/UrScannerView.tsx) — the camera →
  `UrScanner` bridge with progress and repeat-deduplicated rejections.
