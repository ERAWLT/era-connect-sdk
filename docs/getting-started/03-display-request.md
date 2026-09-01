# 3. Display a sign request

You build the transaction with your own stack (viem, bitcoinjs-lib,
@solana/web3.js, tronweb, …). The SDK wraps the exact bytes to sign in the
chain's `*-sign-request` UR and turns it into animated QR frames. The user
reviews and approves **on the device** — the device screen is the security
boundary, not your UI.

## Build the request

```ts
import { EvmChain } from '@era-wallet/connect/evm';

const request = era.evm.generateSignRequest({
  signData: rlpBytes,                      // exact bytes to sign (see chain guides)
  dataType: EvmChain.DataType.transaction,
  path: evm.pathFor(0),
  xfp: evm.xfp,
  chainId: 1,
  address: evm.deriveAddress(0),
});

request.requestId;   // minted here; the reply must echo it (checked for you)
request.replyTypes;  // e.g. ['eth-signature'] — what answers this request
request.warnings;    // e.g. ['blind-sign-threshold'] for very large payloads
```

The request id is minted at construction so the same object that renders the
QR also validates the reply's echo — a signature from an earlier, cancelled
flow re-presented to the camera is refused instead of accepted.

## Animate it

```ts
const animated = request.toAnimated();

animated.isSingleFrame;  // small payloads fit one static QR
animated.fragmentCount;  // how many source fragments the device must collect
```

Drive it from your own ticker and render with any QR component
(`react-native-qrcode-svg`, `qrcode.react`, …):

```tsx
// React (Native or web) — the entire "animated QR component":
const [frame, setFrame] = useState(() => animated.nextFrame());
useEffect(() => {
  const timer = setInterval(() => setFrame(animated.nextFrame()), 125);
  return () => clearInterval(timer);
}, [animated]);

return <QRCode value={frame} size={250} />;
```

Two things the defaults already handle, so change them knowingly:

- **125 ms (8 fps) and 180-byte fragments** are the battle-tested values for
  the device camera. Bigger fragments = fewer frames but denser QR codes that
  scan worse. See [QR tuning](../advanced/qr-tuning.md).
- **Frames are UPPERCASE** so the QR encoder uses alphanumeric mode (~45%
  denser than byte mode). Pass the string through unchanged.

Keep the SAME `AnimatedUr` mounted for the whole review: the fountain code
means the device can start scanning at any frame — restarting the animation
is unnecessary, and REBUILDING the request mid-review would mint a new
request id that the device's eventual reply no longer matches.

For logging, `animated.toString()` (or `request.ur.toString()`) is the whole
request as ONE `ur:` string — fragments individually are unreadable noise.

Next: [Scan the signature →](04-scan-signature.md)
