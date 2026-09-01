# 4. Scan the signature

After the user approves, the device shows the reply as an animated QR. Scan
it with the scanner the request hands you — it is pre-pinned to the reply
types that can answer *this* request and validates the request-id echo.

```ts
const scanner = request.scanner();

function onCameraFrame(text: string) {
  const result = scanner.receivePart(text);   // synchronous, never throws
  if (result.kind === 'progress') {
    // result.framesReceived / result.framesExpected for a "3 of 5" label
  }
  if (result.kind === 'complete') {
    const signature = scanner.parse();        // typed result, echo-checked
    // → verify & broadcast (next page)
  }
  if (result.kind === 'rejected') {
    // result.rejection.repeated: a static wrong QR repeats at camera rate —
    // show the message once, not 8×/second.
  }
}
```

`parse()` throws `EraSdkError` with a typed `code` instead of handing you a
questionable signature:

| `code` | Meaning |
|---|---|
| `wrong-ur-type` | The assembled UR is not an answer to this request |
| `request-id-mismatch` | The reply answers a DIFFERENT request (stale/cancelled flow) |
| `malformed-reply` / `malformed-cbor` | The reply does not have the chain's shape |
| `empty-signature` | Bitcoin message signing for an address kind the firmware cannot sign — Taproot on firmware 2.1.0+; anything but legacy P2PKH on older firmware |
| `limit-exceeded` / `gzip-error` | The reply exceeds protocol ceilings (Tron) |
| `incomplete-scan` | `parse()` before the scan completed |

## Timeouts and progress

The device animates its reply at **2.5 fps with 150-byte fragments** — slower
than what you send it. A multi-frame reply (a many-input PSBT) legitimately
takes several seconds; budget scan timeouts from
`DeviceProfile.deviceToPhone`, not from your own send rate:

```ts
import { DeviceProfile } from '@hwlt/era-connect';
DeviceProfile.deviceToPhone; // { fragmentBytesOnWire: 150, frameIntervalMs: 400 }
```

Most replies are a single frame and complete on first sight.

Next: [Verify & broadcast →](05-broadcast.md)
