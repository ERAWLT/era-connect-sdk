# QR tuning

The defaults are the values proven against the device camera; this page is
for when you have a reason to deviate.

## Sending (you → device)

| Knob | Default | Trade-off |
|---|---|---|
| `maxFragmentLength` | 180 bytes payload (~200 on-wire with the fragment header) | Bigger = fewer frames but denser QR modules; the device camera scans ~200-byte frames reliably at arm's length. Going past ~500 helps nothing on hardware-wallet screens |
| Frame interval | 125 ms (8 fps) | Faster wastes frames the camera cannot use; slower stretches the handshake. 100–250 ms is the sane band |
| Case | UPPERCASE (automatic) | Alphanumeric QR mode, ~45% denser than byte mode. Do not lowercase frames |

```ts
const animated = request.toAnimated({ maxFragmentLength: 120 }); // denser env: smaller frames
```

The fountain code means the receiver needs *any* `fragmentCount` independent
frames, not specific ones — keep the animation looping; never restart it on
re-render (and never rebuild the request object mid-review: a new request id
orphans the device's reply).

## Receiving (device → you)

The device animates at **2.5 fps, 150-byte fragments** — receiving is slower
than sending by design (its screen is small and its refresh conservative).
Use `DeviceProfile.deviceToPhone` for timeout budgets and
`framesReceived / framesExpected` for progress. Feed EVERY camera callback to
`receivePart` — duplicates are deduplicated internally at zero cost.

## Logging

Log `request.ur.toString()` / `animated.toString()` (one complete `ur:`
string), never individual frames. On the scan side, log
`rejection.code` + `rejection.repeated` — a static wrong QR produces the
identical rejection at camera rate, and `repeated` is what keeps that to one
line. Never log linking payloads (they identify a wallet).
