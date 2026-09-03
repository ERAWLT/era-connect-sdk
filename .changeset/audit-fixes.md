---
'@hwlt/era-connect': minor
---

Close out the external repository audit.

**New:** `accounts.cosmos()` and `accounts.xrp()` — Cosmos and XRP shipped
full signing modules but no typed account view, and an XRP entry from the
device classified as `unknown` because `m/44'/144'` was missing from the path
classifier. Both now behave like the other nine chains; Cosmos addresses take
the zone's bech32 prefix, XRP exposes the single path the device signs with.

**Fixed:** the UR type grammar disagreed with itself — a type containing a
digit could be constructed and then refused as `not-a-ur` on the way back in.
The protobuf's `sync.proto` still carried Keystone's pre-rename namespace.
Thirteen lint warnings (six dead imports) are gone, the Biome config no longer
drifts from the resolved version, and the workspace config no longer both
forbids and permits the same build script.

**Docs:** the normative protocol spec was four chains behind — Bitcoin message
signing, the per-chain request-id shape and the QR fragment defaults all
contradicted the code, and the reference tables omitted seven UR types. The
spec now states its own scope honestly and the tables cover every type the
device speaks. The `.proto` schemas are no longer described as proprietary:
they ship in this package.
