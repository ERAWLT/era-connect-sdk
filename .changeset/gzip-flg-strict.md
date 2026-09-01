---
'@hwlt/era-connect': patch
---

`gunzipCapped` now refuses gzip streams with reserved FLG header bits set
(RFC 1952 requires them to be zero; the underlying inflater silently ignored
them). Aligns the accept/refuse contract with the Dart SDK; no conforming
encoder — the device included — ever sets these bits.
