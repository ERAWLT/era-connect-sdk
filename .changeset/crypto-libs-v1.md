---
'@hwlt/era-connect': patch
---

Load again. 0.9.0 depended on @noble/curves, @noble/hashes, @scure/base and @scure/bip32 v2, whose module names and APIs the SDK does not use, so importing the package failed with ERR_PACKAGE_PATH_NOT_EXPORTED. Back on the v1 versions 0.8.0 shipped with; nothing else changes.
