// Plain .mjs on purpose: a .ts config needs a TS loader at build time, which
// Node 20 (still in the support matrix) does not have natively — tsdown then
// reaches for its optional `unrun` peer and fails. JS needs nothing.
import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    evm: 'src/evm.ts',
    btc: 'src/btc.ts',
    bch: 'src/bch.ts',
    solana: 'src/solana.ts',
    tron: 'src/tron.ts',
    ton: 'src/ton.ts',
    cardano: 'src/cardano.ts',
    sui: 'src/sui.ts',
    cosmos: 'src/cosmos.ts',
    xrp: 'src/xrp.ts',
    verify: 'src/verify.ts',
  },
  format: ['esm', 'cjs'],
  fixedExtension: false,
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
});
