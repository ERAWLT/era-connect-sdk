import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    evm: 'src/evm.ts',
    btc: 'src/btc.ts',
    solana: 'src/solana.ts',
    tron: 'src/tron.ts',
    ton: 'src/ton.ts',
    cardano: 'src/cardano.ts',
    verify: 'src/verify.ts',
  },
  format: ['esm', 'cjs'],
  fixedExtension: false,
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
});
