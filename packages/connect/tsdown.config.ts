import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    evm: 'src/evm.ts',
    btc: 'src/btc.ts',
    solana: 'src/solana.ts',
    tron: 'src/tron.ts',
    verify: 'src/verify.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
});
