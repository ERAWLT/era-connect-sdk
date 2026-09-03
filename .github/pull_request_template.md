## What changes, and why

<!-- The motivation, not just the diff. Link the issue if there is one. -->

## Checks

- [ ] `pnpm --filter @hwlt/era-connect test` passes
- [ ] `pnpm --filter @hwlt/era-connect typecheck` and `pnpm lint` pass
- [ ] A changeset is included (`pnpm changeset`) if this affects the published package

## Wire format

- [ ] This change does **not** alter request or reply bytes

<!-- If it does: byte-exactness is the contract. Say which golden vectors were
     regenerated, and update docs/protocol (and its upstream source) to match. -->
