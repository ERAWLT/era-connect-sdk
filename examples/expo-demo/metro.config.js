// Metro config for a pnpm monorepo example.
const { getDefaultConfig } = require('expo/metro-config');
const path = require('node:path');

const projectRoot = __dirname;
const workspaceRoot = path.resolve(projectRoot, '../..');

const config = getDefaultConfig(projectRoot);
config.watchFolders = [workspaceRoot];
config.resolver.nodeModulesPaths = [
  path.resolve(projectRoot, 'node_modules'),
  path.resolve(workspaceRoot, 'node_modules'),
];
// Package `exports` maps are resolved natively on RN >= 0.79 / Metro >= 0.82;
// enable explicitly for older combinations:
config.resolver.unstable_enablePackageExports = true;
module.exports = config;
