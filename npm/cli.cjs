#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const { existsSync } = require('node:fs');
const { join } = require('node:path');

const exe = process.platform === 'win32' ? 'leak-hunter.exe' : 'leak-hunter';
const bin = join(__dirname, 'leak-hunter-bin', exe);

if (!existsSync(bin)) {
  console.error('leak-hunter native binary was not found. Try reinstalling leak-hunter.');
  process.exit(1);
}

const result = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
process.exit(result.status ?? 1);
