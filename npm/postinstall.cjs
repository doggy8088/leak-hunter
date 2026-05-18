'use strict';

const { mkdirSync, chmodSync, existsSync } = require('node:fs');
const { join } = require('node:path');

// Release installs download a cargo-dist native binary. Source-tree installs keep this
// intentionally small so npm pack/test does not require network access.
const binDir = join(__dirname, 'leak-hunter-bin');
mkdirSync(binDir, { recursive: true });

const exe = process.platform === 'win32' ? 'leak-hunter.exe' : 'leak-hunter';
const localRelease = join(__dirname, '..', 'target', 'release', exe);
const dest = join(binDir, exe);

if (existsSync(localRelease) && !existsSync(dest)) {
  try {
    require('node:fs').copyFileSync(localRelease, dest);
    chmodSync(dest, 0o755);
  } catch {
    // Ignore local convenience copy failures; release postinstall handles downloads.
  }
}
