'use strict';

const assert = require('node:assert/strict');
const { mkdtempSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const postinstall = require('../npm/postinstall.cjs');

test('maps all cargo-dist targets', () => {
  assert.equal(postinstall.cargoDistTarget('darwin', 'arm64'), 'aarch64-apple-darwin');
  assert.equal(postinstall.cargoDistTarget('darwin', 'x64'), 'x86_64-apple-darwin');
  assert.equal(postinstall.cargoDistTarget('linux', 'x64'), 'x86_64-unknown-linux-gnu');
  assert.equal(postinstall.cargoDistTarget('win32', 'x64'), 'x86_64-pc-windows-msvc');
  assert.throws(() => postinstall.cargoDistTarget('linux', 'arm64'), /Unsupported platform/);
});

test('builds release artifact names', () => {
  assert.equal(
    postinstall.artifactName('x86_64-unknown-linux-gnu', '0.1.0'),
    'leak-hunter-0.1.0-x86_64-unknown-linux-gnu.tar.xz',
  );
  assert.equal(
    postinstall.artifactName('x86_64-pc-windows-msvc', '0.1.0'),
    'leak-hunter-0.1.0-x86_64-pc-windows-msvc.zip',
  );
});

test('verifies release archive checksums', () => {
  const dir = mkdtempSync(join(tmpdir(), 'leak-hunter-'));
  const file = join(dir, 'artifact.tar.xz');
  writeFileSync(file, 'hello');
  const hash = postinstall.sha256(file);
  assert.doesNotThrow(() => postinstall.verifyChecksum(file, `${hash}  artifact.tar.xz\n`));
  assert.throws(() => postinstall.verifyChecksum(file, `${'0'.repeat(64)}  artifact.tar.xz\n`), /Checksum mismatch/);
});
