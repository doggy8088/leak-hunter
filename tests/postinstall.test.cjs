'use strict';

const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const postinstall = require('../npm/postinstall.cjs');
const prepublishCheck = require('../npm/prepublish-check.cjs');

test('maps all cargo-dist targets', () => {
  assert.equal(postinstall.cargoDistTarget('darwin', 'arm64'), 'aarch64-apple-darwin');
  assert.equal(postinstall.cargoDistTarget('darwin', 'x64'), 'x86_64-apple-darwin');
  assert.equal(postinstall.cargoDistTarget('linux', 'x64'), 'x86_64-unknown-linux-gnu');
  assert.equal(postinstall.cargoDistTarget('win32', 'x64'), 'x86_64-pc-windows-msvc');
  assert.throws(() => postinstall.cargoDistTarget('linux', 'arm64'), /Unsupported platform/);
});

test('builds release artifact names', () => {
  assert.equal(
    postinstall.artifactName('x86_64-unknown-linux-gnu'),
    'leak-hunter-x86_64-unknown-linux-gnu.tar.xz',
  );
  assert.equal(
    postinstall.artifactName('x86_64-pc-windows-msvc'),
    'leak-hunter-x86_64-pc-windows-msvc.zip',
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

test('finds binaries nested in cargo-dist archive directories', () => {
  const dir = mkdtempSync(join(tmpdir(), 'leak-hunter-'));
  const archiveRoot = join(dir, 'leak-hunter-aarch64-apple-darwin');
  mkdirSync(archiveRoot);
  const bin = join(archiveRoot, 'leak-hunter');
  writeFileSync(bin, 'binary');

  assert.equal(postinstall.findExtractedBinary(dir, 'leak-hunter'), bin);
});

test('builds prepublish release asset checks for every npm target', () => {
  assert.deepEqual(prepublishCheck.expectedReleaseUrls('0.2.0'), [
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-aarch64-apple-darwin.tar.xz',
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-aarch64-apple-darwin.tar.xz.sha256',
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-x86_64-apple-darwin.tar.xz',
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-x86_64-apple-darwin.tar.xz.sha256',
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-x86_64-unknown-linux-gnu.tar.xz',
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-x86_64-unknown-linux-gnu.tar.xz.sha256',
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-x86_64-pc-windows-msvc.zip',
    'https://github.com/doggy8088/leak-hunter/releases/download/v0.2.0/leak-hunter-x86_64-pc-windows-msvc.zip.sha256',
  ]);
});

test('prepublish release asset check reports unavailable assets', async () => {
  let attempts = 0;

  await assert.rejects(
    () =>
      prepublishCheck.verifyReleaseAssets({
        version: '0.2.0',
        retries: 2,
        retryDelayMs: 1,
        check: async (url) => {
          attempts += 1;
          return {
            ok: !url.endsWith('.sha256'),
            statusCode: url.endsWith('.sha256') ? 404 : 200,
          };
        },
      }),
    /Create and host the GitHub release with cargo-dist/,
  );
  assert.equal(attempts, 16);
});
