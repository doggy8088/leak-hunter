#!/usr/bin/env node
'use strict';

const { createHash } = require('node:crypto');
const { copyFileSync, chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { get } = require('node:https');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

const PACKAGE_ROOT = join(__dirname, '..');
const BIN_DIR = join(__dirname, 'leak-hunter-bin');
const BIN_NAME = process.platform === 'win32' ? 'leak-hunter.exe' : 'leak-hunter';
const DEST = join(BIN_DIR, BIN_NAME);

const TARGETS = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'linux-x64': 'x86_64-unknown-linux-gnu',
  'win32-x64': 'x86_64-pc-windows-msvc',
};

function platformKey(platform = process.platform, arch = process.arch) {
  return `${platform}-${arch}`;
}

function cargoDistTarget(platform = process.platform, arch = process.arch) {
  const target = TARGETS[platformKey(platform, arch)];
  if (!target) {
    throw new Error(`Unsupported platform: ${platform}/${arch}`);
  }
  return target;
}

function packageVersion() {
  return require(join(PACKAGE_ROOT, 'package.json')).version;
}

function artifactName(target, version = packageVersion()) {
  const ext = target.includes('windows') || target.includes('pc-windows') ? 'zip' : 'tar.xz';
  return `leak-hunter-${version}-${target}.${ext}`;
}

function releaseBaseUrl(version = packageVersion()) {
  return `https://github.com/doggy8088/leak-hunter/releases/download/v${version}`;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function verifyChecksum(filePath, checksumText) {
  const expected = checksumText.trim().split(/\s+/)[0].toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(expected)) {
    throw new Error('Invalid checksum file format');
  }
  const actual = sha256(filePath);
  if (actual !== expected) {
    throw new Error(`Checksum mismatch for ${filePath}: expected ${expected}, got ${actual}`);
  }
}

function download(url, destination) {
  return new Promise((resolve, reject) => {
    get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        download(res.headers.location, destination).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`Download failed ${res.statusCode}: ${url}`));
        return;
      }
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        writeFileSync(destination, Buffer.concat(chunks));
        resolve();
      });
    }).on('error', reject);
  });
}

function extract(archive, destDir) {
  mkdirSync(destDir, { recursive: true });
  if (archive.endsWith('.zip')) {
    const result = spawnSync('unzip', ['-o', archive, '-d', destDir], { stdio: 'inherit' });
    if (result.status !== 0) throw new Error('Failed to extract zip archive');
  } else {
    const result = spawnSync('tar', ['-xJf', archive, '-C', destDir], { stdio: 'inherit' });
    if (result.status !== 0) throw new Error('Failed to extract tar.xz archive');
  }
}

function installFromLocalBuild() {
  const localRelease = join(PACKAGE_ROOT, 'target', 'release', BIN_NAME);
  if (!existsSync(localRelease)) return false;
  mkdirSync(BIN_DIR, { recursive: true });
  copyFileSync(localRelease, DEST);
  chmodSync(DEST, 0o755);
  return true;
}

async function installFromRelease() {
  const target = cargoDistTarget();
  const archive = artifactName(target);
  const base = releaseBaseUrl();
  const tmpDir = join(BIN_DIR, '.tmp');
  const archivePath = join(tmpDir, archive);
  const checksumPath = `${archivePath}.sha256`;

  rmSync(tmpDir, { recursive: true, force: true });
  mkdirSync(tmpDir, { recursive: true });
  await download(`${base}/${archive}`, archivePath);
  await download(`${base}/${archive}.sha256`, checksumPath);
  verifyChecksum(archivePath, readFileSync(checksumPath, 'utf8'));
  extract(archivePath, tmpDir);

  const extracted = join(tmpDir, BIN_NAME);
  if (!existsSync(extracted)) {
    throw new Error(`Archive did not contain ${BIN_NAME}`);
  }
  mkdirSync(BIN_DIR, { recursive: true });
  copyFileSync(extracted, DEST);
  chmodSync(DEST, 0o755);
  rmSync(tmpDir, { recursive: true, force: true });
}

async function main() {
  if (installFromLocalBuild()) return;
  await installFromRelease();
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}

module.exports = {
  TARGETS,
  artifactName,
  cargoDistTarget,
  platformKey,
  releaseBaseUrl,
  sha256,
  verifyChecksum,
};
