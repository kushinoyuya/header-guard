'use strict';

const assert = require('assert');
const http = require('http');
const { PassThrough } = require('stream');
const { run, parseArgs } = require('../bin/header-guard');

function io(stdinText) {
  const stdin = new PassThrough();
  const out = { text: '' };
  const err = { text: '' };
  const sink = (o) => ({ write: (s) => (o.text += s), isTTY: false });
  if (stdinText !== undefined) stdin.end(stdinText);
  return { io: { stdin, stdout: sink(out), stderr: sink(err), env: {} }, out, err };
}

const HARDENED_RAW = [
  'HTTP/1.1 200 OK',
  'Strict-Transport-Security: max-age=31536000; includeSubDomains',
  "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options: nosniff',
  'Referrer-Policy: no-referrer',
  'Permissions-Policy: camera=()',
  '',
].join('\r\n');

test('parseArgs rejects unknown options and bad levels', () => {
  assert.throws(() => parseArgs(['--nope']), /Unknown option/);
  assert.throws(() => parseArgs(['--fail-on', 'critical']), /must be one of/);
  assert.strictEqual(parseArgs(['--fail-on', 'none']).failOn, 'none');
});

test('parseArgs collects headers and ignores', () => {
  const o = parseArgs(['x.com', '-H', 'Cookie: a=b', '--ignore', 'a,b', '--ignore', 'c']);
  assert.deepStrictEqual(o.headers, { Cookie: 'a=b' });
  assert.deepStrictEqual(o.ignore, ['a', 'b', 'c']);
});

test('missing target exits 2', async () => {
  const t = io();
  assert.strictEqual(await run([], t.io), 2);
  assert.ok(/missing <url>/.test(t.err.text));
});

test('stdin: hardened headers pass with exit 0', async () => {
  const t = io(HARDENED_RAW);
  assert.strictEqual(await run(['-', '--https'], t.io), 0);
  assert.ok(/No issues found/.test(t.out.text));
});

test('stdin: missing CSP fails with exit 1 and --fail-on none passes', async () => {
  const raw = HARDENED_RAW.replace(/Content-Security-Policy:.*\r\n/, '');
  assert.strictEqual(await run(['-', '--https'], io(raw).io), 1);
  assert.strictEqual(await run(['-', '--https', '--fail-on', 'none'], io(raw).io), 0);
});

test('stdin: --json produces a parseable report', async () => {
  const t = io('HTTP/1.1 200 OK\nX-Powered-By: PHP/8\n');
  await run(['-', '--json', '--url', 'https://example.com'], t.io);
  const report = JSON.parse(t.out.text);
  assert.strictEqual(report.url, 'https://example.com');
  assert.strictEqual(report.statusCode, 200);
  assert.ok(report.summary.high > 0);
  assert.ok(report.findings.some((f) => f.id === 'disclosure-x-powered-by'));
});

test('stdin: empty input exits 2', async () => {
  const t = io('');
  assert.strictEqual(await run(['-'], t.io), 2);
});

test('url: fetches a live server and follows redirects', async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/old') {
      res.writeHead(302, { Location: '/new' });
      return res.end();
    }
    res.setHeader('Set-Cookie', 'sid=1; Path=/');
    res.end('ok');
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
  } catch (e) {
    if (e.code === 'EPERM' || e.code === 'EACCES') test.skip('cannot bind a local port here');
    throw e;
  }
  try {
    const t = io();
    const base = 'http://127.0.0.1:' + server.address().port;
    const code = await run([base + '/old', '--json'], t.io);
    const report = JSON.parse(t.out.text);
    assert.strictEqual(code, 1);
    assert.strictEqual(report.url, base + '/new');
    assert.deepStrictEqual(report.redirects, [base + '/old']);
    assert.ok(report.findings.some((f) => f.id === 'cookie-no-httponly'));
  } finally {
    server.close();
  }
});

test('url: connection errors exit 2', async () => {
  const t = io();
  assert.strictEqual(await run(['http://127.0.0.1:1', '--timeout', '2000'], t.io), 2);
  assert.ok(/header-guard:/.test(t.err.text));
});
