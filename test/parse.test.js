'use strict';

const assert = require('assert');
const { parseCsp, parseRawHeaders, parseSetCookie, normalizeHeaders } = require('../src/parse');

test('parseCsp splits directives and lowercases names', () => {
  const [p] = parseCsp("Default-Src 'self'; script-src 'self' https://cdn.example.com ;img-src *");
  assert.deepStrictEqual(Object.assign({}, p), {
    'default-src': ["'self'"],
    'script-src': ["'self'", 'https://cdn.example.com'],
    'img-src': ['*'],
  });
});

test('parseCsp keeps only the first occurrence of a directive', () => {
  const [p] = parseCsp("script-src 'none'; script-src *");
  assert.deepStrictEqual(p['script-src'], ["'none'"]);
});

test('parseCsp returns one entry per comma-separated policy', () => {
  assert.strictEqual(parseCsp("default-src *, script-src 'self'").length, 2);
  assert.strictEqual(parseCsp(['default-src *', "script-src 'self'"]).length, 2);
});

test('parseSetCookie reads flags and key/value attributes case-insensitively', () => {
  const c = parseSetCookie('sid=abc=def; Path=/; SECURE; HttpOnly; SameSite=Lax');
  assert.strictEqual(c.name, 'sid');
  assert.strictEqual(c.value, 'abc=def');
  assert.strictEqual(c.attributes.path, '/');
  assert.strictEqual(c.attributes.secure, true);
  assert.strictEqual(c.attributes.httponly, true);
  assert.strictEqual(c.attributes.samesite, 'Lax');
});

test('parseRawHeaders takes the final response of a redirect chain', () => {
  const raw = [
    'HTTP/1.1 301 Moved Permanently',
    'Location: https://example.com/',
    '',
    'HTTP/2 200',
    'content-type: text/html',
    'Set-Cookie: a=1',
    'set-cookie: b=2',
    'X-Long: part one',
    '  part two',
    '',
  ].join('\r\n');
  const r = parseRawHeaders(raw);
  assert.strictEqual(r.statusCode, 200);
  assert.deepStrictEqual(r.headers['set-cookie'], ['a=1', 'b=2']);
  assert.deepStrictEqual(r.headers['x-long'], ['part one part two']);
  assert.strictEqual(r.headers.location, undefined);
});

test('parseRawHeaders accepts headers without a status line', () => {
  const r = parseRawHeaders('X-Frame-Options: DENY\n');
  assert.strictEqual(r.statusCode, null);
  assert.deepStrictEqual(r.headers['x-frame-options'], ['DENY']);
});

test('normalizeHeaders accepts objects and Maps', () => {
  assert.deepStrictEqual(normalizeHeaders({ 'X-A': '1', 'set-cookie': ['a', 'b'] })['x-a'], ['1']);
  assert.deepStrictEqual(normalizeHeaders(new Map([['X-B', '2']]))['x-b'], ['2']);
});
