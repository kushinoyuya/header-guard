'use strict';

const assert = require('assert');
const { audit } = require('../src/audit');

const ids = (findings) => findings.map((f) => f.id);
const has = (findings, id) => ids(findings).indexOf(id) !== -1;

/** A response that should produce no findings at all. */
const HARDENED = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'content-security-policy':
    "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  'set-cookie': ['__Host-sid=x; Path=/; Secure; HttpOnly; SameSite=Lax'],
};
const HTTPS = { url: 'https://example.com/' };

const withHeaders = (overrides) => {
  const h = Object.assign({}, HARDENED, overrides);
  for (const k of Object.keys(h)) if (h[k] === undefined) delete h[k];
  return h;
};

test('hardened response has no findings', () => {
  assert.deepStrictEqual(audit(HARDENED, HTTPS), []);
});

test('empty response reports the core issues, worst first', () => {
  const f = audit({}, HTTPS);
  for (const id of ['hsts-missing', 'csp-missing', 'clickjacking', 'nosniff-missing', 'referrer-policy-missing']) {
    assert.ok(has(f, id), 'expected ' + id);
  }
  const order = ['high', 'medium', 'low', 'info'];
  for (let i = 1; i < f.length; i++) {
    assert.ok(order.indexOf(f[i - 1].severity) <= order.indexOf(f[i].severity), 'not sorted');
  }
});

// --- HSTS / transport -------------------------------------------------------

test('HSTS is only checked over HTTPS', () => {
  assert.ok(!has(audit({}, { url: 'http://localhost:3000' }), 'hsts-missing'));
});

test('short or zero HSTS max-age is flagged', () => {
  const short = audit(withHeaders({ 'strict-transport-security': 'max-age=3600; includeSubDomains' }), HTTPS);
  assert.strictEqual(short.find((f) => f.id === 'hsts-short-max-age').severity, 'low');
  const zero = audit(withHeaders({ 'strict-transport-security': 'max-age=0' }), HTTPS);
  assert.strictEqual(zero.find((f) => f.id === 'hsts-short-max-age').severity, 'high');
  assert.ok(has(zero, 'hsts-no-subdomains'));
});

test('plain HTTP on a public host is flagged, localhost is not', () => {
  assert.ok(has(audit(HARDENED, { url: 'http://example.com/' }), 'no-https'));
  assert.ok(!has(audit(HARDENED, { url: 'http://127.0.0.1:8080/' }), 'no-https'));
});

// --- CSP --------------------------------------------------------------------

const csp = (policy) => audit(withHeaders({ 'content-security-policy': policy }), HTTPS);

test("'unsafe-inline' is flagged unless a nonce/hash is present", () => {
  assert.ok(has(csp("default-src 'self' 'unsafe-inline'"), 'csp-unsafe-inline'));
  assert.ok(!has(csp("script-src 'self' 'unsafe-inline' 'nonce-r4nd'"), 'csp-unsafe-inline'));
});

test("'unsafe-eval' is flagged", () => {
  assert.ok(has(csp("script-src 'self' 'unsafe-eval'"), 'csp-unsafe-eval'));
});

test('wildcard and scheme-only script sources are flagged', () => {
  for (const src of ['*', 'https:', 'data:']) {
    assert.ok(has(csp('script-src ' + src), 'csp-broad-script-src'), src);
  }
  // ignored by browsers when strict-dynamic + nonce is used
  assert.ok(!has(csp("script-src 'nonce-x' 'strict-dynamic' https:"), 'csp-broad-script-src'));
});

test('script-src falls back to default-src', () => {
  assert.ok(has(csp("img-src 'self'"), 'csp-no-script-src'));
  assert.ok(!has(csp("default-src 'self'"), 'csp-no-script-src'));
});

test('object-src and base-uri gaps are flagged', () => {
  const f = csp("default-src 'self'");
  assert.ok(has(f, 'csp-object-src'));
  assert.ok(has(f, 'csp-base-uri'));
  assert.ok(!has(csp("default-src 'none'; base-uri 'self'"), 'csp-object-src'));
});

test('a weakness is ignored if another enforced policy blocks it', () => {
  const f = csp("script-src *, script-src 'self'; object-src 'none'; base-uri 'self'");
  assert.ok(!has(f, 'csp-broad-script-src'));
});

test('report-only CSP is reported as not enforced', () => {
  const f = audit(
    withHeaders({ 'content-security-policy': undefined, 'content-security-policy-report-only': "default-src 'self'" }),
    HTTPS
  );
  assert.ok(has(f, 'csp-report-only'));
  assert.ok(!has(f, 'csp-missing'));
});

// --- framing, sniffing, referrer -------------------------------------------

test('X-Frame-Options satisfies clickjacking protection without frame-ancestors', () => {
  const policy = "default-src 'self'; object-src 'none'; base-uri 'self'";
  assert.ok(has(csp(policy), 'clickjacking'));
  assert.ok(!has(audit(withHeaders({ 'content-security-policy': policy, 'x-frame-options': 'sameorigin' }), HTTPS), 'clickjacking'));
});

test('nosniff must have the exact value', () => {
  assert.ok(has(audit(withHeaders({ 'x-content-type-options': 'yes' }), HTTPS), 'nosniff-missing'));
});

test('unsafe referrer policies are flagged; the last token wins', () => {
  assert.ok(has(audit(withHeaders({ 'referrer-policy': 'unsafe-url' }), HTTPS), 'referrer-policy-unsafe'));
  assert.ok(!has(audit(withHeaders({ 'referrer-policy': 'unsafe-url, no-referrer' }), HTTPS), 'referrer-policy-unsafe'));
});

// --- cookies ----------------------------------------------------------------

const cookie = (c, opts) => audit(withHeaders({ 'set-cookie': [c] }), opts || HTTPS);

test('session cookie without Secure/HttpOnly is high/medium', () => {
  const f = cookie('session_id=1; Path=/; SameSite=Lax');
  assert.strictEqual(f.find((x) => x.id === 'cookie-no-secure').severity, 'high');
  assert.strictEqual(f.find((x) => x.id === 'cookie-no-httponly').severity, 'medium');
});

test('non-session cookie gets lower severities', () => {
  const f = cookie('theme=dark; Path=/; SameSite=Lax');
  assert.strictEqual(f.find((x) => x.id === 'cookie-no-secure').severity, 'medium');
  assert.strictEqual(f.find((x) => x.id === 'cookie-no-httponly').severity, 'low');
});

test('missing Secure is only low on plain-HTTP localhost', () => {
  const f = cookie('sid=1; HttpOnly; SameSite=Lax', { url: 'http://localhost:3000/' });
  assert.strictEqual(f.find((x) => x.id === 'cookie-no-secure').severity, 'low');
});

test('SameSite=None without Secure and missing SameSite are flagged', () => {
  assert.ok(has(cookie('a=1; HttpOnly; SameSite=None'), 'cookie-samesite-none-insecure'));
  assert.ok(has(cookie('a=1; Secure; HttpOnly'), 'cookie-no-samesite'));
});

test('cookie prefix rules are enforced', () => {
  assert.ok(has(cookie('__Host-a=1; Secure; Path=/; Domain=example.com; HttpOnly; SameSite=Lax'), 'cookie-host-prefix'));
  assert.ok(has(cookie('__Secure-a=1; HttpOnly; SameSite=Lax'), 'cookie-secure-prefix'));
});

// --- CORS / disclosure / misc ----------------------------------------------

test('dangerous CORS configurations are flagged', () => {
  assert.ok(has(audit(withHeaders({ 'access-control-allow-origin': 'null' }), HTTPS), 'cors-null-origin'));
  assert.ok(
    has(
      audit(withHeaders({ 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }), HTTPS),
      'cors-wildcard-credentials'
    )
  );
  assert.ok(!has(audit(withHeaders({ 'access-control-allow-origin': '*' }), HTTPS), 'cors-wildcard-credentials'));
});

test('version disclosure is flagged', () => {
  const f = audit(withHeaders({ server: 'nginx/1.18.0', 'x-powered-by': 'Express' }), HTTPS);
  assert.ok(has(f, 'server-version'));
  assert.ok(has(f, 'disclosure-x-powered-by'));
  assert.ok(!has(audit(withHeaders({ server: 'nginx' }), HTTPS), 'server-version'));
});

test('X-XSS-Protection enabled is info, 0 is fine', () => {
  assert.ok(has(audit(withHeaders({ 'x-xss-protection': '1; mode=block' }), HTTPS), 'x-xss-protection-enabled'));
  assert.ok(!has(audit(withHeaders({ 'x-xss-protection': '0' }), HTTPS), 'x-xss-protection-enabled'));
});

// --- options ----------------------------------------------------------------

test('ignore and minSeverity filter findings', () => {
  const all = audit({}, HTTPS);
  const ignored = audit({}, Object.assign({ ignore: ['csp-missing'] }, HTTPS));
  assert.strictEqual(ignored.length, all.length - 1);
  assert.ok(audit({}, Object.assign({ minSeverity: 'high' }, HTTPS)).every((f) => f.severity === 'high'));
});

test('every finding has the documented shape', () => {
  for (const f of audit({ 'set-cookie': ['a=1'], server: 'x/1', 'access-control-allow-origin': 'null' }, HTTPS)) {
    for (const k of ['id', 'severity', 'title', 'detail', 'fix']) {
      assert.strictEqual(typeof f[k], 'string', k + ' on ' + f.id);
    }
  }
});
