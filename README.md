# header-guard

> Audit a site's HTTP security headers in one command — with a concrete fix for every finding.

[日本語版 README](README.ja.md)

`header-guard` checks the response headers of any URL (including `localhost`) for
common web-security misconfigurations — Content-Security-Policy, HSTS, cookie
attributes, CORS, clickjacking and more — and tells you **what is wrong, why it
matters, and the exact header to add**.

- **Zero dependencies.** Node.js ≥ 12, nothing else.
- **CI-friendly.** Non-zero exit code on findings, `--json` output, `--ignore` for accepted risks.
- **Passive.** Sends one ordinary `GET` request (plus redirects). No payloads, no crawling.
- **Library too.** `audit(headers)` is a pure function — drop it into your integration tests.

```console
$ npx header-guard https://staging.example.com

header-guard https://staging.example.com/ [200]

  [HIGH]   CSP allows 'unsafe-inline' scripts  (csp-unsafe-inline)
           The script policy contains 'unsafe-inline' without a nonce or hash, which neutralises CSP's XSS protection.
           → Remove 'unsafe-inline' and use nonces ('nonce-<random>') or hashes for inline scripts.

  [HIGH]   Cookie `session_id` is missing Secure  (cookie-no-secure)
           The cookie can be sent over plain HTTP and intercepted.
           → Add the Secure attribute.

  [MEDIUM] Page can be framed by other sites  (clickjacking)
           Neither CSP frame-ancestors nor X-Frame-Options is set, enabling clickjacking.
           → Add `frame-ancestors 'self'` to the CSP (and `X-Frame-Options: SAMEORIGIN` for old browsers).
  ...

  5 high, 4 medium, 7 low, 1 info
```

## Usage

```sh
npx header-guard <url> [options]
curl -sI https://example.com | npx header-guard - --https   # audit headers from stdin
```

| Option | Description |
| --- | --- |
| `--fail-on <level>` | Exit 1 if a finding at this level or worse exists: `high` (default), `medium`, `low`, `info`, `none` |
| `--min-severity <level>` | Hide findings below this level |
| `--ignore <ids>` | Comma-separated finding ids to suppress (accepted risks) |
| `--json` | Print a JSON report |
| `-H, --header "Name: value"` | Extra request header, e.g. a session cookie to audit logged-in pages |
| `--timeout <ms>` | Request timeout (default 10000) |
| `--no-follow` | Don't follow redirects |
| `--insecure` | Accept self-signed certificates (local development) |
| `--https`, `--url <url>` | With `-`: context for headers read from stdin |

Exit codes: `0` passed · `1` findings at/above `--fail-on` · `2` usage or network error.

### In CI (GitHub Actions)

```yaml
- run: npm start &                    # start your app
- run: npx wait-on http://localhost:3000
- run: npx header-guard http://localhost:3000 --fail-on medium --ignore permissions-policy-missing
```

### As a library

```js
const { audit } = require('header-guard');

// e.g. inside a Jest / Mocha / node:test integration test
const res = await fetch('http://localhost:3000/');
const findings = audit(res.headers, { url: res.url, minSeverity: 'medium' });
assert.deepStrictEqual(findings, []);
```

TypeScript types are included.

## Checks

| id | Severity | What it catches |
| --- | --- | --- |
| `no-https` | high | Public site served over plain HTTP without redirecting to HTTPS |
| `hsts-missing` / `hsts-invalid` | high | HTTPS response without a valid `Strict-Transport-Security` |
| `hsts-short-max-age` | low (high if 0) | HSTS `max-age` under 6 months |
| `hsts-no-subdomains` | info | HSTS without `includeSubDomains` |
| `csp-missing` | high | No `Content-Security-Policy` |
| `csp-report-only` | medium | Only `Content-Security-Policy-Report-Only` is set |
| `csp-no-script-src` | high | Neither `script-src` nor `default-src` |
| `csp-unsafe-inline` | high | `'unsafe-inline'` scripts without nonce/hash |
| `csp-broad-script-src` | high | `*`, `https:`, `data:` … as script sources (unless `'strict-dynamic'` + nonce) |
| `csp-unsafe-eval` | medium | `'unsafe-eval'` |
| `csp-insecure-script-host` | medium | `http://` script sources |
| `csp-object-src` / `csp-base-uri` | low | Missing `object-src 'none'` / `base-uri` |
| `clickjacking` | medium | No `frame-ancestors` and no valid `X-Frame-Options` |
| `nosniff-missing` | medium | No `X-Content-Type-Options: nosniff` |
| `referrer-policy-missing` / `-unsafe` | low / medium | Missing, or `unsafe-url` / `no-referrer-when-downgrade` |
| `cors-null-origin` | high | `Access-Control-Allow-Origin: null` |
| `cors-wildcard-credentials` | medium | `*` combined with `Allow-Credentials: true` |
| `cookie-no-secure` | high–low | Cookie without `Secure` (severity depends on HTTPS and whether it looks like a session cookie) |
| `cookie-no-httponly` | medium / low | Cookie without `HttpOnly` (medium for session-like names) |
| `cookie-no-samesite` | low | Cookie without explicit `SameSite` |
| `cookie-samesite-none-insecure` | high | `SameSite=None` without `Secure` (browsers reject it) |
| `cookie-host-prefix` / `cookie-secure-prefix` | high | `__Host-` / `__Secure-` cookies that break prefix rules |
| `server-version`, `disclosure-x-powered-by`, … | low | Software/version disclosure |
| `x-xss-protection-enabled` | info | Legacy XSS auditor enabled |
| `permissions-policy-missing` | info | No `Permissions-Policy` |

Rules model real browser behaviour rather than just header presence — for example,
multiple CSP policies are intersected, `'unsafe-inline'` is ignored when a nonce is
present, and host sources are ignored under `'strict-dynamic'`.

## Scope and responsible use

`header-guard` only reads the response headers of a normal request; it does not
probe for vulnerabilities. It is a fast first line of defence, **not** a substitute
for a penetration test. Only scan sites you own or are authorised to test.

## Development

```sh
npm test          # zero-dependency test runner (test/run.js)
```

Project layout:

```
bin/header-guard.js   CLI (argument parsing, exit codes)
src/parse.js          header / CSP / Set-Cookie parsers
src/rules.js          the checks — each rule is a pure (context) => Finding[]
src/audit.js          runs the rules, filtering and sorting
src/fetch.js          fetches headers with redirect handling
src/format.js         text and JSON reporters
```

Adding a check means writing one function in `src/rules.js` and its tests in
`test/audit.test.js`.

## License

MIT
