'use strict';

const { parseCsp, parseSetCookie } = require('./parse');

/**
 * @typedef {Object} Finding
 * @property {string} id        stable identifier, usable with --ignore
 * @property {'high'|'medium'|'low'|'info'} severity
 * @property {string} title
 * @property {string} detail    what was observed
 * @property {string} fix       how to fix it
 */

/**
 * @typedef {Object} Context
 * @property {Record<string, string[]>} headers  lowercase name -> values
 * @property {boolean} https                    response was served over TLS
 * @property {URL|null} url
 */

const ONE_YEAR = 31536000;
const HALF_YEAR = 15552000;

function finding(id, severity, title, detail, fix) {
  return { id, severity, title, detail, fix };
}

function header(ctx, name) {
  const v = ctx.headers[name];
  return v && v.length ? v.join(', ') : undefined;
}

// ---------------------------------------------------------------------------
// Content-Security-Policy
// ---------------------------------------------------------------------------

const SCRIPT_FALLBACK = ['script-src', 'default-src'];
const OBJECT_FALLBACK = ['object-src', 'default-src'];

function effective(policy, chain) {
  for (const name of chain) {
    if (name in policy) return policy[name];
  }
  return null;
}

const isNonceOrHash = (s) => /^'(nonce-|sha256-|sha384-|sha512-)/i.test(s);
const lower = (list) => list.map((s) => s.toLowerCase());

/** Findings for a single CSP policy. Returned as a map keyed by finding id. */
function checkPolicy(policy) {
  const found = {};
  const add = (f) => {
    found[f.id] = f;
  };

  const script = effective(policy, SCRIPT_FALLBACK);
  if (!script) {
    add(finding(
      'csp-no-script-src',
      'high',
      'CSP does not restrict scripts',
      'Neither script-src nor default-src is set, so any script source is allowed.',
      "Add `default-src 'self'` (or a stricter script-src) to the policy."
    ));
  } else {
    const s = lower(script);
    const hasNonceOrHash = s.some(isNonceOrHash);
    const strictDynamic = s.indexOf("'strict-dynamic'") !== -1;

    // CSP2+ browsers ignore 'unsafe-inline' when a nonce or hash is present.
    if (s.indexOf("'unsafe-inline'") !== -1 && !hasNonceOrHash) {
      add(finding(
        'csp-unsafe-inline',
        'high',
        "CSP allows 'unsafe-inline' scripts",
        "The script policy contains 'unsafe-inline' without a nonce or hash, which neutralises CSP's XSS protection.",
        "Remove 'unsafe-inline' and use nonces ('nonce-<random>') or hashes for inline scripts."
      ));
    }
    if (s.indexOf("'unsafe-eval'") !== -1) {
      add(finding(
        'csp-unsafe-eval',
        'medium',
        "CSP allows 'unsafe-eval'",
        "The script policy contains 'unsafe-eval', allowing eval(), new Function() and string timers.",
        "Remove 'unsafe-eval'; refactor code that builds code from strings."
      ));
    }
    // With 'strict-dynamic' + nonce/hash, host and scheme sources are ignored.
    if (!(strictDynamic && hasNonceOrHash)) {
      const broad = s.filter((x) => x === '*' || x === 'http:' || x === 'https:' || x === 'data:' || x === 'blob:');
      if (broad.length) {
        add(finding(
          'csp-broad-script-src',
          'high',
          'CSP allows scripts from any host',
          'The script policy contains ' + broad.join(', ') + ', which lets an attacker load script from almost anywhere.',
          'Restrict script sources to specific origins, or use nonces with \'strict-dynamic\'.'
        ));
      }
    }
    const insecure = s.filter((x) => /^http:\/\//.test(x));
    if (insecure.length) {
      add(finding(
        'csp-insecure-script-host',
        'medium',
        'CSP allows scripts over plain HTTP',
        'Script sources loaded without TLS: ' + insecure.join(', ') + '.',
        'Serve these scripts over https://.'
      ));
    }
  }

  const object = effective(policy, OBJECT_FALLBACK);
  if (!object || lower(object).join(' ') !== "'none'") {
    add(finding(
      'csp-object-src',
      'low',
      "CSP does not set object-src 'none'",
      'Plugin content (<object>, <embed>) is not fully blocked.',
      "Add `object-src 'none'`."
    ));
  }

  if (!('base-uri' in policy)) {
    add(finding(
      'csp-base-uri',
      'low',
      'CSP does not restrict base-uri',
      'An injected <base> tag could redirect relative script URLs.',
      "Add `base-uri 'self'` (or 'none')."
    ));
  }

  return found;
}

function cspRule(ctx) {
  const enforced = header(ctx, 'content-security-policy');
  const reportOnly = header(ctx, 'content-security-policy-report-only');

  if (!enforced) {
    if (reportOnly) {
      return [finding(
        'csp-report-only',
        'medium',
        'CSP is report-only',
        'Only Content-Security-Policy-Report-Only is set, so violations are reported but not blocked.',
        'Once the reports are clean, send the policy as Content-Security-Policy.'
      )];
    }
    return [finding(
      'csp-missing',
      'high',
      'Content-Security-Policy is missing',
      'No CSP header was found; the browser applies no restrictions on script, style or frame sources.',
      "Start with `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'` and tighten from there."
    )];
  }

  // Every policy is enforced, so a weakness only matters if *all* policies have it.
  const perPolicy = parseCsp(enforced).map(checkPolicy);
  if (!perPolicy.length) return [];
  return Object.keys(perPolicy[0])
    .filter((id) => perPolicy.every((p) => id in p))
    .map((id) => perPolicy[0][id]);
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

function hstsRule(ctx) {
  if (!ctx.https) return [];
  const v = header(ctx, 'strict-transport-security');
  if (!v) {
    return [finding(
      'hsts-missing',
      'high',
      'Strict-Transport-Security is missing',
      'Browsers may still connect over plain HTTP, enabling SSL-stripping attacks.',
      'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.'
    )];
  }
  const out = [];
  const m = /max-age\s*=\s*"?(\d+)"?/i.exec(v);
  const maxAge = m ? Number(m[1]) : NaN;
  if (isNaN(maxAge)) {
    out.push(finding(
      'hsts-invalid',
      'high',
      'Strict-Transport-Security has no valid max-age',
      'Value: `' + v + '`. Browsers ignore HSTS without max-age.',
      'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.'
    ));
  } else if (maxAge < HALF_YEAR) {
    out.push(finding(
      'hsts-short-max-age',
      maxAge === 0 ? 'high' : 'low',
      'Strict-Transport-Security max-age is short',
      'max-age=' + maxAge + ' (' + Math.round(maxAge / 86400) + ' days). At least 6 months is recommended.',
      'Use max-age=' + ONE_YEAR + ' (one year).'
    ));
  }
  if (!/includesubdomains/i.test(v)) {
    out.push(finding(
      'hsts-no-subdomains',
      'info',
      'Strict-Transport-Security does not include subdomains',
      'Subdomains can still be reached over plain HTTP.',
      'Add includeSubDomains once every subdomain supports HTTPS.'
    ));
  }
  return out;
}

const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|\[::1\]|::1)$/i;

function httpsRule(ctx) {
  if (ctx.https || !ctx.url) return [];
  if (LOCAL_HOST.test(ctx.url.hostname)) return [];
  return [finding(
    'no-https',
    'high',
    'Response was served over plain HTTP',
    ctx.url.href + ' did not redirect to HTTPS.',
    'Redirect all HTTP traffic to HTTPS and enable HSTS.'
  )];
}

// ---------------------------------------------------------------------------
// Browser hardening headers
// ---------------------------------------------------------------------------

function nosniffRule(ctx) {
  const v = header(ctx, 'x-content-type-options');
  if (v && v.trim().toLowerCase() === 'nosniff') return [];
  return [finding(
    'nosniff-missing',
    'medium',
    'X-Content-Type-Options: nosniff is missing',
    v ? 'Unexpected value `' + v + '`.' : 'Browsers may MIME-sniff responses into executable content.',
    'Add `X-Content-Type-Options: nosniff`.'
  )];
}

function clickjackingRule(ctx) {
  const csp = header(ctx, 'content-security-policy');
  if (csp && parseCsp(csp).some((p) => 'frame-ancestors' in p)) return [];

  const xfo = (header(ctx, 'x-frame-options') || '').trim().toUpperCase();
  if (xfo === 'DENY' || xfo === 'SAMEORIGIN') return [];
  return [finding(
    'clickjacking',
    'medium',
    'Page can be framed by other sites',
    xfo
      ? 'X-Frame-Options has unsupported value `' + xfo + '` and CSP has no frame-ancestors.'
      : 'Neither CSP frame-ancestors nor X-Frame-Options is set, enabling clickjacking.',
    "Add `frame-ancestors 'self'` to the CSP (and `X-Frame-Options: SAMEORIGIN` for old browsers)."
  )];
}

function referrerRule(ctx) {
  const v = header(ctx, 'referrer-policy');
  if (!v) {
    return [finding(
      'referrer-policy-missing',
      'low',
      'Referrer-Policy is missing',
      'Browser defaults apply; older browsers may leak full URLs (including query strings) to other sites.',
      'Add `Referrer-Policy: strict-origin-when-cross-origin`.'
    )];
  }
  // The last recognised token wins; a fallback list is comma-separated.
  const tokens = v.split(',').map((t) => t.trim().toLowerCase());
  const last = tokens[tokens.length - 1];
  if (last === 'unsafe-url' || last === 'no-referrer-when-downgrade') {
    return [finding(
      'referrer-policy-unsafe',
      'medium',
      'Referrer-Policy leaks full URLs',
      '`' + last + '` sends the full URL, including path and query, to other origins.',
      'Use `strict-origin-when-cross-origin` or `no-referrer`.'
    )];
  }
  return [];
}

function permissionsRule(ctx) {
  if (header(ctx, 'permissions-policy')) return [];
  return [finding(
    'permissions-policy-missing',
    'info',
    'Permissions-Policy is not set',
    'Powerful features (camera, geolocation, ...) are not explicitly disabled.',
    'Disable unused features, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.'
  )];
}

function xssProtectionRule(ctx) {
  const v = header(ctx, 'x-xss-protection');
  if (!v || v.trim() === '0') return [];
  return [finding(
    'x-xss-protection-enabled',
    'info',
    'X-XSS-Protection is enabled',
    'Value `' + v + '`. The legacy XSS auditor is removed from modern browsers and could introduce leaks in old ones.',
    'Remove the header or set `X-XSS-Protection: 0`, and rely on CSP.'
  )];
}

// ---------------------------------------------------------------------------
// Information disclosure
// ---------------------------------------------------------------------------

function disclosureRule(ctx) {
  const out = [];
  const server = header(ctx, 'server');
  if (server && /\d/.test(server)) {
    out.push(finding(
      'server-version',
      'low',
      'Server header discloses a version',
      'Server: `' + server + '` helps attackers pick known exploits.',
      'Strip the version (e.g. nginx `server_tokens off;`).'
    ));
  }
  for (const name of ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']) {
    const v = header(ctx, name);
    if (!v) continue;
    out.push(finding(
      'disclosure-' + name,
      'low',
      'Technology disclosed via ' + name,
      name + ': `' + v + '`.',
      'Remove the header (e.g. Express: `app.disable("x-powered-by")`).'
    ));
  }
  return out;
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

function corsRule(ctx) {
  const origin = (header(ctx, 'access-control-allow-origin') || '').trim();
  if (!origin) return [];
  const credentials = /^true$/i.test((header(ctx, 'access-control-allow-credentials') || '').trim());

  if (origin === 'null') {
    return [finding(
      'cors-null-origin',
      'high',
      'CORS allows the "null" origin',
      'Sandboxed iframes and file:// pages send Origin: null, so any attacker can match it.',
      'Never allow "null"; allow-list explicit origins.'
    )];
  }
  if (origin === '*' && credentials) {
    return [finding(
      'cors-wildcard-credentials',
      'medium',
      'CORS combines * with credentials',
      'Browsers reject this, which often leads developers to "fix" it by reflecting any Origin.',
      'Allow-list explicit origins when credentials are needed.'
    )];
  }
  return [];
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------

const SESSIONISH = /(sess|sid|token|auth|jwt|login|remember)/i;

function cookieRule(ctx) {
  const out = [];
  for (const raw of ctx.headers['set-cookie'] || []) {
    const c = parseSetCookie(raw);
    if (!c.name) continue;
    const a = c.attributes;
    const label = 'Cookie `' + c.name + '`';
    const sessionish = SESSIONISH.test(c.name);
    const sameSite = typeof a.samesite === 'string' ? a.samesite.toLowerCase() : null;

    if (/^__host-/i.test(c.name) && (!a.secure || a.path !== '/' || 'domain' in a)) {
      out.push(finding(
        'cookie-host-prefix',
        'high',
        label + ' violates the __Host- prefix rules',
        'Browsers reject __Host- cookies unless they have Secure, Path=/ and no Domain.',
        'Add Secure and Path=/, and remove Domain.'
      ));
    } else if (/^__secure-/i.test(c.name) && !a.secure) {
      out.push(finding(
        'cookie-secure-prefix',
        'high',
        label + ' violates the __Secure- prefix rules',
        'Browsers reject __Secure- cookies without the Secure attribute.',
        'Add the Secure attribute.'
      ));
    } else if (!a.secure) {
      out.push(finding(
        'cookie-no-secure',
        ctx.https ? (sessionish ? 'high' : 'medium') : 'low',
        label + ' is missing Secure',
        ctx.https
          ? 'The cookie can be sent over plain HTTP and intercepted.'
          : 'The site is HTTP-only here; mark the cookie Secure once served over HTTPS.',
        'Add the Secure attribute.'
      ));
    }

    if (!a.httponly) {
      out.push(finding(
        'cookie-no-httponly',
        sessionish ? 'medium' : 'low',
        label + ' is missing HttpOnly',
        sessionish
          ? 'This looks like a session/auth cookie; any XSS can read and steal it.'
          : 'Scripts can read this cookie. Fine only if client-side JS genuinely needs it.',
        'Add the HttpOnly attribute unless JavaScript must read the cookie.'
      ));
    }

    if (sameSite === 'none' && !a.secure) {
      out.push(finding(
        'cookie-samesite-none-insecure',
        'high',
        label + ' has SameSite=None without Secure',
        'Modern browsers reject this cookie.',
        'Add Secure, or use SameSite=Lax if cross-site sending is not needed.'
      ));
    } else if (!sameSite) {
      out.push(finding(
        'cookie-no-samesite',
        'low',
        label + ' has no SameSite attribute',
        'Browser defaults differ (Lax in Chromium, None in some others), so CSRF protection is inconsistent.',
        'Set SameSite=Lax (or Strict) explicitly.'
      ));
    }
  }
  return out;
}

/** All rules, in reporting order. Each takes a Context and returns Finding[]. */
const RULES = [
  httpsRule,
  hstsRule,
  cspRule,
  clickjackingRule,
  nosniffRule,
  referrerRule,
  corsRule,
  cookieRule,
  disclosureRule,
  xssProtectionRule,
  permissionsRule,
];

module.exports = { RULES };
