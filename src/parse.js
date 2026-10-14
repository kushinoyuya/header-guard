'use strict';

/**
 * Normalise a header bag into { lowercase-name: string[] }.
 * Accepts Node's IncomingMessage#headers, a plain object, a Map, or a
 * WHATWG Headers-like object with entries().
 * @param {object} input
 * @returns {Record<string, string[]>}
 */
function normalizeHeaders(input) {
  const out = Object.create(null);
  if (!input) return out;

  const add = (name, value) => {
    const key = String(name).toLowerCase();
    const values = Array.isArray(value) ? value : [value];
    for (const v of values) {
      if (v === undefined || v === null) continue;
      (out[key] = out[key] || []).push(String(v));
    }
  };

  if (typeof input.entries === 'function' && !Array.isArray(input)) {
    for (const [k, v] of input.entries()) add(k, v);
  } else {
    for (const k of Object.keys(input)) add(k, input[k]);
  }
  return out;
}

/**
 * Parse raw HTTP response headers, e.g. the output of `curl -sI <url>`.
 * When several responses are present (curl -L), the last one wins.
 * @param {string} text
 * @returns {{ statusCode: number|null, headers: Record<string, string[]> }}
 */
function parseRawHeaders(text) {
  const blocks = String(text)
    .replace(/\r\n/g, '\n')
    .split(/\n\s*\n/)
    .filter((b) => /^HTTP\/\S+\s+\d{3}/.test(b.trim()) || /^[\w-]+\s*:/.test(b.trim()));
  const block = blocks.length ? blocks[blocks.length - 1] : '';

  let statusCode = null;
  const pairs = [];
  for (const line of block.split('\n')) {
    if (!line.trim()) continue;
    const status = /^HTTP\/\S+\s+(\d{3})/.exec(line.trim());
    if (status) {
      statusCode = Number(status[1]);
      continue;
    }
    // obs-fold: continuation of the previous header value
    if (/^[ \t]/.test(line) && pairs.length) {
      pairs[pairs.length - 1][1] += ' ' + line.trim();
      continue;
    }
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    pairs.push([line.slice(0, idx).trim(), line.slice(idx + 1).trim()]);
  }

  const headers = Object.create(null);
  for (const [k, v] of pairs) {
    const key = k.toLowerCase();
    (headers[key] = headers[key] || []).push(v);
  }
  return { statusCode, headers };
}

/**
 * Parse a Set-Cookie header value.
 * @param {string} header
 * @returns {{ name: string, value: string, attributes: Record<string, string|true> }}
 */
function parseSetCookie(header) {
  const parts = String(header).split(';');
  const first = parts.shift() || '';
  const eq = first.indexOf('=');
  const name = (eq === -1 ? first : first.slice(0, eq)).trim();
  const value = eq === -1 ? '' : first.slice(eq + 1).trim();

  const attributes = Object.create(null);
  for (const part of parts) {
    const p = part.trim();
    if (!p) continue;
    const i = p.indexOf('=');
    const key = (i === -1 ? p : p.slice(0, i)).trim().toLowerCase();
    attributes[key] = i === -1 ? true : p.slice(i + 1).trim();
  }
  return { name, value, attributes };
}

/**
 * Parse a Content-Security-Policy header into its policies.
 * A header may carry several comma-separated policies; all are enforced.
 * @param {string|string[]} header
 * @returns {Array<Record<string, string[]>>} one directive map per policy
 */
function parseCsp(header) {
  const raw = Array.isArray(header) ? header.join(',') : String(header);
  return raw
    .split(',')
    .map((policy) => {
      const directives = Object.create(null);
      for (const d of policy.split(';')) {
        const tokens = d.trim().split(/\s+/).filter(Boolean);
        if (!tokens.length) continue;
        const name = tokens[0].toLowerCase();
        // Per CSP3, only the first occurrence of a directive counts.
        if (!(name in directives)) directives[name] = tokens.slice(1);
      }
      return directives;
    })
    .filter((d) => Object.keys(d).length > 0);
}

module.exports = { normalizeHeaders, parseRawHeaders, parseSetCookie, parseCsp };
