'use strict';

const { normalizeHeaders } = require('./parse');
const { RULES } = require('./rules');
const { rank, sortFindings } = require('./severity');

/**
 * Audit a set of HTTP response headers. Pure: no I/O.
 *
 * @param {object} headers  response headers (plain object, Map or Headers)
 * @param {object} [options]
 * @param {string|URL} [options.url]      URL the response came from
 * @param {boolean} [options.https]       override TLS detection (default: from url)
 * @param {string[]} [options.ignore]     finding ids to suppress
 * @param {string} [options.minSeverity]  drop findings below this level
 * @returns {import('./rules').Finding[]} findings, worst first
 */
function audit(headers, options) {
  const opts = options || {};
  const url = opts.url ? new URL(String(opts.url)) : null;
  const https = typeof opts.https === 'boolean' ? opts.https : !!url && url.protocol === 'https:';
  const ctx = { headers: normalizeHeaders(headers), https, url };

  const ignore = new Set(opts.ignore || []);
  const min = opts.minSeverity ? rank(opts.minSeverity) : 0;

  const findings = [];
  for (const rule of RULES) {
    for (const f of rule(ctx)) {
      if (ignore.has(f.id) || rank(f.severity) < min) continue;
      findings.push(f);
    }
  }
  return sortFindings(findings);
}

/**
 * Count findings per severity.
 * @param {Array<{severity: string}>} findings
 */
function summarize(findings) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

module.exports = { audit, summarize };
