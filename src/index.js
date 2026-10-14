'use strict';

const { audit, summarize } = require('./audit');
const { fetchHeaders } = require('./fetch');
const { parseCsp, parseRawHeaders, parseSetCookie, normalizeHeaders } = require('./parse');
const { SEVERITIES } = require('./severity');
const { formatText, formatJson } = require('./format');

/**
 * Fetch a URL and audit its response headers.
 * @param {string} url
 * @param {object} [options]  fetch options plus audit options (ignore, minSeverity)
 */
function auditUrl(url, options) {
  const opts = options || {};
  return fetchHeaders(url, opts).then((res) => ({
    url: res.url,
    statusCode: res.statusCode,
    redirects: res.redirects,
    findings: audit(res.headers, { url: res.url, ignore: opts.ignore, minSeverity: opts.minSeverity }),
  }));
}

module.exports = {
  audit,
  auditUrl,
  summarize,
  fetchHeaders,
  parseCsp,
  parseRawHeaders,
  parseSetCookie,
  normalizeHeaders,
  formatText,
  formatJson,
  SEVERITIES,
};
