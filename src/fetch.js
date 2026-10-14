'use strict';

const http = require('http');
const https = require('https');

/**
 * Fetch only the response headers of a URL (the body is discarded).
 *
 * @param {string} target
 * @param {object} [options]
 * @param {number} [options.timeout=10000]      per-request timeout in ms
 * @param {boolean} [options.followRedirects=true]
 * @param {number} [options.maxRedirects=5]
 * @param {Record<string,string>} [options.headers]  extra request headers
 * @param {boolean} [options.insecure=false]    accept invalid TLS certs (local dev)
 * @returns {Promise<{url: string, statusCode: number, headers: object, redirects: string[]}>}
 */
function fetchHeaders(target, options) {
  const opts = Object.assign(
    { timeout: 10000, followRedirects: true, maxRedirects: 5, headers: {}, insecure: false },
    options
  );
  const redirects = [];

  const once = (href) =>
    new Promise((resolve, reject) => {
      let url;
      try {
        url = new URL(href);
      } catch (e) {
        reject(new Error('Invalid URL: ' + href));
        return;
      }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        reject(new Error('Unsupported protocol: ' + url.protocol));
        return;
      }
      const lib = url.protocol === 'https:' ? https : http;
      const req = lib.request(
        url,
        {
          method: 'GET',
          headers: Object.assign({ 'user-agent': 'header-guard', accept: '*/*' }, opts.headers),
          rejectUnauthorized: !opts.insecure,
        },
        (res) => {
          res.resume(); // headers are all we need
          res.on('error', () => {});
          resolve({ url: url.href, statusCode: res.statusCode, headers: res.headers });
          req.destroy();
        }
      );
      req.setTimeout(opts.timeout, () => {
        req.destroy(new Error('Timed out after ' + opts.timeout + 'ms: ' + url.href));
      });
      req.on('error', reject);
      req.end();
    });

  const loop = (href) =>
    once(href).then((res) => {
      const location = res.headers.location;
      const isRedirect = res.statusCode >= 300 && res.statusCode < 400 && location;
      if (!opts.followRedirects || !isRedirect) {
        return Object.assign(res, { redirects });
      }
      if (redirects.length >= opts.maxRedirects) {
        throw new Error('Too many redirects (>' + opts.maxRedirects + ')');
      }
      redirects.push(res.url);
      return loop(new URL(location, res.url).href);
    });

  return loop(target);
}

module.exports = { fetchHeaders };
