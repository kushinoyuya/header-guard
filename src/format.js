'use strict';

const { summarize } = require('./audit');

const CODES = { red: 31, yellow: 33, blue: 34, gray: 90, green: 32, bold: 1, dim: 2 };

function painter(enabled) {
  return (style, text) => (enabled ? '\u001b[' + CODES[style] + 'm' + text + '\u001b[0m' : text);
}

const SEVERITY_STYLE = { high: 'red', medium: 'yellow', low: 'blue', info: 'gray' };

/**
 * Human-readable report.
 * @param {object} report  { url, statusCode, redirects, findings }
 * @param {{ color?: boolean }} [options]
 */
function formatText(report, options) {
  const paint = painter(!!(options && options.color));
  const lines = [];

  const target = report.url || '(stdin)';
  const status = report.statusCode ? ' ' + paint('dim', '[' + report.statusCode + ']') : '';
  lines.push(paint('bold', 'header-guard') + ' ' + target + status);
  if (report.redirects && report.redirects.length) {
    lines.push(paint('dim', '  via ' + report.redirects.join(' -> ')));
  }
  lines.push('');

  if (!report.findings.length) {
    lines.push(paint('green', '  ✔ No issues found.'));
    return lines.join('\n') + '\n';
  }

  for (const f of report.findings) {
    const tag = paint(SEVERITY_STYLE[f.severity], ('[' + f.severity.toUpperCase() + ']').padEnd(9));
    lines.push('  ' + tag + paint('bold', f.title) + paint('dim', '  (' + f.id + ')'));
    lines.push('           ' + f.detail);
    lines.push('           ' + paint('green', '→ ' + f.fix));
    lines.push('');
  }

  const c = summarize(report.findings);
  lines.push(
    '  ' +
      [
        paint('red', c.high + ' high'),
        paint('yellow', c.medium + ' medium'),
        paint('blue', c.low + ' low'),
        paint('gray', c.info + ' info'),
      ].join(', ')
  );
  return lines.join('\n') + '\n';
}

/** Machine-readable report. */
function formatJson(report) {
  return (
    JSON.stringify(
      {
        url: report.url || null,
        statusCode: report.statusCode || null,
        redirects: report.redirects || [],
        summary: summarize(report.findings),
        findings: report.findings,
      },
      null,
      2
    ) + '\n'
  );
}

module.exports = { formatText, formatJson };
