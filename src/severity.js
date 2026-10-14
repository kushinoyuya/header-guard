'use strict';

/** Severity levels, lowest first. */
const SEVERITIES = ['info', 'low', 'medium', 'high'];

/**
 * @param {string} s
 * @returns {number} rank of the severity (higher is worse), -1 if unknown
 */
function rank(s) {
  return SEVERITIES.indexOf(String(s).toLowerCase());
}

/**
 * Sort findings worst-first, keeping original order within a severity.
 * @param {Array<{severity: string}>} findings
 */
function sortFindings(findings) {
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => rank(b.f.severity) - rank(a.f.severity) || a.i - b.i)
    .map((x) => x.f);
}

module.exports = { SEVERITIES, rank, sortFindings };
