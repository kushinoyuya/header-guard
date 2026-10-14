#!/usr/bin/env node
'use strict';

const lib = require('../src/index');
const { rank, SEVERITIES } = require('../src/severity');
const pkg = require('../package.json');

const HELP = `Usage: header-guard <url | -> [options]

Audit a site's HTTP security headers (CSP, HSTS, cookies, CORS, ...).
Pass "-" to read raw response headers from stdin, e.g. \`curl -sI URL | header-guard -\`.

Options:
  --fail-on <level>    exit 1 if a finding at this level or worse exists
                       (high | medium | low | info | none)   [default: high]
  --min-severity <l>   hide findings below this level         [default: info]
  --ignore <ids>       comma-separated finding ids to suppress
  --json               print a JSON report
  -H, --header <h>     extra request header, e.g. -H "Cookie: sid=..."
  --timeout <ms>       request timeout                        [default: 10000]
  --no-follow          do not follow redirects
  --insecure           accept invalid TLS certificates (local dev only)
  --https              with "-": treat the response as served over HTTPS
  --url <url>          with "-": URL the headers came from
  --no-color           disable colours (also honours NO_COLOR)
  -h, --help           show this help
  -v, --version        show version

Exit codes: 0 = passed, 1 = findings at/above --fail-on, 2 = usage or network error.`;

class UsageError extends Error {}

function parseArgs(argv) {
  const opts = {
    target: null,
    failOn: 'high',
    minSeverity: 'info',
    ignore: [],
    json: false,
    headers: {},
    timeout: 10000,
    followRedirects: true,
    insecure: false,
    https: undefined,
    url: undefined,
    color: undefined,
  };

  const value = (i, flag) => {
    if (i + 1 >= argv.length) throw new UsageError(flag + ' requires a value');
    return argv[i + 1];
  };
  const level = (v, flag, extra) => {
    const l = String(v).toLowerCase();
    if (rank(l) === -1 && l !== extra) {
      throw new UsageError(flag + ' must be one of ' + SEVERITIES.concat(extra ? [extra] : []).join(', '));
    }
    return l;
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h':
      case '--help':
        opts.help = true;
        break;
      case '-v':
      case '--version':
        opts.version = true;
        break;
      case '--json':
        opts.json = true;
        break;
      case '--fail-on':
        opts.failOn = level(value(i++, a), a, 'none');
        break;
      case '--min-severity':
        opts.minSeverity = level(value(i++, a), a);
        break;
      case '--ignore':
        opts.ignore = opts.ignore.concat(value(i++, a).split(',').map((s) => s.trim()).filter(Boolean));
        break;
      case '-H':
      case '--header': {
        const h = value(i++, a);
        const idx = h.indexOf(':');
        if (idx <= 0) throw new UsageError('Invalid header "' + h + '", expected "Name: value"');
        opts.headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
        break;
      }
      case '--timeout': {
        const n = Number(value(i++, a));
        if (!(n > 0)) throw new UsageError('--timeout must be a positive number');
        opts.timeout = n;
        break;
      }
      case '--no-follow':
        opts.followRedirects = false;
        break;
      case '--insecure':
        opts.insecure = true;
        break;
      case '--https':
        opts.https = true;
        break;
      case '--url':
        opts.url = value(i++, a);
        break;
      case '--no-color':
        opts.color = false;
        break;
      default:
        if (a !== '-' && a.charAt(0) === '-') throw new UsageError('Unknown option ' + a);
        if (opts.target) throw new UsageError('Only one target may be given');
        opts.target = a;
    }
  }
  return opts;
}

function readStdin(stdin) {
  return new Promise((resolve, reject) => {
    let data = '';
    stdin.setEncoding('utf8');
    stdin.on('data', (c) => (data += c));
    stdin.on('end', () => resolve(data));
    stdin.on('error', reject);
  });
}

function withScheme(target) {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? target : 'https://' + target;
}

/**
 * Run the CLI. Returns the exit code instead of exiting, for testability.
 * @param {string[]} argv
 * @param {{ stdin: NodeJS.ReadableStream, stdout: NodeJS.WritableStream, stderr: NodeJS.WritableStream, env: object }} io
 */
function run(argv, io) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (e) {
    io.stderr.write('header-guard: ' + e.message + '\n\n' + HELP + '\n');
    return Promise.resolve(2);
  }
  if (opts.help) {
    io.stdout.write(HELP + '\n');
    return Promise.resolve(0);
  }
  if (opts.version) {
    io.stdout.write(pkg.version + '\n');
    return Promise.resolve(0);
  }
  if (!opts.target) {
    io.stderr.write('header-guard: missing <url>\n\n' + HELP + '\n');
    return Promise.resolve(2);
  }

  const auditOpts = { ignore: opts.ignore, minSeverity: opts.minSeverity };
  let reportP;
  if (opts.target === '-') {
    reportP = readStdin(io.stdin).then((text) => {
      const parsed = lib.parseRawHeaders(text);
      if (!Object.keys(parsed.headers).length) throw new Error('No headers found on stdin');
      return {
        url: opts.url,
        statusCode: parsed.statusCode,
        redirects: [],
        findings: lib.audit(parsed.headers, Object.assign({ url: opts.url, https: opts.https }, auditOpts)),
      };
    });
  } else {
    reportP = lib.auditUrl(
      withScheme(opts.target),
      Object.assign(
        {
          timeout: opts.timeout,
          followRedirects: opts.followRedirects,
          headers: opts.headers,
          insecure: opts.insecure,
        },
        auditOpts
      )
    );
  }

  return reportP.then(
    (report) => {
      const color = opts.color !== false && !('NO_COLOR' in io.env) && !!io.stdout.isTTY;
      io.stdout.write(opts.json ? lib.formatJson(report) : lib.formatText(report, { color }));
      if (opts.failOn === 'none') return 0;
      const threshold = rank(opts.failOn);
      return report.findings.some((f) => rank(f.severity) >= threshold) ? 1 : 0;
    },
    (err) => {
      io.stderr.write('header-guard: ' + err.message + '\n');
      return 2;
    }
  );
}

module.exports = { run, parseArgs };

if (require.main === module) {
  run(process.argv.slice(2), {
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    env: process.env,
  }).then((code) => {
    process.exitCode = code;
  });
}
