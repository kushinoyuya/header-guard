'use strict';

// Minimal zero-dependency test runner: each *.test.js file calls `test(name, fn)`.
const fs = require('fs');
const path = require('path');

const tests = [];
global.test = (name, fn) => tests.push({ name, fn });
global.test.skip = (reason) => {
  throw Object.assign(new Error(reason), { skip: true });
};

const only = process.argv[2];
for (const file of fs.readdirSync(__dirname).sort()) {
  if (!file.endsWith('.test.js')) continue;
  if (only && file.indexOf(only) === -1) continue;
  const before = tests.length;
  require(path.join(__dirname, file));
  for (let i = before; i < tests.length; i++) tests[i].file = file;
}

(async () => {
  let passed = 0;
  let failed = 0;
  let skipped = 0;
  for (const t of tests) {
    const label = t.file + ' › ' + t.name;
    try {
      await t.fn();
      passed++;
      console.log('  ✔ ' + label);
    } catch (e) {
      if (e && e.skip) {
        skipped++;
        console.log('  - ' + label + ' (skipped: ' + e.message + ')');
        continue;
      }
      failed++;
      console.log('  ✘ ' + label);
      console.log((e && e.stack ? e.stack : String(e)).replace(/^/gm, '      '));
    }
  }
  console.log('\n' + passed + ' passed, ' + failed + ' failed, ' + skipped + ' skipped');
  process.exitCode = failed ? 1 : 0;
})();
