#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { buildManifest } from '../src/manifest.mjs';
import { audit } from '../src/audit.mjs';

const [cmd, arg] = process.argv.slice(2);

function printReport(report) {
  console.log(`verdict: ${report.verdict}`);
  for (const c of report.checks) console.log(`  [${c.status}] ${c.id} — ${c.detail}`);
  const f = report.findings;
  for (const key of Object.keys(f)) {
    if (f[key].length) console.log(`  findings.${key}: ${JSON.stringify(f[key])}`);
  }
  console.log(`  metrics: ${JSON.stringify(report.metrics)}`);
}

if (cmd === 'demo') {
  const specs = [];
  for (let i = 0; i < 10; i++) specs.push({ client: i % 2 ? 'beta' : 'alpha', payload: `record-${i}` });
  const { manifest } = buildManifest({ recordSpecs: specs, windowSize: 4, maxLatencyWindows: 2 });
  writeFileSync('demo-manifest.json', JSON.stringify(manifest, null, 2));
  const report = audit(manifest);
  writeFileSync('demo-report.json', JSON.stringify(report, null, 2));
  console.log('wrote demo-manifest.json and demo-report.json');
  printReport(report);
  process.exit(report.verdict === 'PASS' ? 0 : 1);
} else if (cmd === 'audit' && arg) {
  const manifest = JSON.parse(readFileSync(arg, 'utf8'));
  const report = audit(manifest);
  printReport(report);
  process.exit(report.verdict === 'PASS' ? 0 : 1);
} else {
  console.log('usage: audit.mjs demo | audit.mjs audit <manifest.json>');
  process.exit(2);
}
