// Summarizes a bench/run.sh result directory: per scenario the median over the runs of oha's latency
// percentiles (ms, with the spread of p50 across runs), the achieved rate, the server's CPU time per
// request (cgroup usage_usec / requests), then the in-process benchmark if it ran.
//   node summarize.mjs <dir>
import { existsSync, readFileSync, readdirSync } from 'node:fs';

const dir = process.argv[2];
if (!dir) {
  console.error('usage: node summarize.mjs <result-dir>');
  process.exit(2);
}

const median = (xs) => {
  const sorted = [...xs].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
};
const ms = (seconds) => seconds * 1000;
const fmt = (value, digits = 3) => value.toFixed(digits);

const scenarios = readFileSync(`${dir}/scenarios.txt`, 'utf8').trim().split('\n');
const cpu = readFileSync(`${dir}/cpu.txt`, 'utf8')
  .trim()
  .split('\n')
  .map((line) => line.split(' '));

const header = ['scenario', 'path', 'runs', 'rps', 'p50 ms', 'p50 min–max', 'p90 ms', 'p99 ms', 'max ms', 'errors', 'CPU µs/req'];
const rows = [header];
for (const scenario of scenarios) {
  const [name, path] = scenario.split(' ');
  const files = readdirSync(dir).filter((f) => f.startsWith(`${name}-`) && f.endsWith('.json'));
  const results = files.map((f) => JSON.parse(readFileSync(`${dir}/${f}`, 'utf8')));
  const p = (key) => results.map((r) => ms(r.latencyPercentiles[key]));
  const p50 = p('p50');
  const errors = results.reduce((sum, r) => sum + Math.round((1 - r.summary.successRate) * (r.summary.total ? 1 : 0)), 0);
  const statusOk = results.every((r) => Object.keys(r.statusCodeDistribution ?? {}).every((code) => code < '400'));
  const cpuPerRequest = cpu.filter(([n]) => n === name).map(([, , usec, requests]) => Number(usec) / Number(requests));
  rows.push([
    name,
    path,
    String(results.length),
    fmt(median(results.map((r) => r.summary.requestsPerSec)), 0),
    fmt(median(p50)),
    `${fmt(Math.min(...p50))}–${fmt(Math.max(...p50))}`,
    fmt(median(p('p90'))),
    fmt(median(p('p99'))),
    fmt(median(results.map((r) => ms(r.summary.slowest)))),
    statusOk && errors === 0 ? '0' : `${errors}${statusOk ? '' : ' (status ≥ 400)'}`,
    fmt(median(cpuPerRequest), 1),
  ]);
}

const widths = header.map((_, i) => Math.max(...rows.map((r) => r[i].length)));
for (const row of rows) console.log(row.map((cell, i) => cell.padEnd(widths[i])).join('  '));

if (existsSync(`${dir}/inprocess.txt`)) {
  console.log('\nhandler chain in process (no sockets, no access log):');
  console.log(readFileSync(`${dir}/inprocess.txt`, 'utf8').trimEnd());
}
