const fs = require('fs');
const split = require('split');

if (!fs.existsSync('yarn.lock')) {
  console.error('yarn.lock is missing');
  process.exit(1);
}

function parseYarnLock() {
  let pos = 0;
  let currentModule = '';
  const yarnLock = {};
  for (const row of fs.readFileSync('yarn.lock', 'utf8').split('\n')) {
    pos++;
    if (row.length > 0 && row[0] != ' ') {
      currentModule = row.replace(/"/g, '').replace(/(..*?)@.*/, '$1');
    }
    if (new RegExp(' +version').test(row)) {
      const version = row.replace(/\s+version "(.*)"/, '$1');
      if (!yarnLock[currentModule]) yarnLock[currentModule] = {};
      yarnLock[currentModule][version] = {
        'startLine': pos,
        'endLine': pos,
        'startColumn': 1,
        'endColumn': row.length,
      };
    }
  }
  return yarnLock;
}

function yarnLockRange(yarnLock, moduleName, version) {
  if (yarnLock[moduleName] && yarnLock[moduleName][version]) {
    return yarnLock[moduleName][version];
  } else {
    return {
      'startLine': 1,
    };
  }
}

const yarnLock = parseYarnLock();

const severities = {
  info: 'INFO',
  low: 'MINOR',
  moderate: 'MINOR',
  high: 'CRITICAL',
  critical: 'BLOCKER',
};

const resolvedIds = new Set();
const stats = {};
let firstLine = true;

function processRow(row) {
  if (!row) return;
  const {type, data} = JSON.parse(row);
  if (type !== 'auditAdvisory') return;
  const {advisory, resolution} = data;
  if (resolvedIds.has(resolution.id)) return;

  const [mainVersion, ...otherVersions] = new Set(advisory.findings.map((f) => f.version));

  if (!firstLine) {
    process.stdout.write(',');
  } else {
    firstLine = false;
  }
  process.stdout.write(JSON.stringify({
    engineId: 'yarn-audit',
    ruleId: resolution.id.toString(),
    severity: severities[advisory.severity] || 'INFO',
    type: 'VULNERABILITY',
    efforMinutes: 0,
    primaryLocation: {
      'message': advisory.overview,
      'filePath': 'yarn.lock',
      'textRange': yarnLockRange(yarnLock, advisory.module_name, mainVersion),
    },
    secondaryLocations: otherVersions.map((version) => {
      return {
        'message': advisory.overview,
        'filePath': 'yarn.lock',
        'textRange': yarnLockRange(yarnLock, advisory.module_name, version),
      };
    }),
  }));
  stats[advisory.severity] = (stats[advisory.severity] || 0) + 1;
}

process.stdout.write('{"issues":[');
process
  .stdin
  .pipe(split())
  .on('data', processRow)
  .on('end', () => {
    process.stdout.write(']}\n');
    const out = [];
    let total = 0;
    for(const [k,v] of Object.entries(stats)) {
      out.push(`${v} ${k}`);
      total += v;
    }
    console.error('yarn audit:');
    console.error(`  ${total} vulnerabilities found`);
    if (total > 0) {
      console.error(`  Severity: ${out.join(' | ')}`);
    }
  });
