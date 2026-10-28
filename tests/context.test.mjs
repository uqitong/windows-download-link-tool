import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { buildSourceContext } from '../lib/context.mjs';
import { LinkError, selectTargets } from '../lib/link-tool.mjs';

const targets = Object.freeze(['first-x64', 'second-arm64'].map((id, index) => Object.freeze({
  id, productEditionId: index + 100, skuId: index + 200,
  fileName: `Synthetic_Windows_${index}.iso`, sizeBytes: 2 * 1024 ** 3,
  officialPage: 'https://www.microsoft.com/zh-cn/software-download/windows11',
})));
const manifestBytes = Buffer.from(JSON.stringify(targets, null, 2) + '\n');
const env = Object.freeze({
  GITHUB_ACTIONS: 'true', SOURCE_REPOSITORY: 'uqitong/windows-download-link-tool',
  SOURCE_WORKFLOW: 'check-links.yml', SOURCE_REF: 'refs/heads/main',
  SOURCE_SHA: 'a'.repeat(40), SOURCE_RUN_ID: '40692261856', SOURCE_RUN_ATTEMPT: '1',
});
const invalid = error => error instanceof LinkError && error.code === 'INVALID_SOURCE_CONTEXT';
const build = (changes = {}) => buildSourceContext({ env, manifestBytes, targets, ...changes });

test('local calls without CI source return no context and preserve version 1 compatibility', () => {
  for (const localEnv of [{}, { GITHUB_ACTIONS: 'false' }, { CI: 'true' }]) {
    assert.equal(buildSourceContext({ env: localEnv }), null);
  }
});

test('complete Actions context uses exact expected fields and raw manifest digest', () => {
  assert.deepEqual(build(), {
    repository: 'uqitong/windows-download-link-tool', workflow: 'check-links.yml',
    ref: 'refs/heads/main', sha: 'a'.repeat(40), runId: '40692261856', runAttempt: '1',
    targetsSha256: createHash('sha256').update(manifestBytes).digest('hex'),
    targetIds: ['first-x64', 'second-arm64'],
  });
});

test('raw byte hashing preserves whitespace and CRLF identity rather than normalizing JSON', () => {
  const crlf = Buffer.from(manifestBytes.toString('utf8').replaceAll('\n', '\r\n'));
  assert.equal(build({ manifestBytes: crlf }).targetsSha256, createHash('sha256').update(crlf).digest('hex'));
  assert.notEqual(build({ manifestBytes: crlf }).targetsSha256, build().targetsSha256);
  assert.deepEqual(JSON.parse(crlf), JSON.parse(manifestBytes));
});

test('context binds selected target IDs and order while hashing the complete manifest', () => {
  const selected = selectTargets(targets, 'second-arm64,first-x64');
  const value = build({ targets: selected });
  assert.deepEqual(value.targetIds, ['second-arm64', 'first-x64']);
  assert.equal(value.targetsSha256, build().targetsSha256);
  assert.deepEqual(build({ targets: selectTargets(targets, 'second-arm64') }).targetIds, ['second-arm64']);
});

for (const name of Object.keys(env).filter(name => name !== 'GITHUB_ACTIONS')) {
  test(`missing ${name} is rejected in CI`, () => {
    const incomplete = { ...env }; delete incomplete[name];
    assert.throws(() => build({ env: incomplete }), invalid);
  });
  test(`blank ${name} is rejected in CI`, () => {
    assert.throws(() => build({ env: { ...env, [name]: '' } }), invalid);
  });
}

for (const flag of [undefined, 'false', '1', true]) {
  test(`source metadata without a true Actions flag is rejected (${String(flag)})`, () => {
    assert.throws(() => build({ env: { ...env, GITHUB_ACTIONS: flag } }), invalid);
  });
}

test('an Actions execution with no explicit source mappings is rejected', () => {
  assert.throws(() => build({ env: { GITHUB_ACTIONS: 'true' } }), invalid);
});

for (const [field, value] of [
  ['SOURCE_REPOSITORY', 'another-owner/windows-download-link-tool'],
  ['SOURCE_WORKFLOW', '../check-links.yml'],
  ['SOURCE_REF', 'refs/pull/1/merge'],
  ['SOURCE_SHA', 'A'.repeat(40)],
  ['SOURCE_SHA', 'a'.repeat(39)],
  ['SOURCE_SHA', 'x'.repeat(40)],
  ['SOURCE_RUN_ID', 40692261856],
  ['SOURCE_RUN_ID', '0'],
  ['SOURCE_RUN_ID', '0123'],
  ['SOURCE_RUN_ID', '123\n'],
  ['SOURCE_RUN_ID', '1'.repeat(21)],
  ['SOURCE_RUN_ATTEMPT', '-1'],
  ['SOURCE_RUN_ATTEMPT', '01'],
  ['SOURCE_RUN_ATTEMPT', '1'.repeat(7)],
]) {
  test(`invalid ${field} ${JSON.stringify(value)} is rejected without echoing metadata`, () => {
    assert.throws(() => build({ env: { ...env, [field]: value } }), invalid);
  });
}

for (const [name, bytes] of [
  ['missing', undefined], ['string', manifestBytes.toString('utf8')],
  ['empty', Buffer.alloc(0)], ['oversized', Buffer.alloc(1024 * 1024 + 1)],
  ['bad JSON', Buffer.from('not-json')], ['no targets', Buffer.from('[]')],
]) {
  test(`invalid ${name} manifest cannot produce CI context`, () => {
    assert.throws(() => build({ manifestBytes: bytes }), invalid);
  });
}

test('selected target IDs must belong to the exact manifest and have matching media identity', () => {
  for (const replacement of [
    { ...targets[0], id: 'other-x64' }, { ...targets[0], productEditionId: 999 },
    { ...targets[0], skuId: 999 }, { ...targets[0], fileName: 'Other.iso' },
    { ...targets[0], sizeBytes: targets[0].sizeBytes + 1 },
    { ...targets[0], officialPage: 'https://www.microsoft.com/zh-cn/software-download/windows11arm64' },
  ]) {
    assert.throws(() => build({ targets: [replacement] }), invalid);
  }
  assert.throws(() => build({ targets: [] }), invalid);
  assert.throws(() => build({ targets: [targets[0], targets[0]] }), invalid);
});

test('returned context does not share or mutate caller target ID arrays', () => {
  const value = build();
  value.targetIds.reverse();
  assert.deepEqual(build().targetIds, ['first-x64', 'second-arm64']);
  assert.equal(Object.isFrozen(env), true);
  assert.equal(Object.isFrozen(targets), true);
});

test('workflow has two daily standard free runner attempts with bounded isolated encrypted artifacts', async () => {
  const workflow = await readFile(new URL('../.github/workflows/check-links.yml', import.meta.url), 'utf8');
  assert.match(workflow, /cron: '23 5,17 \* \* \*'/);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /runs-on: ubuntu-latest/);
  assert.match(workflow, /timeout-minutes: 15/);
  assert.match(workflow, /permissions:\s*contents: read/);
  assert.match(workflow, /cancel-in-progress: false/);
  assert.match(workflow, /name: encrypted-download-results-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/);
  assert.match(workflow, /retention-days: 1/);
  for (const [name, value] of [
    ['SOURCE_REPOSITORY', '${{ github.repository }}'], ['SOURCE_WORKFLOW', 'check-links.yml'],
    ['SOURCE_REF', '${{ github.ref }}'], ['SOURCE_SHA', '${{ github.sha }}'],
    ['SOURCE_RUN_ID', '${{ github.run_id }}'], ['SOURCE_RUN_ATTEMPT', '${{ github.run_attempt }}'],
  ]) assert.ok(workflow.includes(`${name}: ${value}`));
  assert.doesNotMatch(workflow, /secrets\.|contents: write|self-hosted|coscli|keepalive/i);
});
