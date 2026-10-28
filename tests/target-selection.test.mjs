import test from 'node:test';
import assert from 'node:assert/strict';
import { LinkError, selectTargets } from '../lib/link-tool.mjs';

const targets = Object.freeze(['first-x64', 'second-arm64', 'third-x64'].map((id, index) => Object.freeze({
  id, productEditionId: 100 + index, skuId: 200 + index,
  fileName: `Synthetic_Windows_${index}.iso`, sizeBytes: 2 * 1024 ** 3,
  officialPage: 'https://www.microsoft.com/zh-cn/software-download/windows11',
})));
const invalidSelection = error => error instanceof LinkError && error.code === 'INVALID_SELECTION';

test('no selection and blank environment selection preserve all manifest targets', () => {
  assert.equal(selectTargets(targets), targets);
  assert.equal(selectTargets(targets, ''), targets);
  assert.equal(selectTargets(targets, ' \t\r\n '), targets);
});

test('a valid subset follows requested order and reuses only exact manifest records', () => {
  const result = selectTargets(targets, ' third-x64 , first-x64 ');
  assert.deepEqual(result.map(item => item.id), ['third-x64', 'first-x64']);
  assert.equal(result[0], targets[2]);
  assert.equal(result[1], targets[0]);
  assert.deepEqual(targets.map(item => item.id), ['first-x64', 'second-arm64', 'third-x64']);
});

test('a single valid target yields only that target', () => {
  assert.deepEqual(selectTargets(targets, 'second-arm64'), [targets[1]]);
});

for (const [label, selection] of [
  ['unknown ID', 'not-in-the-manifest'],
  ['case-changed ID', 'FIRST-X64'],
  ['unknown ID among known IDs', 'first-x64,unknown,third-x64'],
  ['leading empty component', ',first-x64'],
  ['trailing empty component', 'first-x64,'],
  ['middle empty component', 'first-x64,,third-x64'],
  ['whitespace-only component', 'first-x64,  ,third-x64'],
  ['all empty components', ',,'],
  ['duplicate ID', 'first-x64,first-x64'],
  ['duplicate after trim', 'first-x64, first-x64 '],
]) {
  test(`target selection rejects ${label}`, () => {
    assert.throws(() => selectTargets(targets, selection), invalidSelection);
  });
}

for (const [label, selection] of [
  ['HTTPS URL', 'https://example.invalid/arbitrary.iso'],
  ['URL after valid ID', 'first-x64,https://example.invalid/arbitrary.iso'],
  ['JSON target injection', '{"id":"new","officialPage":"https://example.invalid/"}'],
  ['query-string injection', 'first-x64?url=https://example.invalid/'],
  ['path traversal', '../../private/result.json'],
]) {
  test(`environment selection cannot add a ${label}`, () => {
    assert.throws(() => selectTargets(targets, selection), invalidSelection);
  });
}

test('selection still validates the complete manifest before selecting a subset', () => {
  const invalidManifest = [targets[0], { ...targets[1], officialPage: 'https://example.invalid/' }];
  assert.throws(() => selectTargets(invalidManifest, 'first-x64'), error => error.code === 'INVALID_TARGET');
});
