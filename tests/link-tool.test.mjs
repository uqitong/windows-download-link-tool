import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import {
  LinkError, safeError, validateTargets, CookieJar, parsePayload,
  acquireTarget, verifyCandidate, seal, unseal,
} from '../lib/link-tool.mjs';

// All network responses and signatures in this file are synthetic fixtures.
// No test contacts Microsoft or downloads a file.
const NOW = Date.parse('2026-01-01T00:00:00Z');
const target = Object.freeze({
  id: 'test-windows-x64', productEditionId: 123, skuId: 456,
  fileName: 'Test_Windows_x64_zh-cn.iso', sizeBytes: 2 * 1024 ** 3,
  officialPage: 'https://www.microsoft.com/zh-cn/software-download/windows11',
});
function candidate(overrides = {}) {
  const u = new URL('https://software.download.prss.microsoft.com/' + target.fileName);
  u.searchParams.set('P1', String((NOW + 86400000) / 1000));
  u.searchParams.set('P4', 'TEST_ONLY_NOT_A_REAL_SIGNATURE');
  for (const [key, value] of Object.entries(overrides)) u.searchParams.set(key, value);
  return u.href;
}
const hasCode = expected => error => error instanceof LinkError && error.code === expected;
function byteResponse({ status = 206, contentRange = `bytes 0-0/${target.sizeBytes}`, contentLength = '1', bytes = [0] } = {}) {
  return new Response(Uint8Array.from(bytes), { status, headers: {
    'content-range': contentRange, 'content-length': contentLength,
    'content-type': 'application/octet-stream',
  } });
}
function jsonResponse(value) { return new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } }); }
function responseWithCookies(values) { return { headers: { getSetCookie: () => values } }; }

test('target manifest accepts an exact valid public target', () => {
  const targets = [target];
  assert.equal(validateTargets(targets), targets);
});

for (const [label, targets] of [
  ['empty', []], ['not an array', {}], ['too many', Array(31).fill(target)],
  ['duplicate IDs', [target, target]],
]) {
  test(`target manifest rejects ${label}`, () => assert.throws(() => validateTargets(targets), LinkError));
}

for (const [field, value] of [
  ['id', '../escape'], ['productEditionId', 0], ['skuId', 1.5],
  ['fileName', '../other.iso'], ['fileName', 'wrong.exe'], ['sizeBytes', 0],
  ['officialPage', 'https://www.microsoft.com.evil.invalid/zh-cn/software-download/windows11'],
  ['officialPage', 'http://www.microsoft.com/zh-cn/software-download/windows11'],
]) {
  test(`target manifest rejects invalid ${field} ${String(value).slice(0, 20)}`, () => {
    assert.throws(() => validateTargets([{ ...target, [field]: value }]), hasCode('INVALID_TARGET'));
  });
}

test('JSON payload accepts normal and double-encoded objects', () => {
  const object = { Errors: [], Skus: [{ Id: 456 }] };
  assert.deepEqual(parsePayload(JSON.stringify(object)), object);
  assert.deepEqual(parsePayload(JSON.stringify(JSON.stringify(object))), object);
});

test('payload parsing never includes a rejected response body in the error', () => {
  const marker = 'SYNTHETIC_PRIVATE_RESPONSE_MARKER';
  for (const body of [
    'Microsoft Sentinel/rejected ' + marker,
    'Access Denied ' + marker,
    JSON.stringify({ Errors: [{ Value: marker }] }),
    JSON.stringify({ errors: marker }),
  ]) {
    assert.throws(() => parsePayload(body), error => {
      assert.equal(safeError(error), 'MICROSOFT_REJECTED');
      assert.ok(!String(error).includes(marker));
      return true;
    });
  }
});

test('payload parsing rejects invalid JSON and scalar payloads', () => {
  assert.throws(() => parsePayload('<html>not json</html>'), hasCode('INVALID_JSON'));
  assert.throws(() => parsePayload('null'), hasCode('INVALID_PAYLOAD'));
  assert.throws(() => parsePayload('7'), hasCode('INVALID_PAYLOAD'));
});

test('safe errors do not echo native errors or externally supplied code fields', () => {
  const error = new Error(candidate());
  error.code = 'SYNTHETIC_PRIVATE_VALUE';
  assert.equal(safeError(error), 'REQUEST_FAILED');
  assert.equal(safeError({ code: 'SYNTHETIC_PRIVATE_VALUE' }), 'REQUEST_FAILED');
  assert.equal(safeError(new LinkError('MICROSOFT_REJECTED')), 'MICROSOFT_REJECTED');
});

test('cookies are isolated by exact origin unless a valid domain was supplied', () => {
  const jar = new CookieJar();
  jar.capture(responseWithCookies(['host=one; Path=/', 'shared=two; Domain=.microsoft.com; Path=/']), 'https://www.microsoft.com/start');
  assert.equal(jar.header('https://www.microsoft.com/next'), 'host=one; shared=two');
  assert.equal(jar.header('https://ov-df.microsoft.com/next'), 'shared=two');
  assert.equal(jar.header('https://vlscppe.microsoft.com/next'), 'shared=two');
  assert.equal(jar.header('https://microsoft.com.evil.invalid/next'), '');
  assert.equal(jar.header('https://notmicrosoft.com/next'), '');
});

test('cookies reject foreign Domain attributes, obey path boundaries and clear Max-Age=0', () => {
  const jar = new CookieJar();
  jar.capture(responseWithCookies([
    'foreign=no; Domain=evil.invalid; Path=/', 'scoped=yes; Path=/software', 'kept=old; Path=/',
  ]), 'https://www.microsoft.com/software/start');
  assert.equal(jar.header('https://evil.invalid/'), '');
  assert.equal(jar.header('https://www.microsoft.com/software/item'), 'scoped=yes; kept=old');
  assert.equal(jar.header('https://www.microsoft.com/software-other'), 'kept=old');
  jar.capture(responseWithCookies(['kept=gone; Path=/; Max-Age=0']), 'https://www.microsoft.com/');
  assert.equal(jar.header('https://www.microsoft.com/'), '');
});

test('Range verification requires exactly one byte and expected total size', async () => {
  let calls = 0;
  const result = await verifyCandidate(target, candidate(), { now: NOW, fetchImpl: async (u, options) => {
    calls++;
    assert.equal(new URL(u).hostname, 'software.download.prss.microsoft.com');
    assert.equal(options.headers.Range, 'bytes=0-0');
    assert.equal(options.headers['accept-encoding'], 'identity');
    assert.equal(options.redirect, 'manual');
    assert.ok(options.signal instanceof AbortSignal);
    return byteResponse();
  } });
  assert.equal(calls, 1);
  assert.equal(result.id, target.id);
  assert.equal(result.sizeBytes, target.sizeBytes);
  assert.equal(result.expiresAt, '2026-01-02T00:00:00.000Z');
});

for (const [label, url] of [
  ['evil host', candidate().replace('software.download.prss.microsoft.com', 'example.invalid')],
  ['suffix host', candidate().replace('software.download.prss.microsoft.com', 'software.download.prss.microsoft.com.evil.invalid')],
  ['plain HTTP', candidate().replace('https:', 'http:')],
  ['userinfo', candidate().replace('https://', 'https://user:password@')],
  ['different image', candidate().replace(target.fileName, 'Wrong_Windows.iso')],
]) {
  test(`Range rejects ${label} before any request`, async () => {
    let called = false;
    await assert.rejects(verifyCandidate(target, url, { now: NOW, fetchImpl: async () => { called = true; throw new Error('must not fetch'); } }), hasCode('MEDIA_IDENTITY_MISMATCH'));
    assert.equal(called, false);
  });
}

for (const [label, expires] of [
  ['expired', String(NOW / 1000 - 1)], ['less than ten minutes', String(NOW / 1000 + 599)],
  ['missing', ''], ['non-numeric', 'not-an-expiry'], ['millisecond timestamp', String(NOW + 86400000)],
]) {
  test(`Range rejects ${label} expiration before any request`, async () => {
    let called = false;
    await assert.rejects(verifyCandidate(target, candidate({ P1: expires }), { now: NOW, fetchImpl: async () => { called = true; } }), hasCode('EXPIRING_LINK'));
    assert.equal(called, false);
  });
}

for (const [label, response] of [
  ['wrong total size', { contentRange: `bytes 0-0/${target.sizeBytes + 1}` }],
  ['wrong offset', { contentRange: `bytes 1-1/${target.sizeBytes}` }],
  ['multi-byte range', { contentRange: `bytes 0-1/${target.sizeBytes}`, contentLength: '2' }],
  ['missing declared length', { contentLength: '' }],
]) {
  test(`Range rejects ${label}`, async () => {
    await assert.rejects(verifyCandidate(target, candidate(), { now: NOW, fetchImpl: async () => byteResponse(response) }), hasCode('RANGE_IDENTITY_MISMATCH'));
  });
}

for (const status of [200, 302, 403, 429, 500]) {
  test(`HTTP ${status} cancels without opening a download reader or following a redirect`, async () => {
    let cancelled = false, reads = 0, calls = 0;
    await assert.rejects(verifyCandidate(target, candidate(), { now: NOW, fetchImpl: async () => {
      calls++;
      return { status, headers: new Headers({ 'content-length': String(target.sizeBytes), location: 'https://example.invalid/large.iso' }),
        body: { locked: false, getReader() { reads++; throw new Error('must not read large response'); }, async cancel() { cancelled = true; } } };
    } }), hasCode('RANGE_IDENTITY_MISMATCH'));
    assert.equal(reads, 0);
    assert.equal(calls, 1);
    assert.equal(cancelled, true);
  });
}

test('Range rejects an empty body even when the headers claim one byte', async () => {
  await assert.rejects(verifyCandidate(target, candidate(), { now: NOW, fetchImpl: async () => byteResponse({ bytes: [] }) }), hasCode('EMPTY_RANGE'));
});

test('Range rejects extra body bytes even when the headers claim one byte', async () => {
  await assert.rejects(verifyCandidate(target, candidate(), { now: NOW, fetchImpl: async () => byteResponse({ bytes: [0, 1] }) }), hasCode('RANGE_LENGTH_MISMATCH'));
});

test('normal acquisition uses only allowed hosts, matching SKU and exact media', async () => {
  const requests = [];
  const replies = [
    new Response('<html>Official download page</html>'), new Response('public tags response'),
    new Response('resource?w=synthetic&rticks=1234567890123'), new Response('session accepted'),
    jsonResponse({ Skus: [{ Id: target.skuId, Language: 'Chinese (Simplified)' }] }),
    jsonResponse({ ProductDownloadOptions: [{ Uri: candidate() }] }), byteResponse(),
  ];
  const result = await acquireTarget(target, { now: NOW, fetchImpl: async (u, options) => {
    requests.push({ url: new URL(u), options });
    assert.equal(options.redirect, 'manual');
    assert.ok(replies.length > 0);
    return replies.shift();
  } });
  assert.equal(result.id, target.id);
  assert.equal(requests.length, 7);
  assert.equal(requests[4].url.searchParams.get('ProductEditionId'), String(target.productEditionId));
  assert.equal(requests[5].url.searchParams.get('SKU'), String(target.skuId));
  assert.equal(requests[4].url.searchParams.get('sessionID'), requests[5].url.searchParams.get('sessionID'));
});

test('acquisition does not follow an allowed-origin redirect to an unrelated host', async () => {
  let calls = 0;
  await assert.rejects(acquireTarget(target, { now: NOW, fetchImpl: async () => {
    calls++;
    return new Response(null, { status: 302, headers: { location: 'https://example.invalid/collect' } });
  } }), hasCode('UNEXPECTED_REQUEST_HOST'));
  assert.equal(calls, 1);
});

test('acquisition stops at explicit HTTP rejection without retries', async () => {
  for (const status of [403, 429]) {
    let calls = 0;
    await assert.rejects(acquireTarget(target, { now: NOW, fetchImpl: async () => {
      calls++; return new Response('synthetic rejection detail', { status });
    } }), hasCode('MICROSOFT_REJECTED'));
    assert.equal(calls, 1);
  }
});

test('acquisition stops at a successful-HTTP Sentinel response without retries', async () => {
  let calls = 0;
  await assert.rejects(acquireTarget(target, { now: NOW, fetchImpl: async () => {
    calls++; return new Response('Microsoft Sentinel/rejected');
  } }), hasCode('MICROSOFT_REJECTED'));
  assert.equal(calls, 1);
});

const keyOptions = { modulusLength: 3072,
  publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } };
const recipient = generateKeyPairSync('rsa', keyOptions);
const differentRecipient = generateKeyPairSync('rsa', keyOptions);

test('encrypted result round-trips without a plaintext URL or private key in its envelope', () => {
  const payload = { version: 1, checkedAt: '2026-01-01T00:00:00.000Z', records: [{ ...target, resolvedUrl: candidate() }], failures: [] };
  const envelope = seal(payload, recipient.publicKey);
  assert.equal(envelope.algorithm, 'RSA-OAEP-256+A256GCM');
  assert.equal(Buffer.from(envelope.iv, 'base64').length, 12);
  assert.equal(Buffer.from(envelope.tag, 'base64').length, 16);
  const serialized = JSON.stringify(envelope);
  assert.ok(!serialized.includes('TEST_ONLY_NOT_A_REAL_SIGNATURE'));
  assert.ok(!serialized.includes('PRIVATE KEY'));
  assert.ok(!serialized.includes('microsoft.com'));
  assert.deepEqual(unseal(envelope, recipient.privateKey), payload);
});

test('encryption randomizes both key wrapping and ciphertext for identical input', () => {
  const first = seal({ value: 1 }, recipient.publicKey);
  const second = seal({ value: 1 }, recipient.publicKey);
  assert.notEqual(first.iv, second.iv);
  assert.notEqual(first.wrappedKey, second.wrappedKey);
  assert.notEqual(first.ciphertext, second.ciphertext);
});

test('decryption rejects a different recipient private key', () => {
  const envelope = seal({ value: 1 }, recipient.publicKey);
  assert.throws(() => unseal(envelope, differentRecipient.privateKey));
});

for (const field of ['wrappedKey', 'iv', 'tag', 'ciphertext']) {
  test(`decryption rejects tampered ${field}`, () => {
    const envelope = seal({ value: 'integrity check' }, recipient.publicKey);
    const changed = Buffer.from(envelope[field], 'base64');
    changed[0] ^= 1;
    assert.throws(() => unseal({ ...envelope, [field]: changed.toString('base64') }, recipient.privateKey));
  });
}

test('decryption rejects unknown version and algorithm', () => {
  const envelope = seal({ value: 1 }, recipient.publicKey);
  assert.throws(() => unseal({ ...envelope, version: 2 }, recipient.privateKey), hasCode('INVALID_ENVELOPE'));
  assert.throws(() => unseal({ ...envelope, algorithm: 'AES-CBC' }, recipient.privateKey), hasCode('INVALID_ENVELOPE'));
});
