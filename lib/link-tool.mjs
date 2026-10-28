import {
  randomUUID, randomBytes, createCipheriv, createDecipheriv,
  publicEncrypt, privateDecrypt, constants,
} from 'node:crypto';

const REQUEST_HOSTS = new Set(['www.microsoft.com', 'vlscppe.microsoft.com', 'ov-df.microsoft.com']);
const DOWNLOAD_HOSTS = new Set(['software.download.prss.microsoft.com', 'software-static.download.prss.microsoft.com', 'download.microsoft.com']);
const PROFILE = '606624d44113';
const INSTANCE = '560dc9f3-1aa5-4a2f-b63c-9e18f8d0e175';
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export class LinkError extends Error {
  constructor(code) { super(code); this.code = code; }
}

export function safeError(error) {
  return error instanceof LinkError ? error.code : 'REQUEST_FAILED';
}

export function validateTargets(targets) {
  if (!Array.isArray(targets) || !targets.length || targets.length > 30) throw new LinkError('INVALID_TARGETS');
  const ids = new Set();
  for (const item of targets) {
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(item.id) || ids.has(item.id) ||
        !Number.isSafeInteger(item.productEditionId) || item.productEditionId <= 0 ||
        !Number.isSafeInteger(item.skuId) || item.skuId <= 0 ||
        !/^[A-Za-z0-9_.-]+\.iso$/i.test(item.fileName) ||
        !Number.isSafeInteger(item.sizeBytes) || item.sizeBytes <= 1024 ** 3 ||
        !/^https:\/\/www\.microsoft\.com\/zh-cn\/software-download\/windows11(?:arm64)?$/.test(item.officialPage)) {
      throw new LinkError('INVALID_TARGET');
    }
    ids.add(item.id);
  }
  return targets;
}

export class CookieJar {
  #entries = new Map();
  capture(response, requestUrl) {
    const u = new URL(requestUrl);
    for (const header of response.headers.getSetCookie?.() ?? []) {
      const [pair, ...attributes] = header.split(';');
      const at = pair.indexOf('=');
      if (at < 1) continue;
      const name = pair.slice(0, at).trim();
      const value = pair.slice(at + 1).trim();
      const props = Object.fromEntries(attributes.map(v => {
        const [key, ...rest] = v.trim().split('=');
        return [key.toLowerCase(), rest.join('=')];
      }));
      const domain = (props.domain ?? u.hostname).replace(/^\./, '').toLowerCase();
      if (domain !== u.hostname && !u.hostname.endsWith('.' + domain)) continue;
      const path = props.path?.startsWith('/') ? props.path : '/';
      const key = domain + path + name;
      if (props['max-age'] === '0' || !value) this.#entries.delete(key);
      else this.#entries.set(key, { name, value, domain, path, hostOnly: !props.domain });
    }
  }
  header(requestUrl) {
    const u = new URL(requestUrl);
    return [...this.#entries.values()].filter(c =>
      (u.hostname === c.domain || (!c.hostOnly && u.hostname.endsWith('.' + c.domain))) &&
      (u.pathname === c.path || u.pathname.startsWith(c.path.endsWith('/') ? c.path : c.path + '/')),
    ).map(c => c.name + '=' + c.value).join('; ');
  }
}

async function boundedText(response) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.length;
      if (length > MAX_RESPONSE_BYTES) throw new LinkError('RESPONSE_TOO_LARGE');
      chunks.push(part.value);
    }
  } finally { await reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks).toString('utf8');
}

export function parsePayload(text) {
  if (/sentinel|reject(?:ed|ion)?|access denied/i.test(text)) throw new LinkError('MICROSOFT_REJECTED');
  let result;
  try { result = JSON.parse(text); if (typeof result === 'string') result = JSON.parse(result); }
  catch { throw new LinkError('INVALID_JSON'); }
  if (!result || typeof result !== 'object') throw new LinkError('INVALID_PAYLOAD');
  const errors = result.Errors ?? result.errors;
  if (errors != null && (!Array.isArray(errors) || errors.length)) throw new LinkError('MICROSOFT_REJECTED');
  return result;
}

function apiUrl(method, fields) {
  const u = new URL('https://www.microsoft.com/software-download-connector/api/' + method);
  for (const [key, value] of Object.entries({ profile: PROFILE, ...fields })) u.searchParams.set(key, String(value));
  return u;
}

export async function acquireTarget(target, { fetchImpl = fetch, now = Date.now() } = {}) {
  validateTargets([target]);
  const jar = new CookieJar();
  const session = randomUUID();
  const referer = target.officialPage.replace('/zh-cn/', '/en-us/');
  const requestText = async (address, accept = '*/*') => {
    let u = new URL(address);
    for (let redirect = 0; redirect < 5; redirect++) {
      if (u.protocol !== 'https:' || !REQUEST_HOSTS.has(u.hostname) || u.username || u.password) throw new LinkError('UNEXPECTED_REQUEST_HOST');
      const headers = { accept, 'accept-language': 'en-US,en;q=0.9', 'accept-encoding': 'identity',
        'user-agent': 'uqitong-windows-link-tool/0.1', referer };
      const cookies = jar.header(u);
      if (cookies) headers.cookie = cookies;
      if (accept === 'application/json') headers['X-Requested-With'] = 'XMLHttpRequest';
      const response = await fetchImpl(u, { headers, redirect: 'manual', signal: AbortSignal.timeout(30000) });
      jar.capture(response, u);
      if ([301,302,303,307,308].includes(response.status)) {
        const location = response.headers.get('location');
        await response.body?.cancel();
        if (!location) throw new LinkError('INVALID_REDIRECT');
        u = new URL(location, u); continue;
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new LinkError(response.status === 403 || response.status === 429 ? 'MICROSOFT_REJECTED' : 'HTTP_' + response.status);
      }
      const text = await boundedText(response);
      if (/sentinel|reject(?:ed|ion)?|access denied/i.test(text)) throw new LinkError('MICROSOFT_REJECTED');
      return text;
    }
    throw new LinkError('TOO_MANY_REDIRECTS');
  };

  await requestText(referer, 'text/html');
  await requestText('https://vlscppe.microsoft.com/tags?' + new URLSearchParams({ org_id: 'y6jn8c31', session_id: session }));
  const handshake = await requestText('https://ov-df.microsoft.com/mdt.js?' + new URLSearchParams({ instanceId: INSTANCE, PageId: 'si', session_id: session }));
  const w = handshake.match(/[?&]w=([^&"'\s]+)/i)?.[1];
  const rticks = handshake.match(/rticks[="]+\+?\s*(\d{10,})/i)?.[1];
  if (!w || !rticks) throw new LinkError('SESSION_UNAVAILABLE');
  await requestText('https://ov-df.microsoft.com/?' + new URLSearchParams({
    session_id: session, CustomerId: INSTANCE, PageId: 'si', w, rticks, mdt: String(Date.now()),
  }));
  const skuResponse = parsePayload(await requestText(apiUrl('getskuinformationbyproductedition', {
    ProductEditionId: target.productEditionId, SKU: 'undefined', friendlyFileName: 'undefined', Locale: 'en-US', sessionID: session,
  }), 'application/json'));
  const sku = skuResponse.Skus?.find(s => Number(s.Id) === target.skuId);
  const language = `${sku?.Language ?? ''} ${sku?.LocalizedLanguage ?? ''}`;
  if (!sku || !/chinese.*simplified|simplified.*chinese|简体|zh-cn/i.test(language)) throw new LinkError('SKU_NOT_OFFERED');
  const payload = parsePayload(await requestText(apiUrl('GetProductDownloadLinksBySku', {
    productEditionId: 'undefined', SKU: target.skuId, friendlyFileName: 'undefined', Locale: 'en-US', sessionID: session,
  }), 'application/json'));
  const options = payload.ProductDownloadOptions;
  if (!Array.isArray(options)) throw new LinkError('NO_DOWNLOAD_OPTIONS');
  const candidates = options.map(o => o.Uri ?? o.URI ?? o.Url ?? o.URL).filter(value => {
    try { return decodeURIComponent(new URL(value).pathname.split('/').at(-1)) === target.fileName; }
    catch { return false; }
  });
  if (candidates.length !== 1) throw new LinkError('MEDIA_IDENTITY_MISMATCH');
  return verifyCandidate(target, candidates[0], { fetchImpl, now });
}

export async function verifyCandidate(target, address, { fetchImpl = fetch, now = Date.now() } = {}) {
  validateTargets([target]);
  const u = new URL(address);
  if (u.protocol !== 'https:' || !DOWNLOAD_HOSTS.has(u.hostname) || u.username || u.password ||
      decodeURIComponent(u.pathname.split('/').at(-1)) !== target.fileName) throw new LinkError('MEDIA_IDENTITY_MISMATCH');
  const expires = u.searchParams.get('P1');
  if (!/^\d{10}$/.test(expires ?? '') || Number(expires) * 1000 < now + 10 * 60 * 1000) throw new LinkError('EXPIRING_LINK');
  const response = await fetchImpl(u, { headers: { Range: 'bytes=0-0', 'accept-encoding': 'identity' },
    redirect: 'manual', signal: AbortSignal.timeout(30000) });
  try {
    if (response.status !== 206 || response.headers.get('content-range') !== `bytes 0-0/${target.sizeBytes}` ||
        response.headers.get('content-length') !== '1') throw new LinkError('RANGE_IDENTITY_MISMATCH');
    const reader = response.body?.getReader();
    if (!reader) throw new LinkError('EMPTY_RANGE');
    let received = 0;
    try {
      for (;;) { const part = await reader.read(); if (part.done) break;
        received += part.value.length; if (received > 1) throw new LinkError('RANGE_LENGTH_MISMATCH'); }
    } finally { await reader.cancel().catch(() => {}); }
    if (received !== 1) throw new LinkError('EMPTY_RANGE');
  } finally { if (response.body && !response.body.locked) await response.body.cancel().catch(() => {}); }
  return { ...target, resolvedUrl: u.href, expiresAt: new Date(Number(expires) * 1000).toISOString() };
}

export function seal(value, publicKey) {
  const key = randomBytes(32), iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  const wrappedKey = publicEncrypt({ key: publicKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, key);
  return { version: 1, algorithm: 'RSA-OAEP-256+A256GCM', wrappedKey: wrappedKey.toString('base64'),
    iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
}

export function unseal(envelope, privateKey) {
  if (envelope.version !== 1 || envelope.algorithm !== 'RSA-OAEP-256+A256GCM') throw new LinkError('INVALID_ENVELOPE');
  const key = privateDecrypt({ key: privateKey, oaepHash: 'sha256', padding: constants.RSA_PKCS1_OAEP_PADDING }, Buffer.from(envelope.wrappedKey, 'base64'));
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]).toString('utf8'));
}
