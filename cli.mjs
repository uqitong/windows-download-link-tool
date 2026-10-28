import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { acquireTarget, safeError, seal, unseal, selectTargets } from './lib/link-tool.mjs';
import { buildSourceContext } from './lib/context.mjs';

async function writeNew(file, data) {
  await mkdir(dirname(file), { recursive: true });
  await writeFile(file, data, { flag: 'wx', mode: 0o600 });
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'keygen' && args.length === 2) {
    const pair = generateKeyPairSync('rsa', { modulusLength: 3072,
      publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    await writeNew(args[0], pair.privateKey);
    await writeNew(args[1], pair.publicKey);
    console.log('KEYPAIR_CREATED private_key_local_only=true');
    return;
  }
  if (command === 'decrypt' && args.length === 3) {
    const result = unseal(JSON.parse(await readFile(args[0], 'utf8')), await readFile(args[1], 'utf8'));
    await writeNew(args[2], JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify({ checkedAt: result.checkedAt, successful: result.records.length, failed: result.failures.length,
      items: result.records.map(({id,fileName,sizeBytes,expiresAt}) => ({id,fileName,sizeBytes,expiresAt})), failures: result.failures }));
    return;
  }
  if (command === 'acquire' && args.length === 3) {
    const manifestBytes = await readFile(args[0]);
    const targets = selectTargets(JSON.parse(manifestBytes.toString('utf8')), process.env.TARGET_IDS ?? '');
    const source = buildSourceContext({ manifestBytes, targets });
    const publicKey = args[1] === 'env' ? process.env.RECIPIENT_PUBLIC_KEY : await readFile(args[1], 'utf8');
    const parsedKey = createPublicKey(publicKey);
    if (parsedKey.asymmetricKeyType !== 'rsa' || parsedKey.asymmetricKeyDetails.modulusLength < 3072) throw new Error('Invalid recipient key');
    const result = { version: source ? 2 : 1, ...(source ? { source } : {}),
      checkedAt: new Date().toISOString(), records: [], failures: [] };
    for (const target of targets) {
      try {
        const record = await acquireTarget(target);
        result.records.push(record);
        console.log(JSON.stringify({ id: record.id, status: 'verified', fileName: record.fileName, sizeBytes: record.sizeBytes, expiresAt: record.expiresAt }));
      } catch (error) {
        const failure = { id: target.id, reason: safeError(error) };
        result.failures.push(failure); console.log(JSON.stringify(failure));
      }
    }
    await writeNew(args[2], JSON.stringify(seal(result, publicKey)) + '\n');
    console.log(JSON.stringify({ successful: result.records.length, failed: result.failures.length, result: 'encrypted' }));
    if (result.failures.length) process.exitCode = 2;
    return;
  }
  throw new Error('Invalid command');
}
main().catch(error => { console.error('TOOL_FAILED ' + safeError(error)); process.exitCode = 1; });
