import { createHash } from 'node:crypto';
import { LinkError, validateTargets } from './link-tool.mjs';

const SOURCE_ENV = Object.freeze([
  'SOURCE_REPOSITORY', 'SOURCE_WORKFLOW', 'SOURCE_REF', 'SOURCE_SHA',
  'SOURCE_RUN_ID', 'SOURCE_RUN_ATTEMPT',
]);
const IDENTITY_FIELDS = Object.freeze([
  'id', 'productEditionId', 'skuId', 'fileName', 'sizeBytes', 'officialPage',
]);

// This binds an encrypted result to a particular workflow invocation; it does
// not authenticate the sender. A consumer must also verify GitHub's run and
// artifact metadata against its own trusted repository, workflow and commit.
export function buildSourceContext({ env = process.env, manifestBytes, targets } = {}) {
  const hasSource = SOURCE_ENV.some(name => Object.hasOwn(env, name));
  const inActions = env.GITHUB_ACTIONS === 'true';
  if (!hasSource && !inActions) return null;
  if (!inActions || SOURCE_ENV.some(name => typeof env[name] !== 'string' || !env[name])) {
    throw new LinkError('INVALID_SOURCE_CONTEXT');
  }
  if (env.SOURCE_REPOSITORY !== 'uqitong/windows-download-link-tool' ||
      env.SOURCE_WORKFLOW !== 'check-links.yml' || env.SOURCE_REF !== 'refs/heads/main' ||
      !/^[a-f0-9]{40}$/.test(env.SOURCE_SHA) ||
      !/^[1-9][0-9]{0,19}$/.test(env.SOURCE_RUN_ID) ||
      !/^[1-9][0-9]{0,5}$/.test(env.SOURCE_RUN_ATTEMPT)) {
    throw new LinkError('INVALID_SOURCE_CONTEXT');
  }
  if (!(manifestBytes instanceof Uint8Array) || !manifestBytes.length || manifestBytes.length > 1024 * 1024) {
    throw new LinkError('INVALID_SOURCE_CONTEXT');
  }
  let manifest;
  try {
    manifest = validateTargets(JSON.parse(Buffer.from(manifestBytes).toString('utf8')));
    validateTargets(targets);
    for (const target of targets) {
      const expected = manifest.find(item => item.id === target.id);
      if (!expected || IDENTITY_FIELDS.some(field => expected[field] !== target[field])) {
        throw new LinkError('INVALID_SOURCE_CONTEXT');
      }
    }
  } catch {
    throw new LinkError('INVALID_SOURCE_CONTEXT');
  }
  return {
    repository: env.SOURCE_REPOSITORY,
    workflow: env.SOURCE_WORKFLOW,
    ref: env.SOURCE_REF,
    sha: env.SOURCE_SHA,
    runId: env.SOURCE_RUN_ID,
    runAttempt: env.SOURCE_RUN_ATTEMPT,
    targetsSha256: createHash('sha256').update(manifestBytes).digest('hex'),
    targetIds: targets.map(target => target.id),
  };
}
