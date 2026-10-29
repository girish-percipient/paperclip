import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { authorizeManualPrivateEvidence, requiresPrivateManualEvidence } from './manual-private-retention.ts';

export function manualEvidenceRouting(env) {
  if (env.EVENT_NAME !== 'workflow_dispatch' || env.EVAL_CADENCE !== 'manual') return { retention: 'recurring', executionIds: [] };
  const ids = (env.SELECT_ID ?? '').split(',').map(id => id.trim()).filter(Boolean);
  if (!ids.length) {
    if ((env.SELECT_SUITE ?? '').split(',').includes('chat-features') || env.TARGET_SHA !== env.GITHUB_SHA)
      throw new Error('Explicit reviewed IDs required before sensitive target execution');
    return { retention: 'actions', executionIds: [] };
  }
  if (!ids.some(requiresPrivateManualEvidence)) return { retention: 'actions', executionIds: ids };
  if (env.TEST_RUNNER !== 'runs-on/fleet=paperclip-public-pr-x64/env=public-ci') throw new Error('Private manual evidence currently requires the reviewed AWS route');
  const approval = authorizeManualPrivateEvidence({ workflowSha: env.GITHUB_SHA ?? '', targetSha: env.TARGET_SHA ?? '',
    runId: env.GITHUB_RUN_ID ?? '', attempt: env.GITHUB_RUN_ATTEMPT ?? '', executionIds: ids }, env.MANUAL_PRIVATE_APPROVALS_JSON ?? '');
  return { retention: 'private', executionIds: approval.executionIds, approval };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = manualEvidenceRouting(process.env);
    appendFileSync(process.env.GITHUB_OUTPUT, `evidence_retention=${result.retention}\nmanual_private_ids=${JSON.stringify(result.executionIds)}\n`);
  } catch { process.stderr.write('Manual evidence authorization failed before paid access; details withheld\n'); process.exitCode = 1; }
}
