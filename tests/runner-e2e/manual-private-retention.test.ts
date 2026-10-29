import { expect, it } from "vitest";
import { authorizeManualPrivateEvidence, MANUAL_PRIVATE_EXECUTIONS, MANUAL_PRIVATE_PROTOCOL, manualCellKind, manualPrivateSessionPolicy, requiresPrivateManualEvidence } from "./manual-private-retention.js";
const workflowSha = "a".repeat(40), targetSha = "b".repeat(40);
const identity = { workflowSha, targetSha, runId: "123", attempt: "1", executionIds: [MANUAL_PRIVATE_EXECUTIONS[0]!] };
const approval = () => ({ version: 1, approvals: [{ workflowSha, targetSha, executionIds: identity.executionIds, protocol: MANUAL_PRIVATE_PROTOCOL, launchSha256: "c".repeat(64) }] });
it("requires exact protected workflow, target and selected IDs for the first supported manual scope", () => {
  expect(authorizeManualPrivateEvidence(identity, JSON.stringify(approval()))).toMatchObject({ private: true, protocol: MANUAL_PRIVATE_PROTOCOL });
});
it.each(["chat-features.runner-opencode.local.activity.agent-feedback", "chat-features.runner-codex.local.unknown", "chat-features"])("classification of %s cannot be downgraded by a target flag", id => expect(requiresPrivateManualEvidence(id)).toBe(true));
it.each(["workflow", "target", "ids", "protocol", "extra", "duplicate", "empty", "rerun"])("rejects %s approval mismatch without granting a role", kind => {
 const p = approval(); const i = { ...identity };
 if (kind === "workflow") p.approvals[0]!.workflowSha = "c".repeat(40);
 if (kind === "target") p.approvals[0]!.targetSha = "c".repeat(40);
 if (kind === "ids") p.approvals[0]!.executionIds = [MANUAL_PRIVATE_EXECUTIONS[1]!];
 if (kind === "protocol") p.approvals[0]!.protocol = "unknown";
 if (kind === "extra") Object.assign(p.approvals[0]!, { private: true });
 if (kind === "duplicate") p.approvals.push(p.approvals[0]!);
 if (kind === "empty") p.approvals = [];
 if (kind === "rerun") i.attempt = "2";
 expect(() => authorizeManualPrivateEvidence(i, JSON.stringify(p))).toThrow();
});
it("unknown and mixed manual cases cannot acquire private role authority", () => {
 expect(() => authorizeManualPrivateEvidence({ ...identity, executionIds: ["chat-features.runner-opencode.local.access.invite-teammate"] }, JSON.stringify(approval()))).toThrow();
 expect(() => authorizeManualPrivateEvidence({ ...identity, executionIds: [...identity.executionIds, "runner.native.local.other"] }, JSON.stringify(approval()))).toThrow();
});
it("different cells have distinct immutable private object identities", () => {
 expect(manualCellKind(MANUAL_PRIVATE_EXECUTIONS[0]!)).not.toBe(manualCellKind(MANUAL_PRIVATE_EXECUTIONS[1]!));
 expect(() => manualCellKind("../escape")).toThrow();
});
it("vetted paid transfer session is put-only and the trusted report reads only selected current cells", () => {
 const paid = manualPrivateSessionPolicy({ bucket: "private-evidence", runId: "123", executionIds: identity.executionIds, report: false });
 expect(paid.Statement.flatMap(s => s.Action)).not.toContain("s3:GetObject");
 const report = manualPrivateSessionPolicy({ bucket: "private-evidence", runId: "123", executionIds: identity.executionIds, report: true });
 const reads = report.Statement.find(s => s.Action.includes("s3:GetObject"))!;
 expect(reads.Resource).toEqual([`arn:aws:s3:::private-evidence/runner-e2e-private/bounded-v1/campaigns/gha-123-1/${manualCellKind(identity.executionIds[0]!)}.zip`]);
 expect(JSON.stringify(report)).not.toContain("gha-124");
});
it("the supported private archive kind is collision-free and rejects arbitrary manual paths", async () => {
 const { privateArtifactKey } = await import("./private-history.js");
 expect(privateArtifactKey(manualCellKind(identity.executionIds[0]!), "123")).toContain("/manual-cell-");
 expect(privateArtifactKey("manual-report", "123")).toMatch(/manual-report\.zip$/);
 expect(() => privateArtifactKey("manual-cell-../escape", "123")).toThrow();
});
