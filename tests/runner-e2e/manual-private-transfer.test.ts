import { afterEach, expect, it } from "vitest";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { validateSealedInventory } from "./manual-private-transfer.js";
import { sealManualResultEvidence, type ManualPrivateHandoff } from "./manual-private-handoff.js";
import { MANUAL_PRIVATE_PROTOCOL } from "./manual-private-retention.js";
const roots:string[]=[];
afterEach(async()=>{await Promise.all(roots.splice(0).map(root=>rm(root,{recursive:true,force:true})));});
async function fixture(){const root=await mkdtemp(path.join(os.tmpdir(),"manual-transfer-test-"));roots.push(root);await mkdir(path.join(root,"results"));const context={root,protocol:MANUAL_PRIVATE_PROTOCOL,private:true,workflowSha:"a".repeat(40),targetSha:"b".repeat(40),runId:"123",attempt:"1",executionIds:["chat-features.runner-opencode.local.activity.agent-feedback"]} as ManualPrivateHandoff;return{root,context};}
it("seals genuine final result bytes and rejects an unscanned staged addition before transfer",async()=>{
 const f=await fixture();await writeFile(path.join(f.root,"results","campaign.json"),'{"cleanup":"passed"}');
 await sealManualResultEvidence(f.context,[]);const dir=path.join(f.root,"sealed-results","html-report");
 expect((await validateSealedInventory(dir,"../result-evidence-inventory.json")).complete).toBe(true);
 await writeFile(path.join(dir,"staged.db"),"unscanned");await expect(validateSealedInventory(dir,"../result-evidence-inventory.json")).rejects.toThrow(/Unscanned/);
});
it("rejects modification of final cleanup/result bytes after the scan",async()=>{
 const f=await fixture();await writeFile(path.join(f.root,"results","campaign.json"),'{}');await sealManualResultEvidence(f.context,[]);
 const dir=path.join(f.root,"sealed-results","html-report");await writeFile(path.join(dir,"campaign.json"),'{"later":true}');await expect(validateSealedInventory(dir,"../result-evidence-inventory.json")).rejects.toThrow(/changed/);
});
it("an abnormal fallback cannot retain credential-bearing final data or unsupported staged bytes",async()=>{
 const f=await fixture();await writeFile(path.join(f.root,"results","result.json"),'{"originalResult":"synthetic-final-credential-123456"}');
 await expect(sealManualResultEvidence(f.context,["synthetic-final-credential-123456"])).rejects.toThrow(/contamination/);
 await writeFile(path.join(f.root,"results","result.json"),'{}');await writeFile(path.join(f.root,"results","unknown.bin"),"opaque");
 await expect(sealManualResultEvidence(f.context,[])).rejects.toThrow(/Unsupported/);
});
it("rejects a forged inventory that lists an unscannable original carrier",async()=>{
 const f=await fixture(),dir=path.join(f.root,"results");await mkdir(path.join(dir,"snapshots"));await writeFile(path.join(dir,"snapshots","unknown.bin"),"secret");
 const files=[{path:"snapshots/unknown.bin",bytes:6,sha256:createHash("sha256").update("secret").digest("hex")}];
 await writeFile(path.join(dir,"inventory.json"),JSON.stringify({protocol:MANUAL_PRIVATE_PROTOCOL,complete:true,executionId:"id",sourceBytes:6,files,inventorySha256:createHash("sha256").update(JSON.stringify(files)).digest("hex")}));
 await expect(validateSealedInventory(dir,"inventory.json","id")).rejects.toThrow(/row/);
});
