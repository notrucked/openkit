/** Scratch-only read-only inventory. No register, decisions, or publication effects. */
import {readFileSync,mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {checkImages} from './check-security.mjs';
import {observeIndex,indexPlatforms} from './release-security.mjs';
const id=process.env.IMAGE_ID;
if(!['app','worker-common','worker-runtimes'].includes(id)||process.env.GITHUB_REPOSITORY!=='notrucked/openkit'||process.env.GITHUB_REF!=='refs/heads/scratch/sec-inventory/v0.1.1-rc.1-r6')throw Error('Scratch inventory scope refused');
if(process.env.OPENKIT_SECURITY_FINDINGS)throw Error('Register input prohibited');
const record=JSON.parse(readFileSync(join('scratch-security-inputs',id+'.json'),'utf8'));
if(record.sha!=='4cc2640536632cf8621ef709b2c8d92a65fdf8f7'||record.repository!=='notrucked/openkit'||record.tag!=='v0.0.0-rc-train.20261120.6'||record.id!==id||record.provenance.runId!==44741237290||record.provenance.attempt!==1)throw Error('Exact scratch candidate required');
const startedAt=new Date().toISOString();
const manifests=indexPlatforms(observeIndex(record.image,record.digest),['linux/amd64','linux/arm64']);
for(const m of manifests)if(!record.platforms.some(p=>p.platform===m.platform&&p.digest===m.digest))throw Error('Candidate platform digest differs');
// Prefetch exact manifests outside the unchanged native scanner deadline.
for(const m of manifests){
 const before=performance.now();
 const pulled=spawnSync('docker',['pull',record.image+'@'+m.digest,'--platform',m.platform],{stdio:'ignore'});
 process.stderr.write(JSON.stringify({status:Number.isInteger(pulled.status)?pulled.status:null,signal:pulled.signal??null,errorCode:/^[A-Z0-9_]+$/u.test(pulled.error?.code??'')?pulled.error.code:null,durationMs:Math.round(performance.now()-before)})+'\n');
 if(pulled.error||pulled.status!==0)throw Error('Exact manifest prefetch failed');
}
let findings=[];
const log=console.log;console.log=()=>{};
try{
 // Keep one KEV observation across both exact platform scans.
 const found=await checkImages({images:manifests.map(m=>({platform:m.platform,image:record.image+'@'+m.digest}))});
 findings.push(...found.filter(f=>f.knownExploited||['K','C'].includes(f.class)));
}finally{console.log=log;}
const allowed=['id','artifact','component','advisoryIds','class','knownExploited','fixAvailable'];
for(const f of findings)if(Object.keys(f).some(k=>!allowed.includes(k)))throw Error('Unexpected projection field');
mkdirSync('scratch-security-inventory',{recursive:true});
writeFileSync(join('scratch-security-inventory',id+'.json.inventory.json'),JSON.stringify({schemaVersion:1,repository:record.repository,run:record.provenance,sha:record.sha,tag:record.tag,imageId:record.id,image:record.image,indexDigest:record.digest,platforms:manifests,scanner:'osv-scanner 2.7.1',startedAt,completedAt:new Date().toISOString(),findings},null,2)+'\n',{mode:0o600});
console.log('Structured inventory retained as an artifact; no finding projections printed, no release admission attempted.');
