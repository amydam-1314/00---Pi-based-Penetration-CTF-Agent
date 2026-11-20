import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { createLocalBashOperations } from '@earendil-works/pi-coding-agent';

const agent=path.resolve(import.meta.dirname,'..');
const work=fs.mkdtempSync('D:/2026/pi-ctf/chain-e2e-');
const task=path.join(work,'task');
const taskB=path.join(work,'task-b');
const root=path.join(work,'private-agent');
let count=0;
function pass(name){count++;console.log('PASS',name);}
const wsl=p=>p.replace(/^([A-Za-z]):/,(_,d)=>'/mnt/'+d.toLowerCase()).replaceAll('\\','/');
const quote=s=>`'${s.replaceAll("'","'\\''")}'`;
try {
 fs.mkdirSync(task);fs.mkdirSync(taskB);
 for(const t of [task,taskB])fs.writeFileSync(path.join(t,'.ctf-gate'),'');
 process.env.PI_CODING_AGENT_DIR=path.join(work,'private-agent');
 delete process.env.PI_CTF_GATE;delete process.env.PI_SUBAGENT_PARENT_SESSION;
 const gate=await import(pathToFileURL(path.join(agent,'ctf-gate/ctf-gate.ts')));
 const hooks=new Map();gate.default({on(n,f){hooks.set(n,f);},registerCommand(){}});
 const ctxFor=t=>({cwd:t,hasUI:false,sessionManager:{getSessionFile:()=>path.join(work,'parent.jsonl'),getSessionId:()=> 'chain-parent',getHeader:()=>({})}});
 const ctx=ctxFor(task),ctxB=ctxFor(taskB);
 const before=async c=>hooks.get('before_agent_start')({systemPrompt:'',messageType:'user',prompt:'local regression'},c);
 await hooks.get('session_start')({},ctx);await before(ctx);
 const board=JSON.parse(fs.readFileSync(path.join(agent,'ctf-gate/BOARD.template.json'),'utf8'));
 board.challenge.name='中文测试';board.tooling=[{name:'python3'}];board.next=['验证本地执行链'];
 const write=async c=>{
  const read={toolName:'read',input:{path:'gate/BOARD.json'}};
  assert.equal(await hooks.get('tool_call')(read,c),undefined);
  const current=JSON.parse(fs.readFileSync(read.input.path,'utf8'));
  current.challenge.name='中文测试';current.tooling=[{name:'python3'}];current.next=['验证本地执行链',`记录步骤 ${Date.now()}`];
  const e={toolName:'write',input:{path:'gate/BOARD.json',content:JSON.stringify(current)}};
  const r=await hooks.get('tool_call')(e,c);assert.equal(r,undefined);
  fs.writeFileSync(e.input.path,e.input.content);return e.input.path;
 };
 const cache=await write(ctx);const db=path.join(path.dirname(path.dirname(cache)),'gate.sqlite');
 function dbGet(cmd,args=[],database=db){
  const py=process.platform==='win32'?'python':'python3';
  const r=spawnSync(py,['D:/2026/pi-ctf/_shared/gate_db.py','--db',database,cmd,...args],{encoding:'utf8',timeout:15000,env:{...process.env,PYTHONUTF8:'1'}});
  assert.equal(r.status,0,r.stderr);return r.stdout;
 }
 assert.equal(JSON.parse(dbGet('dump')).challenge.name,'中文测试');pass('Windows write enters the canonical SQLite with UTF-8');
 const pathProbe={toolName:'read',input:{path:wsl(path.join(task,'data/input.txt'))}};
 await hooks.get('tool_call')(pathProbe,ctx);
 assert.equal(pathProbe.input.path,path.join(task,'data/input.txt'));pass('WSL read-tool paths normalize to the Windows task path');
 const cross={toolName:'write',input:{path:wsl(path.join(taskB,'gate/BOARD.json')),content:JSON.stringify(board)}};
 assert.equal((await hooks.get('tool_call')(cross,ctx)).block,true);pass('WSL-style cross-task BOARD writes are rejected');
 const ops=createLocalBashOperations(process.platform==='win32'?{shellPath:'C:/Windows/System32/bash.exe'}:undefined);
 async function shell(cmd,c=ctx){
  const e={toolName:'bash',input:{command:cmd}};
  const block=await hooks.get('tool_call')(e,c);assert.equal(block,undefined,block?.reason);
  let output='';const result=await ops.exec(e.input.command,work,{onData:b=>output+=b.toString(),timeout:20});
  return {...result,output,command:e.input.command};
 }
 /*
 const empty=await shell('./check.sh 1');assert.equal(empty.exitCode,1);pass('check.sh refuses missing stage');
 fs.mkdirSync(path.join(task,'data'));
 fs.writeFileSync(path.join(task,'data/verify.py'),"from pathlib import Path\nassert Path('data/artifact.txt').read_text() == 'evidence'\nprint('independent artifact assertion passed')\n");
 const fail=await shell('./stage.sh 1 5 -- python3 data/verify.py');assert.notEqual(fail.exitCode,0);
 assert.equal(dbGet('stage-get',['1']).trim(),'不通过');pass('failed actual probe writes a failed stage into the same SQLite');
 const blocked={toolName:'bash',input:{command:'./run.sh blocked 5 -- echo must-not-run'}};
 assert.equal((await hooks.get('tool_call')(blocked,ctx)).block,true);pass('failed stage blocks normal run');
 fs.writeFileSync(path.join(task,'data/artifact.txt'),'evidence');
 const ok=await shell('./stage.sh 1 5 -- python3 data/verify.py');assert.equal(ok.exitCode,0,ok.output);
 assert.equal(dbGet('stage-get',['1']).trim(),'通过');pass('stage.sh can revalidate a failed stage with real artifact assertions');
 const check=await shell('./check.sh 1');assert.equal(check.exitCode,0,check.output);pass('real check.sh and Windows DB reader agree on the stage');
 const stage2=await shell('./stage.sh 2 5 -- python3 data/verify.py');assert.equal(stage2.exitCode,0,stage2.output);
 fs.writeFileSync(path.join(task,'data/artifact.txt'),'broken');
 const redo=await shell('./stage.sh 1 5 -- python3 data/verify.py');assert.notEqual(redo.exitCode,0);
 assert.ok(!/^2\t/m.test(dbGet('stages')));pass('revalidating an earlier stage invalidates downstream success');
 fs.writeFileSync(path.join(task,'data/artifact.txt'),'evidence');await shell('./stage.sh 1 5 -- python3 data/verify.py');
 const run=await shell('./run.sh local-ok 5 -- python3 -c "print(123)"');assert.equal(run.exitCode,0,run.output);
 assert.equal(fs.readFileSync(path.join(path.dirname(cache),'evidence/local-ok.out'),'utf8').trim(),'123');pass('real run.sh writes evidence under canonical task partition');
 const timeout=await shell('./run.sh local-timeout 1 -- sleep 3');assert.equal(timeout.exitCode,124,timeout.output);
 assert.match(dbGet('falsified-list'),/local-timeout/);assert.equal(dbGet('stage-get',['1']).trim(),'通过');pass('ordinary timeout falsifies only its tag, without changing stages');
 const again=await hooks.get('tool_call')({toolName:'bash',input:{command:'./run.sh local-timeout 5 -- echo no'}},ctx);
 assert.equal(again.block,true);pass('WSL-written falsified tag is enforced by Windows hook');
 fs.writeFileSync(path.join(task,'data/slow_check.py'),'import time\ntime.sleep(3)\n');
 const probeTimeout=await shell('./stage.sh 2 1 -- python3 data/slow_check.py');assert.equal(probeTimeout.exitCode,124,probeTimeout.output);
 assert.equal(dbGet('stage-get',['2']).trim(),'不通过');pass('stage probe timeout writes stage failure');
 const skip=await shell('./stage.sh 3 5 -- python3 data/verify.py');assert.equal(skip.exitCode,2);pass('stage probe cannot skip failed predecessors');
 */
 await before(ctx);
 const staleCmd=()=>hooks.get('tool_call')({toolName:'bash',input:{command:'./stage.sh 2 5 -- python3 data/verify.py'}},ctx);
 for(let i=0;i<3;i++) assert.equal(await staleCmd(),undefined);
 const fourth=await staleCmd();assert.equal(fourth.block,true);assert.equal(fourth.terminate,undefined);
 const fifth=await staleCmd(),sixth=await staleCmd();
 assert.equal(fifth.block,true);assert.equal(fifth.terminate,undefined);
 assert.equal(sixth.block,true);assert.equal(sixth.terminate,undefined);
 pass('threshold board cadence: 3 free work commands, then soft deny only (never terminates)');
 /*
 await write(ctx);const recovered=await shell('./stage.sh 2 5 -- python3 data/verify.py');assert.equal(recovered.exitCode,0,recovered.output);pass('valid BOARD update permits recovery');
 await hooks.get('session_start')({},ctxB);await before(ctxB);const cacheB=await write(ctxB);
 const dbB=path.join(path.dirname(path.dirname(cacheB)),'gate.sqlite');
 const bRun=await shell('./run.sh local-timeout 5 -- echo task-B',ctxB);assert.equal(bRun.exitCode,0,bRun.output);
 assert.equal(dbGet('stages',[],dbB).trim(),'');assert.equal(dbGet('falsified-list',[],dbB).trim(),'');pass('task B remains isolated from task A stages and falsified tags');
 */
 console.log(`\n${count} execution-chain checks passed (SSH execution tests need live Kali); no model launches or target requests.`);
}finally{fs.rmSync(work,{recursive:true,force:true});}
