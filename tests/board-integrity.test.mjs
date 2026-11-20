import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'ctf-board-integrity-'));
const py='D:/2026/pi-ctf/_shared/gate_db.py';
const db=path.join(tmp,'gate.sqlite');
const binary=process.platform==='win32'?'python':'python3';
function cmd(name,args=[],input){
 const r=spawnSync(binary,[py,'--db',db,name,...args],{encoding:'utf8',timeout:15000,input,env:{...process.env,PYTHONUTF8:'1',PYTHONIOENCODING:'utf-8'}});
 return {code:r.status,stdout:r.stdout,stderr:r.stderr};
}
let n=0;function ok(name,pass){assert.ok(pass,name);n++;console.log('PASS',name);}
try {
 const missing=cmd('dump');ok('dump nonexistent returns error without creating database',missing.code!==0&&!fs.existsSync(db));
 const mr=cmd('rev');ok('rev nonexistent returns error without creating database',mr.code!==0&&!fs.existsSync(db));
 for (const name of ['stages','falsified-list','stage-get','falsified-get','tooling-count']) {
   const args=name.endsWith('-get')?['1']:[];
   const result=cmd(name,args);
   ok(`${name} nonexistent does not create database`,result.code!==0&&!fs.existsSync(db));
 }
 ok('init explicitly creates database',cmd('init').code===0&&fs.existsSync(db));
 const first=JSON.parse(cmd('snapshot').stdout);ok('snapshot returns an atomic rev + board',first.rev===0&&first.board.challenge.name==='');
 const b=first.board;b.challenge.name='中文题';b.tooling=[{name:'python3'}];b.next=['run'];
 ok('valid first import with matching rev',cmd('import',['--rev','0'],JSON.stringify(b)).code===0);
 const rev1=JSON.parse(cmd('snapshot').stdout).rev;ok('revision increments on changed board',rev1===1);
 ok('identical snapshot write is no-op',cmd('import',['--rev',String(rev1)],JSON.stringify(b)).code===0&&Number(cmd('rev').stdout.trim())===rev1);
 ok('unversioned import refused',cmd('import',[],JSON.stringify(b)).code!==0);
 ok('runner falsifies hypothesis in DB',cmd('falsify',['tag-one','timeout:1s','rc=124']).code===0);
 const stale=cmd('import',['--rev','1'],JSON.stringify(b));
 ok('stale revision rejected after independent runner update',stale.code===3&&cmd('falsified-list').stdout.includes('tag-one'));
 const current=JSON.parse(cmd('snapshot').stdout);
 const erasing=cmd('import',['--rev',String(current.rev)],JSON.stringify(b));
 ok('matching rev repairs missing rows instead of failing',erasing.code===0&&cmd('falsified-list').stdout.includes('tag-one'));
 const weakening=structuredClone(current.board);
 weakening.falsified[0].condition='';
 const refused=cmd('import',['--rev',String(current.rev)],JSON.stringify(weakening));
 ok('same tag cannot erase its existing condition',refused.code!==0&&cmd('falsified-list').stdout.includes('timeout:1s'));
 const altered=structuredClone(current.board);
 altered.falsified[0].condition='different-condition';
 ok('same tag cannot rewrite its condition',cmd('import',['--rev',String(current.rev)],JSON.stringify(altered)).code!==0);
 const beforeRepeat=cmd('rev').stdout.trim();
 ok('repeat falsify cannot overwrite original condition',cmd('falsify',['tag-one','other-condition','rc=2']).code===0&&cmd('falsified-list').stdout.includes('timeout:1s'));
 ok('repeat falsify does not fake progress by bumping rev',cmd('rev').stdout.trim()===beforeRepeat);
 const merge=JSON.parse(cmd('snapshot').stdout).board;merge.next=['carry forward'];
 merge.verified=[{tag:'proof-one',fact:'observed',evidence:'probe.out'}];
 merge.flags=[{flag:'TEST{offline}',confidence:'high',basis:'probe.out'}];
 const mergeRev=cmd('rev').stdout.trim();
 ok('merge preserves runner evidence',cmd('import',['--rev',mergeRev],JSON.stringify(merge)).code===0&&cmd('falsified-list').stdout.includes('tag-one'));
 const stable=JSON.parse(cmd('snapshot').stdout), stripped=structuredClone(stable.board);
 stripped.verified=[];stripped.flags=[];
 ok('missing rows auto-restored at matching revision',
   cmd('import',['--rev',String(stable.rev)],JSON.stringify(stripped)).code===0&&
   JSON.parse(cmd('dump').stdout).flags[0].flag==='TEST{offline}');
 const edited=structuredClone(stable.board);edited.flags[0].basis='';
 ok('existing flag basis cannot be erased at matching revision',
   cmd('import',['--rev',String(stable.rev)],JSON.stringify(edited)).code!==0&&
   JSON.parse(cmd('dump').stdout).flags[0].basis==='probe.out');
 const manual=cmd('stage-set',['1','通过','fabricated']);
 ok('direct stage-set no longer exists',manual.code!==0&&cmd('stages').stdout.trim()==='');
 const noop=cmd('stage-probe',['1','5','--','true']);
 ok('stage probe rejects bare true without writing stage',noop.code!==0&&cmd('stages').stdout.trim()==='');
 const fake=cmd('stage-probe',['1','5','--','python3','-c','print(1)','dummy.py']);
 ok('stage probe rejects -c disguised with a .py argument',fake.code!==0&&cmd('stages').stdout.trim()==='');
 console.log(`${n} board-integrity checks passed`);
}finally{fs.rmSync(tmp,{recursive:true,force:true});}
