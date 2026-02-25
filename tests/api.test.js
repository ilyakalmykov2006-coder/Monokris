import test from 'node:test';
import assert from 'node:assert/strict';
import server from '../src/server.js';

const base = 'http://127.0.0.1:3000';
let publicToken = ''; let reqId = 0; let access='';

test.after(async ()=>{ await new Promise(r=>server.close(r)); });

async function csrfHeaders(){
  const r = await fetch(base+'/api/csrf');
  const j = await r.json();
  const cookie = r.headers.get('set-cookie').split(';')[0];
  return { token: j.token, cookie };
}

test('create request', async ()=>{
  const c = await fetch(base+'/api/captcha').then(r=>r.json());
  const csrf = await csrfHeaders();
  const res = await fetch(base+'/api/requests',{method:'POST',headers:{'Content-Type':'application/json','x-csrf-token':csrf.token,'Cookie':csrf.cookie},body:JSON.stringify({requester_name:'Иван Иванов',email:'ivan@mail.ru',phone:'+7000000000',subject:'Тест',body:'Описание проблемы',consent:'1',captcha_answer:c.expected,captcha_expected:c.expected})});
  assert.equal(res.status,201); const j=await res.json(); reqId=j.id; publicToken=j.public_token; assert.ok(publicToken);
});

test('authorization and status update', async ()=>{
  const login = await fetch(base+'/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'admin@local',password:'admin123'})});
  assert.equal(login.status,200); access=(await login.json()).access_token;
  const csrf = await csrfHeaders();
  const patch = await fetch(base+`/api/requests/${reqId}`,{method:'PATCH',headers:{'Content-Type':'application/json','Authorization':'Bearer '+access,'x-csrf-token':csrf.token,'Cookie':csrf.cookie},body:JSON.stringify({status:'in_progress'})});
  assert.equal(patch.status,200);
});

test('message add and read', async ()=>{
  const csrf = await csrfHeaders();
  const add = await fetch(base+`/api/requests/${reqId}/messages`,{method:'POST',headers:{'Content-Type':'application/json','x-csrf-token':csrf.token,'Cookie':csrf.cookie},body:JSON.stringify({body:'Уточните модель',public_token:publicToken})});
  assert.equal(add.status,201);
  const list = await fetch(base+`/api/requests/${reqId}/messages?public_token=${publicToken}`);
  const data = await list.json(); assert.ok(data.items.length >= 2);
});
