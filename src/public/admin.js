let csrf=''; fetch('/api/csrf').then(r=>r.json()).then(j=>csrf=j.token);
let token=''; let currentId=0;
const table=document.getElementById('tbl'); const card=document.getElementById('card'); const chat=document.getElementById('chat');
const api=(u,o={})=>fetch(u,{...o,headers:{...(o.headers||{}),Authorization:'Bearer '+token,'x-csrf-token':csrf}});
document.getElementById('login').onsubmit=async e=>{e.preventDefault();const fd=Object.fromEntries(new FormData(e.target).entries());const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(fd)});const j=await r.json();if(r.ok){token=j.access_token;document.getElementById('loginOut').textContent='OK';loadAll();}else alert('login failed');};
async function loadAll(){
 const status=document.getElementById('fStatus').value; const r=await api('/api/requests'+(status?`?status=${status}`:'')); const d=await r.json();
 table.innerHTML='<tr><th>ID</th><th>Тема</th><th>Статус</th><th></th></tr>'+d.items.map(x=>`<tr><td>${x.id}</td><td>${x.subject}</td><td>${x.status}</td><td><button onclick="openReq(${x.id})">Открыть</button></td></tr>`).join('');
 document.getElementById('stats').textContent=JSON.stringify(await (await api('/api/stats')).json(),null,2);
 const aud=await (await api('/api/audit')).json(); document.getElementById('audit').innerHTML=aud.items.slice(0,8).map(a=>`<li>${a.timestamp}: ${a.action} #${a.target_id}</li>`).join('');
}
window.openReq=async (id)=>{currentId=id;const d=await (await api('/api/requests/'+id)).json();card.innerHTML=`<p><b>${d.subject}</b> (${d.status})</p><button onclick="setStatus('in_progress')">In progress</button><button onclick="setStatus('closed')">Closed</button>`;loadMsgs();const sse=new EventSource(`/api/sse?request_id=${id}`);sse.addEventListener('update',loadMsgs);};
window.setStatus=async (status)=>{await api('/api/requests/'+currentId,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({status})});loadAll();openReq(currentId);};
async function loadMsgs(){const m=await (await api(`/api/requests/${currentId}/messages`)).json();chat.innerHTML=(m.items||[]).map(x=>`<div class="msg ${x.author_type}">${x.author_type}: ${x.body}</div>`).join('');}
document.getElementById('reply').onsubmit=async e=>{e.preventDefault();await api(`/api/requests/${currentId}/messages`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({body:e.target.body.value})});e.target.reset();loadMsgs();};
document.getElementById('refresh').onclick=loadAll;
document.getElementById('export').onclick=()=>window.open('/api/requests/export.csv?token=1');
