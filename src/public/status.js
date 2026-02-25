let csrf=''; fetch('/api/csrf').then(r=>r.json()).then(j=>csrf=j.token);
const q = new URLSearchParams(location.search); const id=q.get('id'); const token=q.get('token');
const chat=document.getElementById('chat'); const rid=document.getElementById('rid'); const status=document.getElementById('status');
rid.textContent='#'+id;
async function load(){
 const r=await fetch(`/api/requests/${id}?public_token=${token}`); const d=await r.json(); status.textContent=d.status;
 const m=await fetch(`/api/requests/${id}/messages?public_token=${token}`).then(r=>r.json());
 chat.innerHTML=''; (m.items||[]).forEach(x=>{const el=document.createElement('div');el.className='msg '+x.author_type;el.textContent=`${x.author_type}: ${x.body}`;chat.append(el)});
}
load();
document.getElementById('msgForm').addEventListener('submit',async e=>{e.preventDefault();const body=e.target.body.value;await fetch(`/api/requests/${id}/messages`,{method:'POST',headers:{'Content-Type':'application/json','x-csrf-token':csrf},body:JSON.stringify({body,public_token:token})});e.target.reset();load();});
const sse = new EventSource(`/api/sse?request_id=${id}`); sse.addEventListener('update',load);
