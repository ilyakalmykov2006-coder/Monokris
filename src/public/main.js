let csrf=''; fetch('/api/csrf').then(r=>r.json()).then(j=>csrf=j.token);
const f = document.getElementById('requestForm'); const out = document.getElementById('out');
let captcha;
fetch('/api/captcha').then(r=>r.json()).then(c=>{captcha=c;document.getElementById('captchaQ').textContent='CAPTCHA: '+c.question;document.getElementById('captchaE').value=c.expected;});
async function fileToPayload(file){
 if(!file) return null;
 const data = await file.arrayBuffer();
 const b64 = btoa(String.fromCharCode(...new Uint8Array(data)));
 return {name:file.name,mime:file.type,size:file.size,data:b64};
}
f?.addEventListener('submit', async (e)=>{e.preventDefault();
 const fd=new FormData(f); const data=Object.fromEntries(fd.entries());
 const file=fd.get('attachment'); if(file && file.size>0) data.attachments=[await fileToPayload(file)];
 const r=await fetch('/api/requests',{method:'POST',headers:{'Content-Type':'application/json','x-csrf-token':csrf},body:JSON.stringify(data)});const j=await r.json();out.textContent=r.ok?`Готово. Ссылка: ${location.origin}${j.status_link}`:JSON.stringify(j);});
