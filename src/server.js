import http from 'http';
import { readFile, writeFile, mkdir, stat } from 'fs/promises';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const DATA_FILE = path.join(ROOT, 'src', 'data', 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
await mkdir(path.dirname(DATA_FILE), { recursive: true });
await mkdir(UPLOAD_DIR, { recursive: true });

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const PORT = Number(process.env.PORT || 3000);

const ensureDb = async () => {
  try { await stat(DATA_FILE); } catch {
    const adminHash = hashPassword('admin123');
    await writeFile(DATA_FILE, JSON.stringify({
      requests: [], messages: [], users: [{ id: 1, name: 'Admin', email: 'admin@local', password_hash: adminHash, role: 'admin' }],
      audit_logs: [], refresh_tokens: [], consents: []
    }, null, 2));
  }
};
await ensureDb();

const loadDb = async () => JSON.parse(await readFile(DATA_FILE, 'utf-8'));
const saveDb = async (db) => writeFile(DATA_FILE, JSON.stringify(db, null, 2));

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, packed) {
  const [salt, hash] = packed.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}
const signJwt = (payload, ttl = 3600) => {
  const head = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000)+ttl })).toString('base64url');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${sig}`;
};
const verifyJwt = (token) => {
  const [h,b,s] = token.split('.');
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${b}`).digest('base64url');
  if (sig !== s) throw new Error('Bad signature');
  const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
  if (payload.exp < Math.floor(Date.now()/1000)) throw new Error('Expired');
  return payload;
};

const clients = new Map();

function saveAttachments(arr){
  if(!Array.isArray(arr)) return [];
  const allow = new Set(['application/pdf','image/jpeg','image/png']);
  const links=[];
  for (const f of arr){
    if(!allow.has(f.mime)) throw new Error('attachment type invalid');
    if(Number(f.size||0) > 5*1024*1024) throw new Error('attachment too large');
    const ext = f.mime==='application/pdf' ? '.pdf' : (f.mime==='image/png'?'.png':'.jpg');
    const fname = `${Date.now()}_${crypto.randomUUID()}${ext}`;
    fs.writeFileSync(path.join(UPLOAD_DIR,fname), Buffer.from(f.data,'base64'));
    links.push(`/uploads/${fname}`);
  }
  return links;
}
function json(res, code, payload) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(payload)); }
function parseCookies(req){ const c = {}; (req.headers.cookie||'').split(';').forEach(v=>{ const [k,...r]=v.trim().split('='); if(k)c[k]=decodeURIComponent(r.join('='));}); return c; }

function issueCsrf(res){
  const token = crypto.randomBytes(16).toString('hex');
  res.setHeader('Set-Cookie', `csrf_token=${token}; HttpOnly; SameSite=Lax`);
  return token;
}
function checkCsrf(req){
  const cookies = parseCookies(req);
  return cookies.csrf_token && req.headers['x-csrf-token'] && cookies.csrf_token===req.headers['x-csrf-token'];
}
async function readBody(req){ let raw=''; for await (const c of req) raw += c; return raw; }
function authUser(req){
  const token = (req.headers.authorization||'').replace('Bearer ','');
  if (!token) return null;
  try { return verifyJwt(token); } catch { return null; }
}

async function sendEmail(to, subject, text){
  const line = `[${new Date().toISOString()}] TO:${to} | ${subject} | ${text}
`;
  await fs.promises.appendFile(path.join(ROOT,'src','data','mail.log'), line);
}

async function audit(userId, action, target_type, target_id, meta={}) {
  const db = await loadDb();
  db.audit_logs.push({ id: db.audit_logs.length+1, user_id: userId||null, action, target_type, target_id, timestamp: new Date().toISOString(), meta });
  await saveDb(db);
}

function validateRequest(input){
  const errs=[];
  ['requester_name','email','phone','subject','body'].forEach(f=>{ if(!input[f]||input[f].length<2) errs.push(`${f} invalid`); });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(input.email||'')) errs.push('email format');
  if (!input.consent) errs.push('consent required');
  if (!input.captcha_answer || Number(input.captcha_answer) !== Number(input.captcha_expected)) errs.push('captcha invalid');
  return errs;
}

async function serveStatic(req,res){
  const p = req.url === '/' ? '/index.html' : req.url;
  const safe = path.normalize(p).replace(/^\.\./,'');
  const file = path.join(PUBLIC_DIR, safe);
  if (!file.startsWith(PUBLIC_DIR)) return false;
  try {
    const ext = path.extname(file);
    const map = { '.html':'text/html', '.css':'text/css', '.js':'text/javascript' };
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': map[ext]||'application/octet-stream' });
    res.end(data); return true;
  } catch { return false; }
}

const server = http.createServer(async (req,res)=>{
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;

  if (method==='GET' && url.pathname==='/api/health') return json(res,200,{ok:true});

  if (method==='GET' && url.pathname==='/api/csrf') { const token = issueCsrf(res); return json(res,200,{token}); }

  if (method==='GET' && url.pathname==='/api/captcha') {
    const a = Math.floor(Math.random()*9)+1; const b = Math.floor(Math.random()*9)+1;
    return json(res,200,{question:`${a}+${b}=?`, expected:a+b});
  }

  if (method==='POST' && url.pathname==='/api/auth/login') {
    const body = JSON.parse(await readBody(req)||'{}');
    const db = await loadDb();
    const user = db.users.find(u=>u.email===body.email);
    if(!user || !verifyPassword(body.password||'', user.password_hash)) return json(res,401,{error:'Invalid credentials'});
    const access = signJwt({sub:user.id,role:user.role,name:user.name}, 3600);
    const refresh = crypto.randomUUID(); db.refresh_tokens.push({token:refresh,user_id:user.id,exp:Date.now()+1000*60*60*24*7}); await saveDb(db);
    await audit(user.id,'login','user',user.id,{});
    return json(res,200,{access_token:access,refresh_token:refresh,user:{id:user.id,name:user.name,role:user.role}});
  }

  if (method==='POST' && url.pathname==='/api/requests') {
    if (!checkCsrf(req)) return json(res,403,{error:'CSRF validation failed'});
    const contentType = req.headers['content-type']||'';
    let body={};
    if (contentType.includes('application/json')) body = JSON.parse(await readBody(req)||'{}');
    else if (contentType.includes('application/x-www-form-urlencoded')) body = Object.fromEntries(new URLSearchParams(await readBody(req)));
    else return json(res,415,{error:'Use JSON or urlencoded'});
    const errs = validateRequest(body); if (errs.length) return json(res,400,{errors:errs});
    const db = await loadDb();
    const id = db.requests.length+1;
    const token = crypto.randomBytes(16).toString('hex');
    let at=[]; try{ at=saveAttachments(body.attachments);}catch(e){ return json(res,400,{error:e.message}); }
    const request = { id, requester_name:body.requester_name, email:body.email, phone:body.phone, subject:body.subject, body:body.body, attachments:at, status:'new', priority:body.priority||'normal', assigned_to:null, created_at:new Date().toISOString(), updated_at:new Date().toISOString(), public_token:token };
    db.requests.push(request);
    db.consents.push({id:db.consents.length+1,request_id:id,accepted_at:new Date().toISOString(),ip:req.socket.remoteAddress||''});
    db.messages.push({ id: db.messages.length+1, request_id:id, author_id:null, author_type:'user', body: body.body, attachments:[], created_at:new Date().toISOString(), read_flag:false });
    await saveDb(db); await audit(null,'request_created','request',id,{email:body.email});
    await sendEmail(body.email,'Заявка создана',`Ваша заявка #${id} принята. Ссылка: /status.html?id=${id}&token=${token}`);
    broadcast(id,{type:'new_request',request});
    return json(res,201,{id,public_token:token,status:'new',status_link:`/status.html?id=${id}&token=${token}`});
  }

  if (method==='GET' && url.pathname.match(/^\/api\/requests\/\d+$/)) {
    const id = Number(url.pathname.split('/').pop()); const token = url.searchParams.get('public_token'); const user = authUser(req);
    const db = await loadDb(); const reqItem = db.requests.find(r=>r.id===id); if(!reqItem) return json(res,404,{error:'Not found'});
    if (!user && token!==reqItem.public_token) return json(res,403,{error:'Forbidden'});
    if (user && !['admin','manager','operator'].includes(user.role)) return json(res,403,{error:'Forbidden'});
    return json(res,200,reqItem);
  }

  if (method==='GET' && url.pathname==='/api/requests') {
    const user = authUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    const db = await loadDb(); let rows=[...db.requests];
    const {status,assigned_to,date_from,date_to}=Object.fromEntries(url.searchParams.entries());
    if(status) rows=rows.filter(r=>r.status===status); if(assigned_to) rows=rows.filter(r=>String(r.assigned_to)===assigned_to);
    if(date_from) rows=rows.filter(r=>r.created_at>=date_from); if(date_to) rows=rows.filter(r=>r.created_at<=date_to);
    return json(res,200,{items:rows,total:rows.length});
  }

  if (method==='PATCH' && url.pathname.match(/^\/api\/requests\/\d+$/)) {
    if (!checkCsrf(req)) return json(res,403,{error:'CSRF validation failed'});
    const user = authUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    const id = Number(url.pathname.split('/').pop());
    const data = JSON.parse(await readBody(req)||'{}');
    const db = await loadDb(); const row = db.requests.find(r=>r.id===id); if(!row) return json(res,404,{error:'Not found'});
    if(data.status) row.status=data.status; if('assigned_to' in data) row.assigned_to=data.assigned_to; if(data.priority) row.priority=data.priority; row.updated_at=new Date().toISOString();
    await saveDb(db); await audit(user.sub,'request_updated','request',id,data); broadcast(id,{type:'request_updated',request:row});
    return json(res,200,row);
  }

  if (method==='POST' && url.pathname.match(/^\/api\/requests\/\d+\/messages$/)) {
    if (!checkCsrf(req)) return json(res,403,{error:'CSRF validation failed'});
    const id = Number(url.pathname.split('/')[3]);
    const user = authUser(req);
    const body = JSON.parse(await readBody(req)||'{}');
    const db = await loadDb(); const reqItem = db.requests.find(r=>r.id===id); if(!reqItem) return json(res,404,{error:'Not found'});
    if (!user && body.public_token!==reqItem.public_token) return json(res,403,{error:'Forbidden'});
    let at=[]; try{ at=saveAttachments(body.attachments);}catch(e){ return json(res,400,{error:e.message}); }
    const msg={id:db.messages.length+1,request_id:id,author_id:user?.sub||null,author_type:user?'staff':'user',body:body.body||'',attachments:at,created_at:new Date().toISOString(),read_flag:false};
    db.messages.push(msg); reqItem.updated_at = new Date().toISOString();
    await saveDb(db); await audit(user?.sub||null,'message_added','request',id,{message_id:msg.id});
    if (user) await sendEmail(reqItem.email,'Новый ответ по заявке',`По заявке #${id} добавлен ответ сотрудника.`);
    if (reqItem.assigned_to && !user) { const op = db.users.find(u=>u.id===reqItem.assigned_to); if(op) await sendEmail(op.email,'Новое сообщение от заявителя',`Заявка #${id}`); }
    broadcast(id,{type:'new_message',message:msg});
    return json(res,201,msg);
  }

  if (method==='GET' && url.pathname.match(/^\/api\/requests\/\d+\/messages$/)) {
    const id = Number(url.pathname.split('/')[3]); const user = authUser(req); const token = url.searchParams.get('public_token');
    const db = await loadDb(); const reqItem = db.requests.find(r=>r.id===id); if(!reqItem) return json(res,404,{error:'Not found'});
    if (!user && token!==reqItem.public_token) return json(res,403,{error:'Forbidden'});
    return json(res,200,{items:db.messages.filter(m=>m.request_id===id)});
  }

  if (method==='GET' && url.pathname==='/api/audit') {
    const user = authUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    const db = await loadDb(); return json(res,200,{items:db.audit_logs.slice(-200).reverse()});
  }

  if (method==='GET' && url.pathname==='/api/stats') {
    const user = authUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    const db = await loadDb();
    const byStatus = db.requests.reduce((a,r)=>((a[r.status]=(a[r.status]||0)+1),a),{});
    const closed = db.requests.filter(r=>r.status==='closed');
    const avgCloseHours = closed.length ? closed.reduce((s,r)=>s+((new Date(r.updated_at)-new Date(r.created_at))/36e5),0)/closed.length : 0;
    return json(res,200,{byStatus,avgCloseHours:Number(avgCloseHours.toFixed(2))});
  }

  if (method==='GET' && url.pathname==='/api/requests/export.csv') {
    const user = authUser(req); if(!user) return json(res,401,{error:'Unauthorized'});
    const db = await loadDb();
    const csv = ['id,subject,status,priority,assigned_to,created_at'];
    db.requests.forEach(r=>csv.push(`${r.id},"${r.subject.replaceAll('"','""')}",${r.status},${r.priority},${r.assigned_to||''},${r.created_at}`));
    res.writeHead(200,{'Content-Type':'text/csv','Content-Disposition':'attachment; filename="requests.csv"'}); return res.end(csv.join('\n'));
  }

  if (method==='GET' && url.pathname==='/api/sse') {
    const requestId = Number(url.searchParams.get('request_id'));
    res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive'});
    if(!clients.has(requestId)) clients.set(requestId,new Set());
    clients.get(requestId).add(res);
    res.write('event: ping\ndata: connected\n\n');
    req.on('close',()=>{ clients.get(requestId)?.delete(res); });
    return;
  }

  if (url.pathname.startsWith('/uploads/')) {
    const file = path.join(UPLOAD_DIR,path.basename(url.pathname));
    if (fs.existsSync(file)) { res.writeHead(200); return fs.createReadStream(file).pipe(res); }
  }
  if (await serveStatic(req,res)) return;
  json(res,404,{error:'Not found'});
});

function broadcast(requestId, data){
  const set = clients.get(requestId); if(!set) return;
  for (const res of set) res.write(`event: update\ndata: ${JSON.stringify(data)}\n\n`);
}

if (process.env.NODE_ENV !== 'test') server.listen(PORT, ()=>console.log(`Server on ${PORT}`));
export default server;
