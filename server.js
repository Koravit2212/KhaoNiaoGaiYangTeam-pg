require('dotenv').config();
const express=require('express'),{Pool,types}=require('pg'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken');
types.setTypeParser(20,Number);types.setTypeParser(1700,Number);types.setTypeParser(1082,v=>v);
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const app=express(),S=process.env.JWT_SECRET||'change-me',HR=['hr','admin'],DEF='Passw0rd!',fails=new Map();
app.use(express.json({limit:'1mb'}));app.use(express.static('public'));
let pool;const getPool=()=>pool||(pool=new Pool({connectionString:process.env.DATABASE_URL,max:3}).on('error',e=>console.error('pg pool:',e.message)));
const sql=(s,b={})=>{const k=[];return[s.replace(/(?<!:):(\w+)/g,(_,n)=>{let i=k.indexOf(n);if(i<0)i=k.push(n)-1;return'$'+(i+1)}),k.map(n=>b[n])]};
const run=async(s,b={})=>{const[t,v]=sql(s,b);return getPool().query(t,v)};
const P2=n=>String(n).padStart(2,'0'),ymd=d=>`${d.getFullYear()}-${P2(d.getMonth()+1)}-${P2(d.getDate())}`;
const q=async(s,b)=>(await run(s,b)).rows.map(r=>Object.fromEntries(Object.entries(r).map(([k,v])=>[k.toLowerCase(),v instanceof Date?ymd(v):v])));
const att=r=>{const{data,...o}=r;return{...o,ot_hours:+data||0}};
const h=f=>(req,res)=>f(req,res).catch(e=>{console.error(e);res.status(['23505','23503'].includes(e.code)?409:500).json({error:e.code==='23505'?'ข้อมูลนี้มีอยู่แล้ว (ชื่อ วันที่ หรืออีเมลซ้ำ)':e.code==='23503'?'ลบไม่ได้ เพราะมีพนักงานหรือคำขอใช้งานอยู่':'ระบบขัดข้อง กรุณาลองใหม่'})});
const auth=(...r)=>(req,res,next)=>{try{req.u=jwt.verify((req.headers.authorization||'').slice(7)||req.query.t,S)}catch{return res.status(401).json({error:'กรุณาเข้าสู่ระบบใหม่'})}
 if(r.length&&!r.includes(req.u.role))return res.status(403).json({error:'ไม่มีสิทธิ์เข้าถึงข้อมูลนี้'});next()};
const okMonth=m=>/^\d{4}-(0[1-9]|1[0-2])$/.test(m||''),span=m=>{const[y,mo]=m.split('-').map(Number);return[m+'-01',m+'-'+P2(new Date(y,mo,0).getDate())]};
const EMP=`SELECT e.employee_id,e.first_name,e.last_name,e.email,e.phone,e.address,e.hire_date,e.day_off,e.employment_status,e.department_id,e.position_id,d.department_name,p.position_name,e.manager_id,m.first_name||' '||m.last_name manager_name,a.role,a.status account_status FROM employees e LEFT JOIN employees m ON m.employee_id=e.manager_id LEFT JOIN accounts a ON a.account_id=e.account_id JOIN departments d ON d.department_id=e.department_id JOIN positions p ON p.position_id=e.position_id`;

const CE=i=>'EMP'+String(i).padStart(3,'0'),TYN={absent:'ขาด',leave:'ลา',late:'มาสาย',ot:'OT'};
const logAct=async(req,action,detail)=>{const u=req.u||{};if(!u.eid||!(HR.includes(u.role)||u.role==='manager'))return;
 try{await run("INSERT INTO reports(employee_id,report_type,created_date,data) VALUES(:e,'log',now() AT TIME ZONE 'Asia/Bangkok',:d)",{e:u.eid,d:JSON.stringify({action,detail})})}catch(e){console.error('log:',e.message)}};
const nameOf=async i=>((await q("SELECT first_name||' '||last_name n FROM employees WHERE employee_id=:i",{i}))[0]||{}).n||CE(i);
const posOk=async(p,d)=>{const[x]=await q('SELECT department_id FROM positions WHERE position_id=:i',{i:p});return !!x&&(!x.department_id||x.department_id===+d)};
let ready;const migrate=()=>ready||(ready=(async()=>{try{
 if(!(await run("SELECT 1 FROM information_schema.columns WHERE table_name='positions' AND column_name='department_id'")).rows.length){
  await run('ALTER TABLE positions ADD COLUMN department_id INTEGER REFERENCES departments(department_id) ON DELETE SET NULL');
  await run('UPDATE positions p SET department_id=x.d FROM (SELECT position_id,MIN(department_id) d FROM employees GROUP BY position_id HAVING COUNT(DISTINCT department_id)=1) x WHERE p.position_id=x.position_id')}
 }catch(e){console.error('migrate:',e.message);ready=null}})());
app.use('/api',(req,res,next)=>{migrate().then(()=>next(),()=>next())});

app.post('/api/login',h(async(req,res)=>{
 const{username,password}=req.body,[a]=await q('SELECT * FROM accounts WHERE username=:u',{u:username||''});
 if(!a||a.status==='inactive')return res.status(401).json({error:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง หรือบัญชียังไม่เปิดใช้งาน'});
 if(a.status==='locked')return res.status(423).json({error:'บัญชีถูกล็อก กรุณาติดต่อฝ่าย HR'});
 if(!await bcrypt.compare(password||'',a.password)){const n=(fails.get(a.account_id)||0)+1;fails.set(a.account_id,n);
  if(n>=5)await run("UPDATE accounts SET status='locked' WHERE account_id=:i",{i:a.account_id});
  return res.status(401).json({error:'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง'})}
 fails.delete(a.account_id);
 const[e]=await q('SELECT employee_id,first_name,last_name FROM employees WHERE account_id=:i',{i:a.account_id});
 const name=e?e.first_name+' '+e.last_name:a.username;
 res.json({token:jwt.sign({id:a.account_id,role:a.role,eid:e&&e.employee_id,name,un:a.username},S,{expiresIn:'8h'}),role:a.role,name})}));

app.get('/api/lookups',auth(),h(async(_,res)=>res.json({departments:await q('SELECT department_id,department_name FROM departments ORDER BY 2'),positions:await q('SELECT position_id,position_name,department_id FROM positions ORDER BY 2')})));
app.get('/api/me',auth(),h(async(req,res)=>res.json((await q(EMP+' WHERE e.employee_id=:i',{i:req.u.eid||0}))[0]||null)));
app.put('/api/me',auth(),h(async(req,res)=>{const id=req.u.eid;if(!id)return res.status(403).json({error:'ไม่พบข้อมูลพนักงานของบัญชีนี้'});
 const b=req.body||{},ph=String(b.phone||'').trim(),em=String(b.email||'').trim(),ad=String(b.address||'').trim();
 if(!/^[0-9+\- ]{9,20}$/.test(ph))return res.status(400).json({error:'กรอกเบอร์โทรศัพท์ให้ถูกต้อง (ตัวเลข 9-20 หลัก)'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)||em.length>150)return res.status(400).json({error:'กรอกอีเมลให้ถูกต้อง'});
 if(ad.length>500)return res.status(400).json({error:'ที่อยู่ยาวเกินไป (ไม่เกิน 500 ตัวอักษร)'});
 const[o]=await q('SELECT email,account_id FROM employees WHERE employee_id=:i',{i:id});if(!o)return res.sendStatus(404);
 const c=await getPool().connect(),x1=(t,p)=>{const[q1,v]=sql(t,p);return c.query(q1,v)};
 try{await c.query('BEGIN');await x1('UPDATE employees SET phone=:p,email=:e,address=:a WHERE employee_id=:i',{p:ph,e:em,a:ad||null,i:id});
  if(o.account_id&&o.email!==em)await x1('UPDATE accounts SET username=:e WHERE account_id=:a AND username=:old',{e:em,a:o.account_id,old:o.email});
  await c.query('COMMIT')}catch(x){await c.query('ROLLBACK');throw x}finally{c.release()}
 await logAct(req,'edit','แก้ไขข้อมูลส่วนตัวของตนเอง');res.json({ok:1})}));

app.get('/api/manual',auth(),h(async(req,res)=>{
 const role=HR.includes(req.u.role)?'hr':req.u.role,html=fs.readFileSync(path.join(__dirname,'docs','manual.html'),'utf8');
 res.type('html').send(html.replace(/<section data-roles="([^"]*)">([\s\S]*?)<\/section>/g,(_,r,c)=>r.split(',').includes(role)?c:''))}));
app.post('/api/change-password',auth(),h(async(req,res)=>{
 const{current_password:c,new_password:n}=req.body||{};
 if(typeof c!=='string'||typeof n!=='string'||!c||!n)return res.status(400).json({error:'กรอกข้อมูลให้ครบ'});
 if(n.length<8||Buffer.byteLength(n)>72)return res.status(400).json({error:'รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร และไม่ยาวเกินไป'});
 if(n===c)return res.status(400).json({error:'รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านเดิม'});
 const[a]=await q('SELECT account_id,password,status FROM accounts WHERE account_id=:i',{i:req.u.id});
 if(!a||a.status!=='active')return res.status(403).json({error:'บัญชีนี้ไม่สามารถใช้งานได้'});
 if(!await bcrypt.compare(c,a.password)){const k=(fails.get(a.account_id)||0)+1;fails.set(a.account_id,k);
  if(k>=5){await run("UPDATE accounts SET status='locked' WHERE account_id=:i",{i:a.account_id});return res.status(423).json({error:'ใส่รหัสผิดเกินกำหนด บัญชีถูกล็อก กรุณาติดต่อฝ่าย HR'})}
  return res.status(400).json({error:'รหัสผ่านปัจจุบันไม่ถูกต้อง'})}
 fails.delete(a.account_id);
 await run('UPDATE accounts SET password=:p WHERE account_id=:i',{p:await bcrypt.hash(n,10),i:a.account_id});res.json({ok:1})}));
app.get('/api/employees',auth(...HR),h(async(req,res)=>res.json(await q(EMP+" WHERE e.employee_id::text||e.first_name||' '||e.last_name||d.department_name||p.position_name ILIKE :s ORDER BY e.employee_id",{s:'%'+(req.query.q||'')+'%'}))));
app.post('/api/employees',auth(...HR),h(async(req,res)=>{
 const b=req.body;if(!['first_name','last_name','email','hire_date','department_id','position_id'].every(k=>b[k]))return res.status(400).json({error:'กรอกข้อมูลให้ครบทุกช่องที่จำเป็น'});
 if(!await posOk(b.position_id,b.department_id))return res.status(400).json({error:'ตำแหน่งนี้ไม่อยู่ในแผนกที่เลือก'});
 const c=await getPool().connect(),x1=(t,p)=>{const[q1,v]=sql(t,p);return c.query(q1,v)};
 try{await c.query('BEGIN');
  const a=await x1("INSERT INTO accounts(username,password,role) VALUES(:u,:p,:r) RETURNING account_id",{u:b.email,p:await bcrypt.hash(DEF,10),r:b.role||'employee'});
  const e=await x1("INSERT INTO employees(account_id,department_id,position_id,manager_id,first_name,last_name,email,phone,address,hire_date,day_off) VALUES(:a,:d,:p,:mg,:fn,:ln,:em,:ph,:ad,CAST(:hd AS date),:dof) RETURNING employee_id",
   {a:a.rows[0].account_id,d:b.department_id,p:b.position_id,mg:b.manager_id?+b.manager_id:null,fn:b.first_name,ln:b.last_name,em:b.email,ph:b.phone||null,ad:b.address||null,hd:b.hire_date,dof:b.day_off||10});
  await c.query('COMMIT');await logAct(req,'add',`เพิ่มข้อมูลพนักงานใหม่: รหัส ${CE(e.rows[0].employee_id)} (${b.first_name} ${b.last_name})`);res.json({id:e.rows[0].employee_id})}catch(x){await c.query('ROLLBACK');throw x}finally{c.release()}}));
app.put('/api/employees/:id',auth(...HR),h(async(req,res)=>{const b=req.body,id=+req.params.id,mg=b.manager_id?+b.manager_id:null;
 if(mg){if(mg===id)return res.status(400).json({error:'เลือกตัวเองเป็นหัวหน้าไม่ได้'});
  let c=mg;for(let i=0;c&&i<20;i++){const[x]=await q('SELECT manager_id FROM employees WHERE employee_id=:i',{i:c});c=x&&x.manager_id;if(c===id)return res.status(400).json({error:'เลือกไม่ได้ เพราะหัวหน้าคนนั้นเป็นลูกทีมของพนักงานคนนี้อยู่'})}}
 await run('UPDATE employees SET first_name=:fn,last_name=:ln,email=:em,phone=:ph,address=:ad,day_off=:dof,manager_id=:mg WHERE employee_id=:id',{fn:b.first_name,ln:b.last_name,em:b.email,ph:b.phone||null,ad:b.address||null,dof:b.day_off||0,mg,id});
 await logAct(req,'edit',`แก้ไขข้อมูลพนักงาน: รหัส ${CE(id)} (${b.first_name} ${b.last_name})`);res.json({ok:1})}));
app.post('/api/employees/:id/resign',auth(...HR),h(async(req,res)=>{
 const i=req.params.id,[e]=await q('SELECT employment_status,account_id FROM employees WHERE employee_id=:i',{i});
 if(!e)return res.sendStatus(404);if(e.employment_status==='resigned')return res.status(400).json({error:'สถานะนี้ถูกบันทึกไว้แล้ว'});
 if((await q("SELECT data FROM reports WHERE employee_id=:i AND report_type='change_request'",{i})).some(r=>JSON.parse(r.data).status==='pending'))return res.status(400).json({error:'พนักงานมีคำขอที่ยังรออนุมัติ กรุณาดำเนินการให้เสร็จก่อน'});
 await run("INSERT INTO resignations(employee_id,effective_date,reason) VALUES(:i,CAST(:d AS date),:r)",{i,d:req.body.effective_date,r:req.body.reason||null});
 await run("UPDATE employees SET employment_status='resigned' WHERE employee_id=:i",{i});
 await run('UPDATE employees SET manager_id=NULL WHERE manager_id=:i',{i});
 await run("UPDATE accounts SET status='inactive' WHERE account_id=:a",{a:e.account_id});
 await logAct(req,'edit',`บันทึกลาออก/พ้นสภาพ: รหัส ${CE(i)} (${await nameOf(i)})`);res.json({ok:1})}));
// HR รีเซ็ตรหัสผ่าน/ปลดล็อกบัญชีให้พนักงาน (กรณีลืมรหัสผ่านจนบัญชีถูกล็อก)
const tmpPw=()=>{const U='ABCDEFGHJKLMNPQRSTUVWXYZ',L='abcdefghijkmnopqrstuvwxyz',N='23456789',A=U+L+N,pk=s=>s[crypto.randomInt(s.length)],c=[pk(U),pk(L),pk(N),...Array.from({length:7},()=>pk(A))];
 for(let i=c.length-1;i>0;i--){const j=crypto.randomInt(i+1);[c[i],c[j]]=[c[j],c[i]]}return c.join('')};
app.post('/api/employees/:id/reset-password',auth(...HR),h(async(req,res)=>{
 const id=+req.params.id,given=req.body&&req.body.new_password,[t]=await q('SELECT e.first_name,e.last_name,e.employment_status,a.account_id,a.role,a.status FROM employees e LEFT JOIN accounts a ON a.account_id=e.account_id WHERE e.employee_id=:i',{i:id});
 if(!t)return res.status(404).json({error:'ไม่พบพนักงาน'});
 if(!t.account_id)return res.status(400).json({error:'พนักงานคนนี้ไม่มีบัญชีเข้าสู่ระบบ'});
 if(t.status==='inactive'||t.employment_status==='resigned')return res.status(400).json({error:'บัญชีของพนักงานที่ลาออก/พ้นสภาพ ไม่สามารถรีเซ็ตรหัสผ่านได้'});
 if(t.role==='admin'&&req.u.role!=='admin')return res.status(403).json({error:'ไม่มีสิทธิ์รีเซ็ตรหัสผ่านของผู้ดูแลระบบ'});
 if(given!=null&&(typeof given!=='string'||given.length<8||Buffer.byteLength(given)>72))return res.status(400).json({error:'รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร และไม่ยาวเกินไป'});
 const pw=given||tmpPw(),hash=await bcrypt.hash(pw,10),c=await getPool().connect(),x1=(s,p)=>{const[q1,v]=sql(s,p);return c.query(q1,v)};
 try{await c.query('BEGIN');
  await x1("UPDATE accounts SET password=:p,status='active' WHERE account_id=:a",{p:hash,a:t.account_id});
  await x1("INSERT INTO reports(employee_id,report_type,created_date,data) VALUES(:e,'pwd_reset',now() AT TIME ZONE 'Asia/Bangkok',:d)",{e:id,d:JSON.stringify({by:req.u.name||req.u.un||'-',locked:t.status==='locked',method:given?'manual':'random'})});
  await c.query('COMMIT')}catch(x){await c.query('ROLLBACK');throw x}finally{c.release()}
 fails.delete(t.account_id);
 await logAct(req,'edit',`รีเซ็ตรหัสผ่าน${t.status==='locked'?'และปลดล็อกบัญชี':''}: รหัส ${CE(id)} (${t.first_name} ${t.last_name})`);
 res.json(given?{ok:1}:{ok:1,temp_password:pw})}));
app.get('/api/password-resets',auth(...HR),h(async(req,res)=>res.json((await q("SELECT r.report_id reset_id,substr(r.created_date::text,1,19) reset_at,r.employee_id,e.first_name||' '||e.last_name emp,r.data FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_type='pwd_reset'"+(req.query.employee_id?' AND r.employee_id=:i':'')+" ORDER BY r.report_id DESC LIMIT 300",req.query.employee_id?{i:+req.query.employee_id||0}:{})).map(({data,...o})=>{let j={};try{j=JSON.parse(data)}catch{}return{...o,reset_by_name:j.by||'-',was_locked:!!j.locked,method:j.method||'random'}}))));
app.get('/api/resignations',auth(...HR),h(async(_,res)=>res.json(await q("SELECT r.resignation_id,e.first_name||' '||e.last_name emp,r.reason,r.request_date,r.effective_date,r.status FROM resignations r JOIN employees e ON e.employee_id=r.employee_id ORDER BY 1 DESC"))));

const reqs=async()=>{const dn=Object.fromEntries((await q('SELECT department_id,department_name FROM departments')).map(x=>[x.department_id,x.department_name])),pn=Object.fromEntries((await q('SELECT position_id,position_name FROM positions')).map(x=>[x.position_id,x.position_name]));
 return(await q("SELECT r.report_id,r.employee_id,r.created_date,r.data,e.first_name||' '||e.last_name emp FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_type='change_request' ORDER BY r.report_id DESC")).map(r=>{const j=JSON.parse(r.data);return{request_id:r.report_id,employee_id:r.employee_id,emp:r.emp,created_date:r.created_date,status:j.status,reason:j.reason,decision_reason:j.decision_reason,old_dept:dn[j.old_department_id],old_pos:pn[j.old_position_id],new_dept:dn[j.new_department_id],new_pos:pn[j.new_position_id],old_role:j.old_role,new_role:j.new_role,_j:j}})};
app.get('/api/requests',auth(...HR,'manager'),h(async(_,res)=>res.json((await reqs()).map(({_j,...r})=>r))));
app.post('/api/requests',auth(...HR),h(async(req,res)=>{const b=req.body,[e]=await q('SELECT e.department_id,e.position_id,a.role FROM employees e LEFT JOIN accounts a ON a.account_id=e.account_id WHERE e.employee_id=:i',{i:b.employee_id});
 if(!e)return res.sendStatus(404);
 const nd=+b.department_id||e.department_id,np=+b.position_id||e.position_id,nr=b.role&&b.role!==e.role?b.role:null;
 if(nr){if(!['employee','hr','manager'].includes(nr))return res.status(400).json({error:'สิทธิ์ที่เลือกไม่ถูกต้อง'});if(!e.role||e.role==='admin')return res.status(400).json({error:'ไม่สามารถเปลี่ยนสิทธิ์ของบัญชีนี้ได้'})}
 if(nd===e.department_id&&np===e.position_id&&!nr)return res.status(400).json({error:'ไม่มีการเปลี่ยนแปลง กรุณาเลือกแผนก ตำแหน่ง หรือสิทธิ์ใหม่อย่างน้อย 1 อย่าง'});
 if((nd!==e.department_id||np!==e.position_id)&&!await posOk(np,nd))return res.status(400).json({error:'ตำแหน่งที่เลือกไม่อยู่ในแผนกใหม่ กรุณาเลือกตำแหน่งที่อยู่ในแผนกนั้น'});
 await run("INSERT INTO reports(employee_id,report_type,data) VALUES(:i,'change_request',:d)",{i:b.employee_id,d:JSON.stringify({status:'pending',reason:b.reason||null,old_department_id:e.department_id,old_position_id:e.position_id,new_department_id:nd,new_position_id:np,...(nr?{old_role:e.role,new_role:nr}:{})})});
 await logAct(req,'add',`ส่งคำขอเปลี่ยนตำแหน่ง/แผนก/สิทธิ์: รหัส ${CE(b.employee_id)} (${await nameOf(b.employee_id)})`);res.json({ok:1})}));
app.post('/api/requests/:id/decide',auth('manager'),h(async(req,res)=>{
 const{approve,reason}=req.body,r=(await reqs()).find(x=>x.request_id==req.params.id&&x.status==='pending');
 if(!r)return res.status(404).json({error:'ไม่พบคำขอที่รออนุมัติ'});if(!approve&&!reason)return res.status(400).json({error:'กรุณาระบุเหตุผลที่ไม่อนุมัติ'});
  if(approve&&r.new_role){const[a]=await q('SELECT a.role FROM employees e JOIN accounts a ON a.account_id=e.account_id WHERE e.employee_id=:e',{e:r.employee_id});
   if(!a||a.role==='admin')return res.status(400).json({error:'ไม่สามารถเปลี่ยนสิทธิ์ของบัญชีนี้ได้'});
   if(a.role==='manager'&&r.new_role!=='manager'&&(await q("SELECT COUNT(*) n FROM accounts a JOIN employees e ON e.account_id=a.account_id WHERE a.role='manager' AND a.status='active' AND e.employment_status<>'resigned'"))[0].n<2)return res.status(400).json({error:'ไม่สามารถลดสิทธิ์ผู้บริหารคนสุดท้ายของระบบได้'})}
 const j={...r._j,status:approve?'approved':'rejected',decision_reason:reason||null,decided_date:new Date().toISOString().slice(0,10)};
 await run('UPDATE reports SET data=:d WHERE report_id=:i',{d:JSON.stringify(j),i:r.request_id});
 if(approve){await run('UPDATE employees SET department_id=:d,position_id=:p WHERE employee_id=:e',{d:j.new_department_id,p:j.new_position_id,e:r.employee_id});
  if(r.new_role)await run('UPDATE accounts SET role=:r WHERE account_id=(SELECT account_id FROM employees WHERE employee_id=:e)',{r:r.new_role,e:r.employee_id})}
 await logAct(req,'edit',`${approve?'อนุมัติ':'ไม่อนุมัติ'}คำขอเปลี่ยนตำแหน่ง/แผนก/สิทธิ์: ${r.emp} (${CE(r.employee_id)})`);res.json({ok:1})}));

const TYP=['absent','leave','late','ot'],ATQ="SELECT r.report_id record_id,r.created_date::date work_date,r.report_type record_type,r.data,e.first_name||' '||e.last_name emp FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_type IN ('absent','leave','late','ot')";
app.get('/api/attendance',auth(...HR),h(async(req,res)=>res.json((await q(ATQ+" AND r.created_date::date=CAST(:d AS date) ORDER BY r.report_id DESC",{d:req.query.date})).map(att))));
const DT=/^\d{4}-\d{2}-\d{2}$/,okHrs=h=>h>0&&h<=24;
app.post('/api/attendance',auth(...HR),h(async(req,res)=>{const b=req.body;if(!TYP.includes(b.record_type))return res.status(400).json({error:'ประเภทไม่ถูกต้อง'});
 if(!DT.test(b.work_date||''))return res.status(400).json({error:'เลือกวันที่ให้ถูกต้อง'});
 if(b.record_type==='ot'&&!okHrs(+b.ot_hours))return res.status(400).json({error:'จำนวนชั่วโมง OT ต้องมากกว่า 0 และไม่เกิน 24'});
 await run("INSERT INTO reports(employee_id,report_type,created_date,data) VALUES(:e,:t,CAST(:d AS timestamp),:h)",{e:b.employee_id,t:b.record_type,d:b.work_date,h:String(b.record_type==='ot'?+b.ot_hours:0)});
 await logAct(req,'add',`บันทึก${TYN[b.record_type]}: ${await nameOf(b.employee_id)} (${b.work_date}${b.record_type==='ot'?', '+(+b.ot_hours)+' ชม.':''})`);res.json({ok:1})}));
const ATONE="SELECT r.report_id,r.report_type,r.created_date::date work_date,r.data,e.first_name||' '||e.last_name emp FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_id=:i AND r.report_type IN ('absent','leave','late','ot')";
app.put('/api/attendance/:id',auth(...HR),h(async(req,res)=>{const b=req.body||{},id=+req.params.id,[r]=await q(ATONE,{i:id});
 if(!r)return res.status(404).json({error:'ไม่พบรายการ'});
 const t=b.record_type||r.report_type,d=b.work_date||r.work_date;
 if(!TYP.includes(t))return res.status(400).json({error:'ประเภทไม่ถูกต้อง'});
 if((r.report_type==='ot')!==(t==='ot'))return res.status(400).json({error:'เปลี่ยนระหว่าง OT กับ ขาด/ลา/มาสาย ไม่ได้'});
 if(!DT.test(d))return res.status(400).json({error:'เลือกวันที่ให้ถูกต้อง'});
 const hrs=t==='ot'?+(b.ot_hours??r.data):0;if(t==='ot'&&!okHrs(hrs))return res.status(400).json({error:'จำนวนชั่วโมง OT ต้องมากกว่า 0 และไม่เกิน 24'});
 await run('UPDATE reports SET report_type=:t,created_date=CAST(:d AS timestamp),data=:h WHERE report_id=:i',{t,d,h:String(hrs),i:id});
 await logAct(req,'edit',`แก้ไขรายการ${TYN[t]}: ${r.emp} (${d}${t==='ot'?', '+hrs+' ชม.':''})`);res.json({ok:1})}));
app.delete('/api/attendance/:id',auth(...HR),h(async(req,res)=>{const id=+req.params.id,[r]=await q(ATONE,{i:id});
 if(!r)return res.status(404).json({error:'ไม่พบรายการ'});
 await run('DELETE FROM reports WHERE report_id=:i',{i:id});
 await logAct(req,'delete',`ลบรายการ${TYN[r.report_type]}: ${r.emp} (${r.work_date})`);res.json({ok:1})}));
app.get('/api/my/records',auth(),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});const[s,e]=span(req.query.month);
 res.json((await q(ATQ+" AND r.employee_id=:i AND r.created_date::date BETWEEN CAST(:s AS date) AND CAST(:e AS date) ORDER BY 2",{i:req.u.eid||0,s,e})).map(att))}));

const pay=async(m,half,eid)=>{const[y,mo]=m.split('-').map(Number),last=new Date(y,mo,0).getDate(),s=`${m}-${half===1?'01':'16'}`,e=`${m}-${half===1?'15':P2(last)}`;
 const emps=await q(`SELECT e.employee_id,e.first_name||' '||e.last_name name,p.salary_rate FROM employees e JOIN positions p ON p.position_id=e.position_id WHERE e.employment_status='active'${eid?' AND e.employee_id=:eid':''} ORDER BY 1`,eid?{eid}:{});
 const recs=await q(`SELECT employee_id,report_type,data FROM reports WHERE report_type IN ('ot','absent') AND created_date::date BETWEEN CAST(:s AS date) AND CAST(:e AS date)${eid?' AND employee_id=:eid':''}`,eid?{s,e,eid}:{s,e});
 const r2=x=>Math.round(x*100)/100;
 return{period:[s,e],rows:emps.map(x=>{const mine=recs.filter(r=>r.employee_id===x.employee_id),ot=mine.filter(r=>r.report_type==='ot').reduce((a,r)=>a+(+r.data||0),0),absent=mine.filter(r=>r.report_type==='absent').length,base=x.salary_rate/2,otp=r2(ot*x.salary_rate/240*1.5),ded=r2(absent*x.salary_rate/30);return{...x,ot,absent,base,ot_pay:otp,deduct:ded,net:r2(base+otp-ded)}})}};
app.get('/api/payroll',auth(...HR),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});res.json(await pay(req.query.month,req.query.half==='2'?2:1))}));
app.get('/api/my/payroll',auth(),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});res.json(await pay(req.query.month,req.query.half==='2'?2:1,req.u.eid||0))}));

app.get('/api/calendar',auth(),h(async(req,res)=>{if(!okMonth(req.query.month))return res.status(400).json({error:'เลือกเดือนก่อน'});const[s,e]=span(req.query.month),all=HR.includes(req.u.role)||req.u.role==='manager',b={s,e};
 if(!all)b.i=req.u.eid||0;
 res.json({all,records:(await q(`SELECT r.created_date::date work_date,r.report_type record_type,r.data,e.first_name||' '||e.last_name emp FROM reports r JOIN employees e ON e.employee_id=r.employee_id WHERE r.report_type IN ('absent','leave','late','ot') AND r.created_date::date BETWEEN CAST(:s AS date) AND CAST(:e AS date)${all?'':' AND r.employee_id=:i'} ORDER BY 1`,b)).map(att)})}));

app.get('/api/report',auth(...HR,'manager'),h(async(req,res)=>{
 const W="WHERE e.employment_status='active' GROUP BY ";
 const r={byDept:await q(`SELECT d.department_name name,COUNT(*) total FROM employees e JOIN departments d ON d.department_id=e.department_id ${W}d.department_name ORDER BY 1`),
  byPos:await q(`SELECT p.position_name name,COUNT(*) total FROM employees e JOIN positions p ON p.position_id=e.position_id ${W}p.position_name ORDER BY 1`),
  today:await q("SELECT report_type name,COUNT(*) total FROM reports WHERE report_type IN ('absent','leave','late','ot') AND created_date::date=CURRENT_DATE GROUP BY report_type")};
 if(req.query.save&&req.u.eid)await run("INSERT INTO reports(employee_id,report_type,data) VALUES(:e,'headcount',:d)",{e:req.u.eid,d:JSON.stringify(r)});
 const m=okMonth(req.query.month)?req.query.month:new Date().toISOString().slice(0,7),[s,e]=span(m);
 r.month=m;
 r.monthly=await q("SELECT e.employee_id,e.first_name||' '||e.last_name AS name,d.department_name AS dept,COUNT(*) FILTER(WHERE x.report_type='absent') AS absent,COUNT(*) FILTER(WHERE x.report_type='leave') AS leave,COUNT(*) FILTER(WHERE x.report_type='late') AS late,COALESCE(SUM(CASE WHEN x.report_type='ot' THEN x.data::numeric ELSE 0 END),0) AS ot_hours FROM employees e JOIN departments d ON d.department_id=e.department_id LEFT JOIN reports x ON x.employee_id=e.employee_id AND x.report_type IN ('absent','leave','late','ot') AND x.created_date::date BETWEEN CAST(:s AS date) AND CAST(:e AS date) WHERE e.employment_status='active' GROUP BY e.employee_id,e.first_name,e.last_name,d.department_name ORDER BY e.employee_id",{s,e});
 r.daily=await q("SELECT x.created_date::date AS day,COUNT(*) FILTER(WHERE x.report_type='absent') AS absent,COUNT(*) FILTER(WHERE x.report_type='leave') AS leave,COUNT(*) FILTER(WHERE x.report_type='late') AS late,COALESCE(SUM(CASE WHEN x.report_type='ot' THEN x.data::numeric ELSE 0 END),0) AS ot_hours FROM reports x JOIN employees e ON e.employee_id=x.employee_id WHERE e.employment_status='active' AND x.report_type IN ('absent','leave','late','ot') AND x.created_date::date BETWEEN CAST(:s AS date) AND CAST(:e AS date) GROUP BY 1 ORDER BY 1",{s,e});
 r.resigned=(await q("SELECT COUNT(*) AS n FROM resignations WHERE status<>'cancelled' AND effective_date BETWEEN CAST(:s AS date) AND CAST(:e AS date)",{s,e}))[0].n;
 res.json(r)}));

app.post('/api/backup',auth(...HR),h(async(req,res)=>{const d={};
 for(const t of['departments','positions','employees','resignations'])d[t]=await q('SELECT * FROM '+t);d.reports=await q("SELECT report_id,employee_id,report_type,created_date,data FROM reports WHERE report_type<>'photo'");
 d.accounts=await q('SELECT account_id,username,role,status FROM accounts');
 await logAct(req,'other','สำรองข้อมูลระบบ');
 res.json({file:'backup-'+new Date().toISOString().replace(/[:T]/g,'-').slice(0,19)+'.json',data:d})}));

app.get('/api/org',auth(...HR),h(async(_,res)=>res.json({
 departments:await q("SELECT d.department_id,d.department_name,d.description,COUNT(e.employee_id) total FROM departments d LEFT JOIN employees e ON e.department_id=d.department_id AND e.employment_status<>'resigned' GROUP BY d.department_id,d.department_name,d.description ORDER BY 2"),
 positions:await q("SELECT p.position_id,p.position_name,p.salary_rate,p.department_id,d2.department_name dept_name,COUNT(e.employee_id) total FROM positions p LEFT JOIN departments d2 ON d2.department_id=p.department_id LEFT JOIN employees e ON e.position_id=p.position_id AND e.employment_status<>'resigned' GROUP BY p.position_id,p.position_name,p.salary_rate,p.department_id,d2.department_name ORDER BY 2")})));
for(const t of['departments','positions']){const P=t==='positions',id=P?'position_id':'department_id',nm=P?'position_name':'department_name',lb=P?'ตำแหน่ง':'แผนก',
 bad=b=>!b.name||(P&&!(b.value!==''&&b.value!=null&&+b.value>=0)),prm=b=>({n:b.name,v:P?+b.value:b.value||null,...(P?{dp:b.department_id?+b.department_id:null}:{})});
 app.post('/api/'+t,auth(...HR),h(async(req,res)=>{const b=req.body;if(bad(b))return res.status(400).json({error:'กรอกข้อมูลให้ครบและถูกต้อง'});
  await run(P?'INSERT INTO positions(position_name,salary_rate,department_id) VALUES(:n,:v,:dp)':'INSERT INTO departments(department_name,description) VALUES(:n,:v)',prm(b));
  await logAct(req,'add',`เพิ่ม${lb}: ${b.name}`);res.json({ok:1})}));
 app.put('/api/'+t+'/:id',auth(...HR),h(async(req,res)=>{const b=req.body;if(bad(b))return res.status(400).json({error:'กรอกข้อมูลให้ครบและถูกต้อง'});
  await run(P?'UPDATE positions SET position_name=:n,salary_rate=:v,department_id=:dp WHERE position_id=:i':'UPDATE departments SET department_name=:n,description=:v WHERE department_id=:i',{...prm(b),i:req.params.id});
  await logAct(req,'edit',`แก้ไข${lb}: ${b.name}`);res.json({ok:1})}));
 app.delete('/api/'+t+'/:id',auth(...HR),h(async(req,res)=>{const[o]=await q(`SELECT ${nm} n FROM ${t} WHERE ${id}=:i`,{i:req.params.id});
  await run(`DELETE FROM ${t} WHERE ${id}=:i`,{i:req.params.id});await logAct(req,'delete',`ลบ${lb}: ${o?o.n:req.params.id}`);res.json({ok:1})}))}

app.post('/api/photo/:id',auth(),h(async(req,res)=>{const id=+req.params.id,im=String(req.body.image||''),pre='data:image/jpeg;base64,';
 if(!Number.isInteger(id)||!(HR.includes(req.u.role)||req.u.eid===id))return res.status(403).json({error:'ไม่มีสิทธิ์เปลี่ยนรูปนี้'});
 if(!im.startsWith(pre)||im.length>30000)return res.status(400).json({error:'ไฟล์รูปไม่ถูกต้องหรือใหญ่เกินไป'});
 await run("DELETE FROM reports WHERE employee_id=:i AND report_type='photo'",{i:id});
 await run("INSERT INTO reports(employee_id,report_type,data) VALUES(:i,'photo',:p)",{i:id,p:im.slice(pre.length)});res.json({ok:1})}));
app.delete('/api/photo/:id',auth(),h(async(req,res)=>{const id=+req.params.id;if(!Number.isInteger(id)||!(HR.includes(req.u.role)||req.u.eid===id))return res.status(403).json({error:'ไม่มีสิทธิ์เปลี่ยนรูปนี้'});
 await run("DELETE FROM reports WHERE employee_id=:i AND report_type='photo'",{i:id});res.json({ok:1})}));
app.get('/api/photo/:id',auth(),h(async(req,res)=>{const id=+req.params.id;if(!Number.isInteger(id)||(req.u.role==='employee'&&req.u.eid!==id))return res.sendStatus(403);
 const[r]=await q("SELECT data FROM reports WHERE employee_id=:i AND report_type='photo'",{i:id});if(!r)return res.sendStatus(404);
 res.set({'Content-Type':'image/jpeg','Cache-Control':'private, max-age=86400'}).send(Buffer.from(r.data,'base64'))}));

app.get('/api/logs',auth(...HR,'manager'),h(async(req,res)=>{const all=req.u.role==='manager';
 res.json((await q(`SELECT r.report_id log_id,substr(r.created_date::text,1,19) ts,r.data,e.first_name||' '||e.last_name actor,a.role actor_role FROM reports r JOIN employees e ON e.employee_id=r.employee_id LEFT JOIN accounts a ON a.account_id=e.account_id WHERE r.report_type='log'${all?'':' AND r.employee_id=:i'} ORDER BY r.report_id DESC LIMIT 300`,all?{}:{i:req.u.eid||0})).map(({data,...o})=>{let j={};try{j=JSON.parse(data)}catch{}return{...o,action:j.action||'other',detail:j.detail||''}}))}));

if(!process.env.VERCEL)app.listen(3000,()=>console.log('http://localhost:3000'));
module.exports=app;
