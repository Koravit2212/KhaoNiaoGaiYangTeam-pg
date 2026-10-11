require('dotenv').config();
const{Client}=require('pg'),bcrypt=require('bcryptjs'),fs=require('fs');
(async()=>{
 const c=new Client({connectionString:process.env.DATABASE_URL});await c.connect();
 for(const s of fs.readFileSync('schema.sql','utf8').split(/;\s*\n/).map(x=>x.trim()).filter(Boolean))await c.query(s);
 const n=+(await c.query('SELECT COUNT(*) n FROM departments')).rows[0].n;
 if(!n){
  const pw=await bcrypt.hash('Passw0rd!',10);
  await c.query('BEGIN');
  for(const d of['ฝ่ายทรัพยากรบุคคล','ฝ่ายไอที','ฝ่ายบัญชี'])await c.query('INSERT INTO departments(department_name) VALUES($1)',[d]);
  for(const[p,s]of[['HR Officer',28000],['Manager',65000],['Developer',45000],['Accountant',32000]])await c.query('INSERT INTO positions(position_name,salary_rate) VALUES($1,$2)',[p,s]);
  const U=[['somchai.j@nexus.co.th','hr','สมชาย','จันทร์เพ็ญ',1,1],['manager@nexus.co.th','manager','วิภา','สุขสันต์',1,2],['dev@nexus.co.th','employee','นภัส','ใจดี',2,3]];
  for(const[u,r,f,l,d,p]of U){
   const a=await c.query('INSERT INTO accounts(username,password,role) VALUES($1,$2,$3) RETURNING account_id',[u,pw,r]);
   await c.query('INSERT INTO employees(account_id,department_id,position_id,first_name,last_name,email,hire_date) VALUES($1,$2,$3,$4,$5,$6,CURRENT_DATE)',[a.rows[0].account_id,d,p,f,l,u])}
  await c.query('COMMIT');console.log('Seeded. Login: somchai.j@nexus.co.th / manager@nexus.co.th / dev@nexus.co.th  password Passw0rd!')}
 console.log('Database ready');await c.end()})().catch(e=>{console.error(e);process.exit(1)});
