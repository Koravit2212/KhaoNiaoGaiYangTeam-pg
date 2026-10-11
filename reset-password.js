require('dotenv').config();
const{Client}=require('pg'),bcrypt=require('bcryptjs');
const[,,user,pass]=process.argv;
(async()=>{
  const c=new Client({connectionString:process.env.DATABASE_URL});await c.connect();
  const r=await c.query("UPDATE accounts SET password=$1,status='active' WHERE username=$2",[await bcrypt.hash(pass,10),user]);
  console.log(r.rowCount?'เปลี่ยนรหัสผ่านแล้ว':'ไม่พบผู้ใช้นี้');
  await c.end();
})().catch(e=>{console.error(e);process.exit(1)});
