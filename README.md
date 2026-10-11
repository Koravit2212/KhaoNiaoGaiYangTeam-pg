<<<<<<< HEAD
# Employee Management System (PostgreSQL + Node.js)

1. ติดตั้ง Node.js 18+ และ PostgreSQL 14+ จากนั้นสร้าง user กับ database:
   ```sql
   CREATE USER ems WITH PASSWORD 'your_password';
   CREATE DATABASE ems OWNER ems;
   ```
2. `npm install` แล้วคัดลอก `.env.example` เป็น `.env` และแก้ `DATABASE_URL` ให้ตรงกับเครื่อง
   (ถ้าใช้ Postgres บนคลาวด์ เช่น Neon / Supabase ให้ใช้ connection string ที่มี `?sslmode=require`)
3. `npm run setup` (สร้างตารางจาก schema.sql + ข้อมูลตัวอย่าง) แล้ว `npm start` เปิด http://localhost:3000

บัญชีตัวอย่าง (รหัสผ่าน Passw0rd!): somchai.j@nexus.co.th (HR), manager@nexus.co.th (ผู้บริหาร), dev@nexus.co.th (พนักงาน)

รีเซ็ตรหัสผ่าน: `node reset-password.js <username> <รหัสใหม่>`
