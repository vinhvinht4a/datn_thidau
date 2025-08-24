// api/index.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import serverless from 'serverless-http';

const app = express();
app.use(express.json());

// If frontend & API are same Vercel project, you can disable CORS.
// If not, keep this:
const allowList = (process.env.CORS_ORIGIN || '').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin(origin, cb){
    if (!origin) return cb(null, true);               // same-origin / curl
    return cb(null, allowList.length ? allowList.includes(origin) : true);
  },
  credentials: true,
}));

/** —— MySQL pool: reuse across invocations —— */
let pool;
function getPool() {
  if (!pool) {
    const cfg = {
      host: process.env.DB_HOST,
      port: Number(process.env.DB_PORT || 3306),
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      waitForConnections: true,
      connectionLimit: 5,          // small for serverless
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
      ssl: process.env.DB_SSL ? { rejectUnauthorized: process.env.DB_SSL_REJECT !== 'false' } : undefined
    };
    pool = mysql.createPool(cfg);
  }
  return pool;
}

// helpers
const sign = (p) => jwt.sign(p, process.env.JWT_SECRET, { expiresIn: '7d' });
const auth = (req,res,next)=>{
  try{
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : null;
    if(!t) return res.status(401).json({error:'No token'});
    req.user = jwt.verify(t, process.env.JWT_SECRET);
    next();
  }catch{ res.status(401).json({error:'Invalid token'}); }
};
const ADMINS = new Set((process.env.ADMIN_EMAILS || '').split(',').map(s=>s.trim().toLowerCase()));
const adminOnly = (req,res,next)=> ADMINS.has((req.user?.email||'').toLowerCase()) ? next() : res.status(403).json({error:'Admin only'});
const now = () => new Date();
const rnd = (n=32) => crypto.randomBytes(n).toString('hex');

// ——— HEALTH
app.get('/api/health', (_req,res)=> res.json({ ok:true }));

/* ========= AUTH ========= */
app.post('/api/auth/register', async (req,res)=>{
  const { email, password, name } = req.body || {};
  if(!email || !password || !name) return res.status(400).json({error:'Missing'});
  const hash = await bcrypt.hash(password, 10);
  const db = getPool();
  try{
    await db.execute('INSERT INTO parents (email,password_hash,name) VALUES (?,?,?)', [email, hash, name]);
    const [[u]] = await db.query('SELECT id,email,name FROM parents WHERE email=?', [email]);
    res.json({ token: sign(u), user:u });
  }catch(e){
    if(e.code === 'ER_DUP_ENTRY') return res.status(409).json({error:'Email exists'});
    throw e;
  }
});
app.post('/api/auth/login', async (req,res)=>{
  const { email, password } = req.body || {};
  const db = getPool();
  const [[u]] = await db.query('SELECT id,email,name,password_hash FROM parents WHERE email=?', [email]);
  if(!u) return res.status(401).json({error:'Invalid'});
  const ok = await bcrypt.compare(password, u.password_hash);
  if(!ok) return res.status(401).json({error:'Invalid'});
  res.json({ token: sign({id:u.id,email:u.email,name:u.name}), user:{id:u.id,email:u.email,name:u.name} });
});
app.get('/api/me', auth, (req,res)=> res.json({ user:req.user }));

/* ========= KIDS ========= */
app.get('/api/kids', auth, async (req,res)=>{
  const db = getPool();
  const [rows] = await db.query('SELECT id,name,grade,access_code,created_at FROM kids WHERE parent_id=? ORDER BY created_at DESC',[req.user.id]);
  res.json(rows);
});
app.post('/api/kids', auth, async (req,res)=>{
  const { name, grade } = req.body || {};
  if(!name) return res.status(400).json({error:'Missing name'});
  const code = Math.random().toString(36).slice(2,6).toUpperCase() + Math.random().toString(36).slice(2,4).toUpperCase();
  const db = getPool();
  const [ret] = await db.query('INSERT INTO kids (parent_id,name,grade,access_code) VALUES (?,?,?,?)',[req.user.id,name,grade||null,code]);
  res.json({ ok:true, id: ret.insertId, access_code: code });
});

/* ========= QUESTIONS (admin) ========= */
app.post('/api/questions', auth, adminOnly, async (req,res)=>{
  const { subject, type='mcq', text, points=1, grade_min=null, grade_max=null, choices=[], correct_numeric=null, tolerance=0 } = req.body || {};
  if(!subject || !text) return res.status(400).json({error:'Missing'});
  const db = getPool();
  const conn = await db.getConnection();
  try{
    await conn.beginTransaction();
    // If you migrated to real numeric columns, use this branch; otherwise keep the MCQ path
    if (type === 'numeric' && correct_numeric != null) {
      const [ret] = await conn.execute(
        'INSERT INTO questions (subject,grade_min,grade_max,type,text,points,correct_numeric,tolerance) VALUES (?,?,?,?,?,?,?,?)',
        [subject,grade_min,grade_max,type,text,points,correct_numeric,tolerance||0]
      );
      await conn.commit();
      return res.json({ ok:true, id: ret.insertId });
    }
    const [ret] = await conn.execute(
      'INSERT INTO questions (subject,grade_min,grade_max,type,text,points) VALUES (?,?,?,?,?,?)',
      [subject,grade_min,grade_max,type,text,points]
    );
    const qid = ret.insertId;
    if(type==='mcq' || (type==='numeric' && choices.length)){
      for(const c of choices){
        await conn.execute('INSERT INTO choices (question_id,label,is_correct) VALUES (?,?,?)',[qid, String(c.label||''), c.is_correct?1:0]);
      }
    }
    await conn.commit();
    res.json({ ok:true, id: qid });
  } catch(e){ await conn.rollback(); throw e; } finally { conn.release(); }
});
app.get('/api/questions', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  const { subject = '', type = '', q = '' } = req.query;
  let where = '1=1'; const params=[];
  if (subject) { where+=' AND subject=?'; params.push(subject); }
  if (type)    { where+=' AND type=?'; params.push(type); }
  if (q)       { where+=' AND text LIKE ?'; params.push(`%${q}%`); }
  const [rows] = await db.query(`SELECT id,subject,type,points,text,created_at FROM questions WHERE ${where} ORDER BY id DESC LIMIT 500`, params);
  res.json(rows);
});
app.get('/api/questions/:id', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  const id = Number(req.params.id);
  const [[qRow]] = await db.query('SELECT * FROM questions WHERE id=?', [id]);
  if (!qRow) return res.status(404).json({ error: 'Not found' });
  const [choices] = await db.query('SELECT id,label,is_correct FROM choices WHERE question_id=? ORDER BY id ASC', [id]);
  res.json({ ...qRow, choices });
});
app.patch('/api/questions/:id', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  const id = Number(req.params.id);
  const { text=null, points=null, subject=null, type=null } = req.body || {};
  await db.execute(
    `UPDATE questions SET text=COALESCE(?,text), points=COALESCE(?,points), subject=COALESCE(?,subject), type=COALESCE(?,type) WHERE id=?`,
    [text,points,subject,type,id]
  );
  res.json({ ok:true });
});
app.post('/api/questions/:id/choices/replace', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  const id = Number(req.params.id);
  const { choices=[] } = req.body || {};
  const conn = await db.getConnection();
  try{
    await conn.beginTransaction();
    await conn.execute('DELETE FROM choices WHERE question_id=?',[id]);
    for(const c of choices){
      await conn.execute('INSERT INTO choices (question_id,label,is_correct) VALUES (?,?,?)',[id, String(c.label||''), c.is_correct?1:0]);
    }
    await conn.commit(); res.json({ ok:true });
  } catch(e){ await conn.rollback(); throw e; } finally { conn.release(); }
});
app.delete('/api/questions/:id', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  await db.execute('DELETE FROM questions WHERE id=?', [Number(req.params.id)]);
  res.json({ ok:true });
});

/* ========= COMPETITIONS ========= */
app.get('/api/competitions', async (req,res)=>{
  const db = getPool();
  const { active, subject } = req.query;
  const params=[]; let where='1=1';
  if(active!==undefined){ where+=' AND active=1'; }
  if(subject){ where+=' AND subject=?'; params.push(subject); }
  const [rows] = await db.query(`SELECT * FROM competitions WHERE ${where} ORDER BY start_at DESC`, params);
  res.json(rows);
});
app.post('/api/competitions', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  const { title, subject, duration_seconds, start_at, end_at, max_attempts=1, active=1, shuffle_questions=true, questions_count=10, question_ids=[] } = req.body || {};
  if(!title || !subject || !duration_seconds || !start_at || !end_at) return res.status(400).json({error:'Missing'});
  const conn = await db.getConnection();
  try{
    await conn.beginTransaction();
    const [ret] = await conn.execute(
      'INSERT INTO competitions (title,subject,duration_seconds,start_at,end_at,max_attempts,active,shuffle_questions,questions_count) VALUES (?,?,?,?,?,?,?,?,?)',
      [title,subject,duration_seconds,start_at,end_at,max_attempts,active?1:0,shuffle_questions?1:0,questions_count]
    );
    const cid = ret.insertId;
    if(question_ids.length){
      let ord=1; for(const qid of question_ids){
        await conn.execute('INSERT INTO comp_questions (competition_id,question_id,ord) VALUES (?,?,?)',[cid,qid,ord++]);
      }
    }
    await conn.commit(); res.json({ ok:true, id: cid });
  } catch(e){ await conn.rollback(); throw e; } finally { conn.release(); }
});
app.patch('/api/competitions/:id', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  const id = Number(req.params.id);
  const { title=null, subject=null, duration_seconds=null, start_at=null, end_at=null, max_attempts=null, active=null, shuffle_questions=null, questions_count=null } = req.body || {};
  await db.execute(
    `UPDATE competitions SET
      title=COALESCE(?,title), subject=COALESCE(?,subject), duration_seconds=COALESCE(?,duration_seconds),
      start_at=COALESCE(?,start_at), end_at=COALESCE(?,end_at), max_attempts=COALESCE(?,max_attempts),
      active=COALESCE(?,active), shuffle_questions=COALESCE(?,shuffle_questions), questions_count=COALESCE(?,questions_count)
     WHERE id=?`,
    [title,subject,duration_seconds,start_at,end_at,max_attempts,active,shuffle_questions,questions_count,id]
  );
  res.json({ ok:true });
});
app.delete('/api/competitions/:id', auth, adminOnly, async (req,res)=>{
  const db = getPool();
  await db.execute('DELETE FROM competitions WHERE id=?', [Number(req.params.id)]);
  res.json({ ok:true });
});

/* ========= ENROLL / ATTEMPTS / ANSWERS / LB ========= */
// (keep your existing endpoints; unchanged logic, but use getPool() for db access)
// — For brevity here, reuse the same code you already have from server.js —

/* export handler for Vercel */
export default serverless(app);
