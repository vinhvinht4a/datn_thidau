import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true, credentials: true }));

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

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
const ADMINS = new Set((process.env.ADMIN_EMAILS||'').split(',').map(s=>s.trim().toLowerCase()));
const adminOnly = (req,res,next)=> ADMINS.has((req.user?.email||'').toLowerCase()) ? next() : res.status(403).json({error:'Admin only'});

const now = () => new Date();
const rnd = (n=32) => crypto.randomBytes(n).toString('hex'); // token

/* ---------- AUTH ---------- */
app.post('/api/auth/register', async (req,res)=>{
  const { email, password, name } = req.body || {};
  if(!email || !password || !name) return res.status(400).json({error:'Missing'});
  const hash = await bcrypt.hash(password, 10);
  const conn = await pool.getConnection();
  try{
    await conn.execute('INSERT INTO parents (email,password_hash,name) VALUES (?,?,?)',[email,hash,name]);
    const [[u]] = await conn.query('SELECT id,email,name FROM parents WHERE email=?',[email]);
    res.json({ token: sign(u), user:u });
  }catch(e){
    if(e.code==='ER_DUP_ENTRY') return res.status(409).json({error:'Email exists'});
    throw e;
  } finally{ conn.release(); }
});
app.post('/api/auth/login', async (req,res)=>{
  const { email, password } = req.body || {};
  const [[u]] = await pool.query('SELECT id,email,name,password_hash FROM parents WHERE email=?',[email]);
  if(!u) return res.status(401).json({error:'Invalid'});
  const ok = await bcrypt.compare(password, u.password_hash);
  if(!ok) return res.status(401).json({error:'Invalid'});
  res.json({ token: sign({id:u.id,email:u.email,name:u.name}), user:{id:u.id,email:u.email,name:u.name} });
});

/* ---------- KIDS ---------- */
app.get('/api/kids', auth, async (req,res)=>{
  const [rows] = await pool.query('SELECT id,name,grade,access_code FROM kids WHERE parent_id=? ORDER BY created_at DESC',[req.user.id]);
  res.json(rows);
});
app.post('/api/kids', auth, async (req,res)=>{
  const { name, grade } = req.body || {};
  if(!name) return res.status(400).json({error:'Missing name'});
  const code = Math.random().toString(36).slice(2,6).toUpperCase() + Math.random().toString(36).slice(2,4).toUpperCase();
  const [ret] = await pool.query('INSERT INTO kids (parent_id,name,grade,access_code) VALUES (?,?,?,?)',[req.user.id,name,grade||null,code]);
  res.json({ ok:true, id: ret.insertId, access_code: code });
});

/* ---------- QUESTIONS (admin) ---------- */
app.post('/api/questions', auth, adminOnly, async (req,res)=>{
  const { subject, type='mcq', text, points=1, grade_min=null, grade_max=null, choices=[] } = req.body || {};
  if(!subject || !text) return res.status(400).json({error:'Missing'});
  const conn = await pool.getConnection();
  try{
    await conn.beginTransaction();
    const [ret] = await conn.execute(
      'INSERT INTO questions (subject,grade_min,grade_max,type,text,points) VALUES (?,?,?,?,?,?)',
      [subject,grade_min,grade_max,type,text,points]
    );
    const qid = ret.insertId;
    if(type==='mcq' && choices.length){
      for(const c of choices){
        await conn.execute('INSERT INTO choices (question_id,label,is_correct) VALUES (?,?,?)',[qid,c.label, c.is_correct?1:0]);
      }
    }
    await conn.commit();
    res.json({ ok:true, id: qid });
  }catch(e){ await conn.rollback(); throw e; } finally{ conn.release(); }
});

/* ---------- COMPETITIONS (admin CRUD + list) ---------- */
app.get('/api/competitions', async (req,res)=>{
  const { active, subject } = req.query;
  const params=[]; let where='1=1';
  if(active!==undefined){ where+=' AND active=1'; }
  if(subject){ where+=' AND subject=?'; params.push(subject); }
  const [rows] = await pool.query(`SELECT * FROM competitions WHERE ${where} ORDER BY start_at DESC`, params);
  res.json(rows);
});
app.post('/api/competitions', auth, adminOnly, async (req,res)=>{
  const { title, subject, duration_seconds, start_at, end_at, max_attempts=1, active=1, shuffle_questions=true, questions_count=10, question_ids=[] } = req.body || {};
  if(!title || !subject || !duration_seconds || !start_at || !end_at) return res.status(400).json({error:'Missing'});
  const conn = await pool.getConnection();
  try{
    await conn.beginTransaction();
    const [ret] = await conn.execute(
      'INSERT INTO competitions (title,subject,duration_seconds,start_at,end_at,max_attempts,active,shuffle_questions,questions_count) VALUES (?,?,?,?,?,?,?,?,?)',
      [title,subject,duration_seconds,start_at,end_at,max_attempts,active?1:0,shuffle_questions?1:0,questions_count]
    );
    const cid = ret.insertId;
    if(question_ids.length){
      let ord=1;
      for(const qid of question_ids){
        await conn.execute('INSERT INTO comp_questions (competition_id,question_id,ord) VALUES (?,?,?)',[cid,qid,ord++]);
      }
    }
    await conn.commit();
    res.json({ ok:true, id: cid });
  }catch(e){ await conn.rollback(); throw e; } finally{ conn.release(); }
});

/* ---------- ENROLL ---------- */
app.post('/api/enroll', auth, async (req,res)=>{
  const { kid_id, competition_id } = req.body || {};
  if(!kid_id || !competition_id) return res.status(400).json({error:'Missing'});
  const [[kid]] = await pool.query('SELECT id FROM kids WHERE id=? AND parent_id=?',[kid_id, req.user.id]);
  if(!kid) return res.status(403).json({error:'Not your kid'});
  await pool.query('INSERT IGNORE INTO enrollments (competition_id,kid_id) VALUES (?,?)',[competition_id,kid_id]);
  res.json({ ok:true });
});

/* ---------- START ATTEMPT (parent triggers; returns kid token + first question) ---------- */
app.post('/api/attempts/start', auth, async (req,res)=>{
  const { kid_id, competition_id } = req.body || {};
  if(!kid_id || !competition_id) return res.status(400).json({error:'Missing'});
  // own kid?
  const [[kid]] = await pool.query('SELECT id FROM kids WHERE id=? AND parent_id=?',[kid_id, req.user.id]);
  if(!kid) return res.status(403).json({error:'Not your kid'});
  // comp window/attempts
  const [[comp]] = await pool.query('SELECT * FROM competitions WHERE id=? AND active=1',[competition_id]);
  if(!comp) return res.status(400).json({error:'Competition not active'});
  const nowDt = now();
  if(nowDt < new Date(comp.start_at) || nowDt > new Date(comp.end_at)) return res.status(400).json({error:'Out of time window'});
  const [[{cnt}]] = await pool.query('SELECT COUNT(*) AS cnt FROM attempts WHERE competition_id=? AND kid_id=?',[competition_id,kid_id]);
  const attempt_no = cnt + 1;
  if(attempt_no > comp.max_attempts) return res.status(429).json({error:'No attempts left'});

  // build question set: curated or auto-pick
  let questions;
  const [curated] = await pool.query('SELECT q.* FROM comp_questions cq JOIN questions q ON q.id=cq.question_id WHERE cq.competition_id=? ORDER BY cq.ord ASC',[competition_id]);
  if(curated.length){
    questions = curated;
  }else{
    const [poolRows] = await pool.query('SELECT * FROM questions WHERE subject=? ORDER BY RAND() LIMIT ?', [comp.subject, comp.questions_count]);
    questions = poolRows;
  }
  if(comp.shuffle_questions) questions.sort(()=>Math.random()-0.5);

  // create attempt
  const token = rnd(32);
  const ends_at = new Date(nowDt.getTime() + comp.duration_seconds*1000);
  const [ret] = await pool.query(
    'INSERT INTO attempts (competition_id,kid_id,attempt_no,ends_at,token,total_points) VALUES (?,?,?,?,?,?)',
    [competition_id,kid_id,attempt_no, ends_at, token, questions.reduce((a,q)=>a+(q.points||1),0)]
  );

  // store a row per question with NULL answer (optional; we can just insert on answer)
  // here we skip pre-insert to reduce rows

  res.json({
    ok:true, attempt_id: ret.insertId, token, ends_at,
    first: pickPublicQ(questions[0]),
    order: questions.map(q=>q.id)  // client keeps order to request next
  });
});
const pickPublicQ = (q)=>({ id:q.id, type:q.type, text:q.text, points:q.points });

/* ---------- NEXT QUESTION ---------- */
app.post('/api/attempts/next', async (req,res)=>{
  const { attempt_id, token, order, index } = req.body || {};
  if(!attempt_id || !token || !Array.isArray(order)) return res.status(400).json({error:'Missing'});
  const [[att]] = await pool.query('SELECT * FROM attempts WHERE id=? AND token=?',[attempt_id, token]);
  if(!att) return res.status(401).json({error:'Invalid attempt'});
  if(att.status !== 'ongoing') return res.status(400).json({error:'Attempt finished'});
  if(now() > new Date(att.ends_at)) return res.status(410).json({error:'Time over'});

  const qid = order[index];
  if(!qid) return res.json({ done:true });

  const [[q]] = await pool.query('SELECT * FROM questions WHERE id=?',[qid]);
  if(!q) return res.status(404).json({error:'Question not found'});

  let choices = [];
  if(q.type==='mcq'){
    const [rows] = await pool.query('SELECT id,label FROM choices WHERE question_id=? ORDER BY RAND()', [qid]); // don’t leak correctness
    choices = rows;
  }
  res.json({ ok:true, question: { id:q.id, type:q.type, text:q.text, points:q.points, choices } });
});

/* ---------- ANSWER ---------- */
app.post('/api/attempts/answer', async (req,res)=>{
  const { attempt_id, token, question_id, choice_id=null, numeric_answer=null } = req.body || {};
  if(!attempt_id || !token || !question_id) return res.status(400).json({error:'Missing'});
  const [[att]] = await pool.query('SELECT * FROM attempts WHERE id=? AND token=?',[attempt_id, token]);
  if(!att) return res.status(401).json({error:'Invalid attempt'});
  if(att.status !== 'ongoing') return res.status(400).json({error:'Attempt finished'});
  if(now() > new Date(att.ends_at)) return res.status(410).json({error:'Time over'});

  const [[q]] = await pool.query('SELECT * FROM questions WHERE id=?',[question_id]);
  if(!q) return res.status(404).json({error:'Question not found'});

  let is_correct = 0, points = 0;
  if(q.type === 'mcq'){
    const [[opt]] = await pool.query('SELECT is_correct FROM choices WHERE id=? AND question_id=?',[choice_id, question_id]);
    if(opt?.is_correct) { is_correct = 1; points = q.points; }
  } else {
    // Simple numeric compare (tweak as needed)
    const answer = Number(numeric_answer);
    const [[truth]] = await pool.query('SELECT label FROM choices WHERE question_id=? AND is_correct=1 LIMIT 1',[question_id]);
    if(truth && Number(truth.label) === answer){ is_correct=1; points=q.points; }
  }

  await pool.query(`
    INSERT INTO attempt_answers (attempt_id, question_id, choice_id, numeric_answer, is_correct, points_awarded)
    VALUES (?,?,?,?,?,?)
    ON DUPLICATE KEY UPDATE choice_id=VALUES(choice_id), numeric_answer=VALUES(numeric_answer),
      is_correct=VALUES(is_correct), points_awarded=VALUES(points_awarded)
  `,[attempt_id, question_id, choice_id, numeric_answer, is_correct, points]);

  // update running score (cheap)
  const [[{ sumPoints }]] = await pool.query('SELECT COALESCE(SUM(points_awarded),0) AS sumPoints FROM attempt_answers WHERE attempt_id=?',[attempt_id]);
  await pool.query('UPDATE attempts SET score=? WHERE id=?',[sumPoints, attempt_id]);

  res.json({ ok:true, is_correct:Boolean(is_correct), awarded: points, total: sumPoints });
});

/* ---------- FINISH ---------- */
app.post('/api/attempts/finish', async (req,res)=>{
  const { attempt_id, token } = req.body || {};
  const [[att]] = await pool.query('SELECT * FROM attempts WHERE id=? AND token=?',[attempt_id, token]);
  if(!att) return res.status(401).json({error:'Invalid attempt'});
  const status = (now() > new Date(att.ends_at)) ? 'expired' : 'submitted';
  await pool.query('UPDATE attempts SET status=?, finished_at=NOW() WHERE id=?',[status, attempt_id]);
  res.json({ ok:true, status });
});

/* ---------- LEADERBOARD ---------- */
app.get('/api/leaderboard', async (req,res)=>{
  const compId = Number(req.query.competition_id);
  const limit  = Math.min(200, Number(req.query.limit||50));
  if(!compId) return res.status(400).json({error:'competition_id required'});

  // best finished attempt per kid
  const sql = `
    SELECT a.kid_id, k.name AS kid_name, MAX(a.score) AS best_score,
           MIN(CASE WHEN a.score = (
             SELECT MAX(a2.score) FROM attempts a2 WHERE a2.kid_id=a.kid_id AND a2.competition_id=a.competition_id AND a2.status IN ('submitted','expired')
           ) THEN TIMESTAMPDIFF(SECOND, a.started_at, a.finished_at) ELSE NULL END) AS best_duration
    FROM attempts a
    JOIN kids k ON k.id=a.kid_id
    WHERE a.competition_id=? AND a.status IN ('submitted','expired')
    GROUP BY a.kid_id, k.name
    ORDER BY best_score DESC, best_duration ASC
    LIMIT ?`;
  const [rows] = await pool.query(sql, [compId, limit]);

  // attach ranks (ties share)
  let rank=0, lastS=null, lastD=null;
  rows.forEach((r,i)=>{ if(r.best_score!==lastS || r.best_duration!==lastD){ rank=i+1; lastS=r.best_score; lastD=r.best_duration; } r.rank=rank; });
  res.json(rows);
});

app.get('/api/health', (_req,res)=> res.json({ ok:true }));

/* -----------------------------------------------------------
 * OPTIONAL: a tiny /api/me to check who’s logged in
 * --------------------------------------------------------- */
app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));

/* -----------------------------------------------------------
 * ADMIN: Parents & Kids
 * --------------------------------------------------------- */
// List parents (+ kids_count), search by name/email
// BEFORE: app.get('/api/admin/parents', ...)
app.get('/api/admin/parents', auth, adminOnly, async (req, res) => {
  const q = (req.query.q ?? '').trim();
  const limit  = Math.min(200, parseInt(req.query.limit, 10)  || 50);
  const offset = Math.max(0,   parseInt(req.query.offset, 10) || 0);

  let where = '1=1';
  const params = [];
  if (q) {
    const like = `%${q}%`;
    where += ' AND (p.email LIKE ? OR p.name LIKE ?)';
    params.push(like, like);
  }

  const sql = `
    SELECT p.id, p.email, p.name, p.created_at, COUNT(k.id) AS kids_count
    FROM parents p
    LEFT JOIN kids k ON k.parent_id = p.id
    WHERE ${where}
    GROUP BY p.id, p.email, p.name, p.created_at
    ORDER BY p.created_at DESC
    LIMIT ${limit} OFFSET ${offset}
  `;

  const [rows] = await pool.query(sql, params); // use query(), not execute()
  res.json(rows);
});


// BEFORE: app.get('/api/admin/kids', ...)
app.get('/api/admin/kids', auth, adminOnly, async (req, res) => {
  const parent_id = req.query.parent_id ? Number(req.query.parent_id) : null;
  const q = (req.query.q ?? '').trim();
  const limit  = Math.min(500, parseInt(req.query.limit, 10)  || 100);
  const offset = Math.max(0,   parseInt(req.query.offset, 10) || 0);

  let where = '1=1';
  const params = [];
  if (parent_id) { where += ' AND k.parent_id = ?'; params.push(parent_id); }
  if (q) {
    const like = `%${q}%`;
    where += ' AND (k.name LIKE ? OR k.grade LIKE ? OR k.access_code LIKE ?)';
    params.push(like, like, like);
  }

  const sql = `
    SELECT k.id, k.name, k.grade, k.access_code, k.created_at,
           p.id AS parent_id, p.email AS parent_email, p.name AS parent_name
    FROM kids k
    JOIN parents p ON p.id = k.parent_id
    WHERE ${where}
    ORDER BY k.created_at DESC
    LIMIT ${limit} OFFSET ${offset}
  `;

  const [rows] = await pool.query(sql, params); // use query(), not execute()
  res.json(rows);
});


// Edit kid (name/grade)
app.patch('/api/admin/kids/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const { name = null, grade = null } = req.body || {};
  await pool.execute(
    'UPDATE kids SET name = COALESCE(?, name), grade = COALESCE(?, grade) WHERE id = ?',
    [name, grade, id]
  );
  res.json({ ok: true });
});

// Delete kid
app.delete('/api/admin/kids/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  await pool.execute('DELETE FROM kids WHERE id=?', [id]);
  res.json({ ok: true });
});

/* -----------------------------------------------------------
 * ADMIN: Questions
 * (You already have POST /api/questions to create)
 * --------------------------------------------------------- */
// List questions (with optional filters)
app.get('/api/questions', auth, adminOnly, async (req, res) => {
  const { subject = '', type = '', q = '' } = req.query;
  let where = '1=1';
  const params = [];
  if (subject) { where += ' AND subject=?'; params.push(subject); }
  if (type) { where += ' AND type=?'; params.push(type); }
  if (q) { where += ' AND text LIKE ?'; params.push(`%${q}%`); }

  const [rows] = await pool.execute(
    `SELECT id, subject, type, points, text, created_at
     FROM questions WHERE ${where}
     ORDER BY id DESC LIMIT 500`, params
  );
  res.json(rows);
});

// Get one question with choices
app.get('/api/questions/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const [[qRow]] = await pool.execute('SELECT * FROM questions WHERE id=?', [id]);
  if (!qRow) return res.status(404).json({ error: 'Not found' });
  const [choices] = await pool.execute('SELECT id, label, is_correct FROM choices WHERE question_id=? ORDER BY id ASC', [id]);
  res.json({ ...qRow, choices });
});

// Update question (text/points/subject/type)
app.patch('/api/questions/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const { text = null, points = null, subject = null, type = null } = req.body || {};
  await pool.execute(
    `UPDATE questions
     SET text = COALESCE(?, text),
         points = COALESCE(?, points),
         subject = COALESCE(?, subject),
         type = COALESCE(?, type)
     WHERE id = ?`,
    [text, points, subject, type, id]
  );
  res.json({ ok: true });
});

// Replace all MCQ choices in one shot
app.post('/api/questions/:id/choices/replace', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const { choices = [] } = req.body || {};
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute('DELETE FROM choices WHERE question_id=?', [id]);
    for (const c of choices) {
      await conn.execute(
        'INSERT INTO choices (question_id, label, is_correct) VALUES (?,?,?)',
        [id, String(c.label || ''), c.is_correct ? 1 : 0]
      );
    }
    await conn.commit();
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
  }
});

// Delete question (choices cascade)
app.delete('/api/questions/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  await pool.execute('DELETE FROM questions WHERE id=?', [id]);
  res.json({ ok: true });
});

/* -----------------------------------------------------------
 * ADMIN: Competitions
 * (You already have POST /api/competitions to create)
 * --------------------------------------------------------- */
// Update competition
app.patch('/api/competitions/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const {
    title = null, subject = null, duration_seconds = null,
    start_at = null, end_at = null, max_attempts = null,
    active = null, shuffle_questions = null, questions_count = null
  } = req.body || {};

  await pool.execute(
    `UPDATE competitions SET
      title=COALESCE(?,title),
      subject=COALESCE(?,subject),
      duration_seconds=COALESCE(?,duration_seconds),
      start_at=COALESCE(?,start_at),
      end_at=COALESCE(?,end_at),
      max_attempts=COALESCE(?,max_attempts),
      active=COALESCE(?,active),
      shuffle_questions=COALESCE(?,shuffle_questions),
      questions_count=COALESCE(?,questions_count)
     WHERE id=?`,
    [title, subject, duration_seconds, start_at, end_at, max_attempts,
     active, shuffle_questions, questions_count, id]
  );
  res.json({ ok: true });
});

// Delete competition (enrollments/entries/attempts cascade by FK)
app.delete('/api/competitions/:id', auth, adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  await pool.execute('DELETE FROM competitions WHERE id=?', [id]);
  res.json({ ok: true });
});


const port = process.env.PORT || 8080;
app.listen(port, ()=> console.log('Contest API listening on', port));
