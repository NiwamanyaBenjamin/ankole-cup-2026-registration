const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const bcrypt = require('bcryptjs');
const PDFDocument = require('pdfkit');
const QRCode = require('qrcode');
const path = require('path');
const fs = require('fs');

const app = express();
function strongPassword(p){ return typeof p === 'string' && p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p); }
function validUsername(u){ return /^[a-zA-Z0-9_.-]{4,30}$/.test(String(u||'')); }
const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'ankole_cup.db');
const uploadDir = path.join(__dirname, 'public/uploads');
const backupDir = path.join(__dirname, 'backups');
fs.mkdirSync(uploadDir, { recursive: true });
fs.mkdirSync(backupDir, { recursive: true });

const DISTRICTS = ['Buhweju','Bushenyi','Ibanda','Isingiro','Kashari','Kiruhura','Mbarara','Mbarara City','Mitooma','Ntungamo','Rubirizi','Rwampara','Sheema'];
const HOME_AREAS = {
  'Mbarara City':['Kakoba','Kamukuzi','Nyamitanga','Biharwe','Kakiika','Ruharo','Kisenyi','Ruti'],
  'Mbarara':['Bubaare','Bukiro','Kagongi','Kashare','Rubaya','Rwanyamahembe','Bwizibwera'],
  'Kashari':['Kashare','Rubaya','Bubaare','Rwanyamahembe','Bwizibwera','Kagongi','Bukiro'],
  'Rwampara':['Bugamba','Mwizi','Ndeija','Nyakayojo','Kinoni','Rugando'],
  'Ntungamo':['Rubaare','Rukoni','Itojo','Ruhaama','Rwashamaire','Kayonza','Nyakyera','Kitwe'],
  'Bushenyi':['Ishaka','Nyakabirizi','Kizinda','Kyeizooba','Bumbaire','Kyabugimbi'],
  'Sheema':['Kabwohe','Itendero','Kagango','Kigarama','Kitagata','Kyangyenyi'],
  'Ibanda':['Ibanda Municipality','Ishongororo','Kicuzi','Keihangara','Rukiri','Nyabuhikye'],
  'Isingiro':['Kabingo','Kikagate','Masha','Rugaaga','Ruborogota','Kabuyanda'],
  'Kiruhura':['Sanga','Kazo','Buremba','Kinoni','Kikatsi','Rwemikoma'],
  'Mitooma':['Kashenshero','Kiyanga','Mayanga','Mutara','Rurehe','Bitereko'],
  'Rubirizi':['Katerera','Katunguru','Rutoto','Magambo','Ryeru','Ndekye'],
  'Buhweju':['Nsiika','Bihanga','Karungu','Nyakishana','Bitsya','Rwengwe']
};
const STATUSES = ['Pending','Under Review','Verified','Approved','Rejected','Suspended'];

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static(uploadDir));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'change_this_ankole_cup_2026_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 8 }
}));

const db = new sqlite3.Database(DB_PATH);
function addColumn(table, colDef){ const name = colDef.split(/\s+/)[0]; db.all(`PRAGMA table_info(${table})`, [], (_, cols)=>{ if (!cols.some(c=>c.name===name)) db.run(`ALTER TABLE ${table} ADD COLUMN ${colDef}`); }); }
function audit(req, action, playerId, details='') { db.run('INSERT INTO audit_logs(user_id, action, player_id, details) VALUES(?,?,?,?)', [req.session.userId || null, action, playerId || null, details]); }

db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'district_officer', district TEXT, full_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS players (
    id INTEGER PRIMARY KEY AUTOINCREMENT, registration_no TEXT UNIQUE, player_code TEXT UNIQUE,
    player_name TEXT NOT NULL, dob TEXT, district TEXT NOT NULL, player_type TEXT NOT NULL, club TEXT NOT NULL,
    home_area TEXT NOT NULL, eligibility TEXT, nin TEXT UNIQUE NOT NULL, previous_clubs TEXT, phone TEXT,
    photo TEXT NOT NULL, national_id_photo TEXT, national_id_front_photo TEXT NOT NULL, national_id_back_photo TEXT NOT NULL,
    player_signature TEXT NOT NULL, official_name TEXT, official_signature TEXT,
    status TEXT DEFAULT 'Pending', review_notes TEXT, reviewed_by INTEGER, reviewed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT NOT NULL, player_id INTEGER, details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
  addColumn('players','player_code TEXT UNIQUE'); addColumn('players','dob TEXT'); addColumn('players','review_notes TEXT');
  addColumn('players','reviewed_by INTEGER'); addColumn('players','reviewed_at DATETIME');
  db.run('CREATE INDEX IF NOT EXISTS idx_players_district ON players(district)');
  db.run('CREATE INDEX IF NOT EXISTS idx_players_status ON players(status)');
  db.run('CREATE INDEX IF NOT EXISTS idx_players_created ON players(created_at)');
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_player ON audit_logs(player_id)');
  db.get('SELECT id FROM users WHERE role="admin" LIMIT 1', [], (err, row) => {
    if (!row) db.run('INSERT INTO users(username,password_hash,role,full_name) VALUES(?,?,?,?)', ['admin', bcrypt.hashSync('1234', 10), 'admin', 'System Administrator']);
  });
  db.run('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)', ['registration_deadline','']);
});

function currentUser(req){ return { id:req.session.userId, username:req.session.username, role:req.session.role, district:req.session.district, full_name:req.session.fullName }; }
function requireLogin(req,res,next){ if(req.session.userId) return next(); res.redirect('/admin-login.html'); }
function requireAdmin(req,res,next){ if(req.session.role==='admin') return next(); res.status(403).send('Only the main admin can perform this action.'); }
function canAccessPlayer(req, player){ return req.session.role === 'admin' || (player && player.district === req.session.district); }
function isValidNIN(nin){ return /^[A-Z]{2}[A-Z0-9]{12}$/.test(String(nin||'').trim().toUpperCase()); }
function safeFileName(name){ return Date.now() + '_' + name.replace(/[^a-zA-Z0-9.\-_]/g,'_'); }
function isPastDeadline(deadline){ if(!deadline) return false; const end = new Date(deadline + 'T23:59:59'); return !isNaN(end) && new Date() > end; }
const upload = multer({
  storage: multer.diskStorage({ destination:(req,file,cb)=>cb(null,uploadDir), filename:(req,file,cb)=>cb(null,safeFileName(file.originalname)) }),
  limits:{ fileSize: 6 * 1024 * 1024 },
  fileFilter:(req,file,cb)=> file.mimetype.startsWith('image/') ? cb(null,true) : cb(new Error('Only image files are allowed.'))
});
function findUploadedFile(files, allowedNames){ return (files||[]).find(f=>allowedNames.includes(f.fieldname)); }

app.get('/api/options', (req,res)=>res.json({ districts:DISTRICTS, homeAreas:HOME_AREAS, statuses:STATUSES }));
app.get('/api/me', requireLogin, (req,res)=>res.json(currentUser(req)));
app.get('/api/settings', (req,res)=>db.all('SELECT key,value FROM settings', [], (e,rows)=>res.json(Object.fromEntries((rows||[]).map(r=>[r.key,r.value])))));

app.post('/register', upload.any(), (req,res)=>{
  db.get('SELECT value FROM settings WHERE key="registration_deadline"', [], (e, setting)=>{
    if (isPastDeadline(setting && setting.value)) return res.status(403).send('Registration is closed. The registration deadline has passed.');
    const b = req.body; const nin = String(b.nin||'').trim().toUpperCase();
    if(!isValidNIN(nin)) return res.status(400).send('Invalid NIN. Use the strict 14-character Uganda NIN format.');
    if(!DISTRICTS.includes(b.district)) return res.status(400).send('Invalid district selected.');
    if(!b.home_area || String(b.home_area).trim().length < 2) return res.status(400).send('Please select or type a valid home area.');
    const playerPhoto = findUploadedFile(req.files, ['photo','player_photo','playerPhoto']);
    const front = findUploadedFile(req.files, ['national_id_front_photo','nationalIdFrontPhoto','id_front_photo','id_front']);
    const back = findUploadedFile(req.files, ['national_id_back_photo','nationalIdBackPhoto','id_back_photo','id_back']);
    if(!playerPhoto || !front || !back) return res.status(400).send('Player photo, National ID front, and National ID back are required.');
    const regNo = 'AC2026-' + Date.now().toString().slice(-8);
    const playerCode = 'AC26-' + Math.floor(100000 + Math.random()*900000);
    db.run(`INSERT INTO players (registration_no, player_code, player_name, dob, district, player_type, club, home_area, eligibility, nin, previous_clubs, phone, photo, national_id_front_photo, national_id_back_photo, player_signature, official_name, official_signature)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [regNo, playerCode, b.player_name, b.dob || '', b.district, b.player_type, b.club, b.home_area, b.eligibility, nin, b.previous_clubs, b.phone, playerPhoto.filename, front.filename, back.filename, b.player_signature, b.official_name, b.official_signature],
      function(err){
        if(err && String(err.message).includes('UNIQUE')) return res.status(409).send('This NIN has already been registered. Duplicate registration is not allowed.');
        if(err) return res.status(500).send('Registration failed. Please try again.');
        res.redirect(`/success.html?reg=${encodeURIComponent(regNo)}`);
      });
  });
});

app.post('/admin-login', (req,res)=>{
  db.get('SELECT * FROM users WHERE username=?', [req.body.username], (err,user)=>{
    if(user && bcrypt.compareSync(req.body.password, user.password_hash)){
      req.session.userId=user.id; req.session.username=user.username; req.session.role=user.role; req.session.district=user.district; req.session.fullName=user.full_name || user.username;
      return res.redirect('/admin.html');
    }
    res.redirect('/admin-login.html?error=1');
  });
});
app.get('/logout', (req,res)=>req.session.destroy(()=>res.redirect('/admin-login.html')));

app.get('/api/players', requireLogin, (req,res)=>{
  const params=[]; let sql='SELECT * FROM players'; const where=[];
  if(req.session.role==='district_officer'){ where.push('district=?'); params.push(req.session.district); }
  else if(req.query.district){ where.push('district=?'); params.push(req.query.district); }
  if(req.query.status){ where.push('status=?'); params.push(req.query.status); }
  if(where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY created_at DESC LIMIT 5000';
  db.all(sql, params, (err,rows)=>err?res.status(500).json({error:'Failed to load players'}):res.json(rows));
});
app.post('/api/players/:id/status', requireLogin, (req,res)=>{
  const status = String(req.body.status || 'Pending'); if(!STATUSES.includes(status)) return res.status(400).json({error:'Invalid status'});
  const notes = req.body.review_notes || '';
  db.get('SELECT * FROM players WHERE id=?', [req.params.id], (err,p)=>{
    if(!p) return res.status(404).json({error:'Not found'});
    if(req.session.role==='district_officer' && p.district !== req.session.district) return res.status(403).json({error:'Not allowed'});
    db.run('UPDATE players SET status=?, review_notes=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?', [status, notes, req.session.userId, req.params.id], err=>{
      if(err) return res.status(500).json({error:'Failed'});
      audit(req, 'Changed player status', req.params.id, `${p.status} -> ${status}`); res.json({success:true});
    });
  });
});

app.get('/api/users', requireLogin, requireAdmin, (req,res)=>db.all('SELECT id,username,role,district,full_name,created_at FROM users ORDER BY role, district, username', [], (e,rows)=>res.json(rows||[])));
app.post('/api/users', requireLogin, requireAdmin, (req,res)=>{
  const { username, password, role, district, full_name } = req.body;
  if(!validUsername(username)) return res.status(400).json({error:'Username must be 4-30 characters and may contain letters, numbers, dots, dashes or underscores.'});
  if(!strongPassword(password)) return res.status(400).json({error:'Password must be at least 8 characters and include uppercase, lowercase and a number.'});
  if(!['admin','district_officer'].includes(role)) return res.status(400).json({error:'Invalid role.'});
  if(role==='district_officer' && !DISTRICTS.includes(district)) return res.status(400).json({error:'Select a valid district.'});
  db.run('INSERT INTO users(username,password_hash,role,district,full_name) VALUES(?,?,?,?,?)', [username, bcrypt.hashSync(password,10), role, role==='admin'?null:district, full_name || username], function(err){
    if(err) return res.status(400).json({error:'Username already exists or user could not be created.'});
    audit(req, 'Created user account', null, `${username} (${role})`); res.json({success:true});
  });
});
app.delete('/api/users/:id', requireLogin, requireAdmin, (req,res)=>{
  if(Number(req.params.id)===Number(req.session.userId)) return res.status(400).json({error:'You cannot delete your own active account.'});
  db.run('DELETE FROM users WHERE id=?', [req.params.id], err=>err?res.status(500).json({error:'Failed'}):res.json({success:true}));
});
app.post('/change-password', requireLogin, (req,res)=>{
  const { current_password, new_password } = req.body;
  if(!strongPassword(new_password)) return res.status(400).send('New password must be at least 8 characters and include uppercase, lowercase and a number.');
  db.get('SELECT * FROM users WHERE id=?', [req.session.userId], (err,user)=>{
    if(!user || !bcrypt.compareSync(current_password, user.password_hash)) return res.status(400).send('Current password is incorrect.');
    db.run('UPDATE users SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [bcrypt.hashSync(new_password,10), req.session.userId], ()=>res.redirect('/admin.html?password=changed'));
  });
});
app.post('/api/settings/deadline', requireLogin, requireAdmin, (req,res)=>{
  db.run('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ['registration_deadline', req.body.deadline || ''], err=>err?res.status(500).json({error:'Failed'}):res.json({success:true}));
});
app.get('/api/audit', requireLogin, requireAdmin, (req,res)=>{
  db.all(`SELECT a.*, u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 100`, [], (e,rows)=>res.json(rows||[]));
});

async function qrDataUrl(text){ return await QRCode.toDataURL(text, { margin: 1, width: 120 }); }
function footer(doc,left,right){
  doc.moveTo(left, 752).lineTo(right, 752).stroke('#d6a62d');
  doc.fillColor('#092f25').font('Helvetica-Bold').fontSize(8).text('ANKOLE CUP 2026', left, 760, {align:'center', width:right-left});
  doc.font('Helvetica').fontSize(7.5).text('Plot 01, Kome Crescent Luzira, P.O Box 203327 Kampala | Tel: 0779 283 515 / 0703 158 864', left, 774, {align:'center', width:right-left});
  doc.text('Plot 01, Bananuka Drive, Wazalendo Sacco Building - Mbarara, 1st Floor - Office 1 | Tel: 0700 905 727', left, 786, {align:'center', width:right-left});
  doc.text('Email: ankolecup2026@gmail.com', left, 798, {align:'center', width:right-left});
}
async function drawPdf(row,res){
  const doc = new PDFDocument({ margin: 36, size: 'A4' });
  res.setHeader('Content-Type','application/pdf'); res.setHeader('Content-Disposition',`attachment; filename="${row.registration_no}.pdf"`); doc.pipe(res);
  const pageW=doc.page.width, left=42, right=pageW-42, logoPath=path.join(__dirname,'public','ankole-logo.png');
  doc.rect(0,0,pageW,120).fill('#092f25'); doc.rect(0,114,pageW,6).fill('#d6a62d');
  if(fs.existsSync(logoPath)) doc.image(logoPath,left,15,{width:78});
  doc.fillColor('white').font('Helvetica-Bold').fontSize(22).text('ANKOLE CUP 2026',125,22,{width:350,align:'center'});
  doc.fontSize(12).text('COMPETITIONS DEPARTMENT',125,52,{width:350,align:'center'}); doc.fontSize(15).text('PLAYER REGISTRATION FORM',125,76,{width:350,align:'center'});
  doc.roundedRect(405,24,148,58,8).fill('#fff'); doc.fillColor('#092f25').fontSize(8).font('Helvetica-Bold').text('REGISTRATION NO',418,34); doc.fontSize(12).text(row.registration_no||'',418,50,{width:120});
  try { const qr = await qrDataUrl(`ANKOLE CUP 2026 VERIFY: ${row.registration_no} | ${row.player_name} | ${row.district}`); doc.image(qr, 515, 86, {width:46}); } catch(e) {}
  let y=140; doc.fillColor('#333').font('Helvetica').fontSize(9).text('For this registration to be processed, all required fields must be filled.',left,y,{width:right-left,align:'center'}); y+=20;
  function section(title){doc.roundedRect(left,y,right-left,22,4).fill('#092f25'); doc.fillColor('white').font('Helvetica-Bold').fontSize(10).text(title,left+10,y+6); y+=30;}
  function rowBox(label,value,x,ypos,w){doc.rect(x,ypos,w,24).stroke('#c9d2cc'); doc.fillColor('#edf3ef').rect(x,ypos,120,24).fill().stroke('#c9d2cc'); doc.fillColor('#092f25').font('Helvetica-Bold').fontSize(8).text(label,x+7,ypos+8,{width:108}); doc.fillColor('#111').font('Helvetica').fontSize(9).text(String(value||''),x+128,ypos+7,{width:w-136});}
  section('Section A: Player Details'); const colW=(right-left-12)/2;
  rowBox('Player Name',row.player_name,left,y,colW); rowBox('District',row.district,left+colW+12,y,colW); y+=24;
  rowBox('Home Area',row.home_area,left,y,colW); rowBox('Club',row.club,left+colW+12,y,colW); y+=24;
  rowBox('Category',row.player_type,left,y,colW); rowBox('NIN',row.nin,left+colW+12,y,colW); y+=24;
  rowBox('Phone',row.phone||'',left,y,colW); rowBox('Date of Birth',row.dob||'',left+colW+12,y,colW); y+=24;
  rowBox('Player Code',row.player_code||'',left,y,colW); rowBox('Status',row.status||'Pending',left+colW+12,y,colW); y+=34;
  section('Section B: Eligibility and History'); rowBox('Previous Clubs',row.previous_clubs||'',left,y,right-left); y+=24; rowBox('Eligibility',row.eligibility||'',left,y,right-left); y+=34;
  section('Section C: Attachments'); const imgY=y, boxW=160; [['Player Photo',row.photo],['National ID Front',row.national_id_front_photo],['National ID Back',row.national_id_back_photo]].forEach((b,i)=>{ const x=left+i*(boxW+18); doc.roundedRect(x,imgY,boxW,105,6).stroke('#c9d2cc'); doc.fillColor('#092f25').font('Helvetica-Bold').fontSize(8).text(b[0],x,imgY+8,{width:boxW,align:'center'}); const p=path.join(uploadDir,b[1]||''); try{ if(b[1]&&fs.existsSync(p)) doc.image(p,x+16,imgY+25,{fit:[boxW-32,70],align:'center',valign:'center'});}catch(e){}}); y+=122;
  section('Section D: Declaration and Signatures'); doc.fillColor('#111').font('Helvetica').fontSize(9).text('Declaration: I declare that the information provided is correct to the best of my knowledge and I shall abide by all Ankole Cup 2026 directives, regulations and decisions.',left,y,{width:right-left,align:'justify'}); y+=36;
  rowBox('Player Signature',row.player_signature,left,y,colW); rowBox('Official Name',row.official_name||'',left+colW+12,y,colW); y+=24; rowBox('Official Signature',row.official_signature||'',left,y,colW); rowBox('Submitted',row.created_at||'',left+colW+12,y,colW); footer(doc,left,right); doc.end();
}
async function drawIdCard(row,res){
  const doc = new PDFDocument({ size:[320,205], margin:0 }); res.setHeader('Content-Type','application/pdf'); res.setHeader('Content-Disposition',`attachment; filename="${row.player_code || row.registration_no}-ID-CARD.pdf"`); doc.pipe(res);
  const logoPath=path.join(__dirname,'public','ankole-logo.png'); doc.rect(0,0,320,205).fill('#f7f9f6'); doc.rect(0,0,320,46).fill('#092f25'); doc.rect(0,44,320,4).fill('#d6a62d'); if(fs.existsSync(logoPath)) doc.image(logoPath,12,7,{width:34});
  doc.fillColor('white').font('Helvetica-Bold').fontSize(13).text('ANKOLE CUP 2026',54,9); doc.fontSize(8).text('OFFICIAL PLAYER IDENTIFICATION CARD',54,27);
  const photo=path.join(uploadDir,row.photo||''); try{if(fs.existsSync(photo)) doc.image(photo,14,62,{fit:[76,90]});}catch(e){}
  doc.fillColor('#092f25').font('Helvetica-Bold').fontSize(11).text(row.player_name||'',104,62,{width:190}); doc.fillColor('#111').font('Helvetica').fontSize(8).text(`Player ID: ${row.player_code||''}`,104,82); doc.text(`District: ${row.district||''}`,104,96); doc.text(`Club: ${row.club||''}`,104,110); doc.text(`NIN: ${row.nin||''}`,104,124); doc.text(`Status: ${row.status||'Pending'}`,104,138);
  try{ const qr=await qrDataUrl(`${row.registration_no}|${row.player_code}|${row.nin}`); doc.image(qr,250,125,{width:54}); }catch(e){}
  doc.rect(0,176,320,29).fill('#092f25'); doc.fillColor('white').fontSize(7).text('This card remains property of Ankole Cup 2026 Competitions Department.',10,185,{width:300,align:'center'}); doc.end();
}
app.get('/players/:regNo/pdf', requireLogin, (req,res)=>db.get('SELECT * FROM players WHERE registration_no=?',[req.params.regNo], async (err,row)=>{
  if(!row) return res.status(404).send('Registration not found');
  if(!canAccessPlayer(req,row)) return res.status(403).send('You are not allowed to access this district registration.');
  if(row.status !== 'Approved') return res.status(403).send('This registration form can only be downloaded after official approval.');
  await drawPdf(row,res);
}));
app.get('/players/:regNo/id-card', requireLogin, (req,res)=>db.get('SELECT * FROM players WHERE registration_no=?',[req.params.regNo], async (err,row)=>{
  if(!row) return res.status(404).send('Registration not found');
  if(!canAccessPlayer(req,row)) return res.status(403).send('You are not allowed to access this district registration.');
  if(row.status !== 'Approved') return res.status(403).send('This player ID card can only be downloaded after official approval.');
  await drawIdCard(row,res);
}));
app.get('/verify/:regNo', (req,res)=>db.get('SELECT registration_no,player_code,player_name,district,club,status FROM players WHERE registration_no=?',[req.params.regNo], (err,row)=> row?res.json(row):res.status(404).json({error:'Not found'})));

// Technical exports are hidden from the interface but kept for emergency/back-office use.
app.get('/api/export/json', requireLogin, requireAdmin, (req,res)=>db.all('SELECT * FROM players ORDER BY created_at DESC',[],(err,rows)=>res.json({exported_at:new Date().toISOString(),rows})));
app.get('/api/export/csv', requireLogin, requireAdmin, (req,res)=>db.all('SELECT * FROM players ORDER BY created_at DESC',[],(err,rows)=>{ const headers=['registration_no','player_code','player_name','district','home_area','club','player_type','nin','phone','status','created_at']; const csv=[headers.join(','),...(rows||[]).map(r=>headers.map(h=>`"${String(r[h]??'').replace(/"/g,'""')}"`).join(','))].join('\n'); res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition','attachment; filename="ankole-cup-players.csv"'); res.send(csv); }));
app.get('/api/backup/database', requireLogin, requireAdmin, (req,res)=>{ const backup=path.join(backupDir,`ankole_cup_backup_${Date.now()}.db`); fs.copyFileSync(DB_PATH,backup); res.download(backup); });

app.use((err,req,res,next)=>{ if(err instanceof multer.MulterError) return res.status(400).send('Upload error: '+err.message+'. Please upload valid image files.'); if(err) return res.status(400).send(err.message||'Upload failed.'); next(); });
app.listen(PORT, ()=>console.log(`Ankole Cup 2026 professional registration system running on http://localhost:${PORT}`));
