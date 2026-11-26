#!/usr/bin/env python3
"""MRITYUNJAY demo API - Python standard-library HTTP server + SQLite."""
import os, json, sqlite3, hashlib, hmac, base64, time, secrets, re, threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

ROOT=Path(__file__).resolve().parent
# Load simple KEY=VALUE .env entries without an extra dependency; shell env wins.
_env_file=ROOT/'.env'
if _env_file.exists():
 for _line in _env_file.read_text().splitlines():
  _line=_line.strip()
  if _line and not _line.startswith('#') and '=' in _line:
   _k,_v=_line.split('=',1); os.environ.setdefault(_k.strip(),_v.strip().strip('\"').strip("'"))
DB=Path(os.getenv('DATABASE_PATH', ROOT/'instance'/'mrityunjay.db'))
DB.parent.mkdir(parents=True,exist_ok=True)
SECRET=os.getenv('JWT_SECRET','CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT_'+secrets.token_hex(12)).encode()
ENC_KEY=hashlib.sha256(os.getenv('DATA_ENCRYPTION_KEY','development-only-key-change-me').encode()).digest()
try:
 from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception: AESGCM=None
if AESGCM is None: raise RuntimeError('Install cryptography to enable required AES-256-GCM encryption.')
try:
 from sklearn.ensemble import IsolationForest
except Exception: IsolationForest=None

SCHEMA='''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('patient','hospital','ambulance','admin')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hospitals(id INTEGER PRIMARY KEY, name TEXT NOT NULL, city TEXT NOT NULL, address TEXT NOT NULL, specialties TEXT NOT NULL, phone TEXT NOT NULL, emergency_email TEXT, verified INTEGER DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS beds(id INTEGER PRIMARY KEY, hospital_id INTEGER NOT NULL REFERENCES hospitals(id) ON DELETE CASCADE, bed_type TEXT NOT NULL, total INTEGER NOT NULL, available INTEGER NOT NULL, updated_at TEXT NOT NULL, UNIQUE(hospital_id,bed_type));
CREATE TABLE IF NOT EXISTS ambulances(id INTEGER PRIMARY KEY, provider TEXT NOT NULL, city TEXT NOT NULL, phone TEXT NOT NULL, vehicle_no TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Available', operator_id INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS ambulance_requests(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), ambulance_id INTEGER REFERENCES ambulances(id), pickup TEXT NOT NULL, destination TEXT NOT NULL, notes TEXT, status TEXT NOT NULL DEFAULT 'Requested', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS donors(id INTEGER PRIMARY KEY, name TEXT NOT NULL, blood_group TEXT NOT NULL, city TEXT NOT NULL, phone TEXT NOT NULL, available INTEGER DEFAULT 1, verified INTEGER DEFAULT 1, user_id INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS donor_requests(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), donor_id INTEGER REFERENCES donors(id), blood_group TEXT NOT NULL, city TEXT NOT NULL, units INTEGER DEFAULT 1, status TEXT DEFAULT 'Requested', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, patient_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, encrypted_blob TEXT NOT NULL, created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS emergency_contacts(id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, phone TEXT NOT NULL, region TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, user_id INTEGER, email TEXT, action TEXT NOT NULL, resource TEXT, ip TEXT, success INTEGER DEFAULT 1, risk REAL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS security_alerts(id INTEGER PRIMARY KEY, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT NOT NULL, status TEXT DEFAULT 'Open', created_at TEXT NOT NULL, user_id INTEGER);
'''
def anomaly_risk(failed, hour=None, sensitive=False):
 # Lightweight behavioral anomaly model: IsolationForest compares the event with a
 # baseline of ordinary healthcare portal activity; deterministic rules add context.
 hour = hour if hour is not None else datetime.now().hour
 features=[[int(failed), int(hour<6 or hour>22), int(sensitive)]]
 if IsolationForest:
  baseline=[[0,0,0],[0,0,0],[0,0,0],[0,1,0],[0,0,1],[0,0,0],[1,0,0]]
  model=IsolationForest(n_estimators=40, contamination=0.2, random_state=7).fit(baseline)
  ml_score=0.8 if model.predict(features)[0] < 0 else 0.15
 else: ml_score=0.0
 return min(0.99, max(ml_score, 0.85 if failed else 0.0, 0.55 if (hour<6 or hour>22) and sensitive else 0.0))
def now(): return datetime.now(timezone.utc).isoformat()
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def pbkdf(pw,salt=None):
 salt=salt or secrets.token_bytes(16); return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',pw.encode(),salt,240000).hex()
def verify(pw,stored):
 try:
  s,v=stored.split(':'); return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',pw.encode(),bytes.fromhex(s),240000).hex(),v)
 except: return False
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def token(uid,role):
 head=b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode()); body=b64(json.dumps({'sub':uid,'role':role,'exp':int(time.time())+36000}).encode()); sig=b64(hmac.new(SECRET,f'{head}.{body}'.encode(),hashlib.sha256).digest()); return f'{head}.{body}.{sig}'
def decode(tok):
 try:
  a,b,s=tok.split('.'); expected=b64(hmac.new(SECRET,f'{a}.{b}'.encode(),hashlib.sha256).digest())
  if not hmac.compare_digest(s,expected): return None
  p=json.loads(base64.urlsafe_b64decode(b+'=='))
  return p if p['exp']>time.time() else None
 except: return None
def encrypt(text):
 n=secrets.token_bytes(12); return 'gcm:'+base64.b64encode(n+AESGCM(ENC_KEY).encrypt(n,text.encode(),None)).decode()
def decrypt(blob):
 if blob.startswith('gcm:') and AESGCM:
  raw=base64.b64decode(blob[4:]); return AESGCM(ENC_KEY).decrypt(raw[:12],raw[12:],None).decode()
 raise ValueError('Unable to decrypt record')
def init_db():
 c=db(); c.executescript(SCHEMA)
 if c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']==0:
  users=[('Demo Patient','patient@mrityunjay.demo','Patient@123','patient'),('City Hospital Staff','hospital@mrityunjay.demo','Hospital@123','hospital'),('Rapid Ambulance Operator','ambulance@mrityunjay.demo','Ambulance@123','ambulance'),('Security Administrator','admin@mrityunjay.demo','Admin@123','admin')]
  for n,e,p,r in users: c.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',(n,e,pbkdf(p),r,now()))
  hs=[('Shree City Multispeciality Hospital','Raipur','Civil Lines, Raipur','Cardiology,Emergency,Neurology','0771-4001001'),('Navjeevan Medical Centre','Raipur','Shankar Nagar, Raipur','Trauma,Orthopaedics,ICU','0771-4001002'),('Aarogya Critical Care','Durg','G E Road, Durg','Critical Care,Emergency','0788-4001003'),('LifeLine Hospital','Bhilai','Sector 6, Bhilai','Maternity,Paediatrics,ICU','0788-4001004')]
  for n,city,a,sp,ph in hs:
   hid=c.execute('INSERT INTO hospitals(name,city,address,specialties,phone,emergency_email,created_at) VALUES(?,?,?,?,?,?,?)',(n,city,a,sp,ph,'emergency@'+re.sub('[^a-z]','',n.lower())+'.demo',now())).lastrowid
   for typ,total,av in [('ICU',20,6),('General',60,24),('Oxygen',15,8)]: c.execute('INSERT INTO beds(hospital_id,bed_type,total,available,updated_at) VALUES(?,?,?,?,?)',(hid,typ,total,av,now()))
  amb=[('Rapid Response 108','Raipur','108','CG04AB1020','Available'),('Life Saver Ambulance','Raipur','0771-2220101','CG04CD2020','Available'),('Durg Emergency Fleet','Durg','0788-2220102','CG07EF3030','Busy'),('Bhilai Care Transit','Bhilai','0788-2220103','CG07GH4040','Available')]
  for x in amb:c.execute('INSERT INTO ambulances(provider,city,phone,vehicle_no,status,operator_id) VALUES(?,?,?,?,?,?)',(*x,3))
  donors=[('Aarav S.','O+','Raipur','9000001001'),('Meera K.','B+','Raipur','9000001002'),('Rohan P.','A+','Durg','9000001003'),('Ananya R.','O-','Bhilai','9000001004'),('Kabir M.','AB+','Raipur','9000001005'),('Ira D.','B-','Durg','9000001006')]
  for x in donors:c.execute('INSERT INTO donors(name,blood_group,city,phone) VALUES(?,?,?,?)',x)
  contacts=[('National Ambulance','Ambulance','112','India'),('Emergency Response','Ambulance','108','Chhattisgarh'),('Police Control Room','Police','100','India'),('Fire & Rescue','Fire','101','India'),('Poison Information Centre','Poison Control','1800-116-117','India'),('Women Helpline','Support','181','India')]
  for x in contacts:c.execute('INSERT INTO emergency_contacts(name,category,phone,region) VALUES(?,?,?,?)',x)
  c.commit()
 c.close()

def asdict(row): return dict(row) if row else None
class Handler(SimpleHTTPRequestHandler):
 def __init__(self,*a,**kw): super().__init__(*a,directory=str(ROOT/'app'),**kw)
 def log_message(self,*a): pass
 def sendj(self,status,obj):
  raw=json.dumps(obj,default=str).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Access-Control-Allow-Headers','Content-Type, Authorization'); self.send_header('Access-Control-Allow-Methods','GET,POST,PATCH,DELETE,OPTIONS'); self.end_headers(); self.wfile.write(raw)
 def body(self):
  try:return json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))) or b'{}')
  except:return {}
 def auth(self,roles=None):
  hdr=self.headers.get('Authorization',''); p=decode(hdr[7:]) if hdr.startswith('Bearer ') else None
  if not p:return None
  if roles and p['role'] not in roles:return None
  return p
 def audit(self,user,action,resource='',success=1,risk=0):
  c=db(); c.execute('INSERT INTO audit_logs(user_id,email,action,resource,ip,success,risk,created_at) VALUES(?,?,?,?,?,?,?,?)',(user.get('sub') if user else None,user.get('email') if user else '',action,resource,self.client_address[0],success,risk,now())); c.commit(); c.close()
 def do_OPTIONS(self): self.sendj(200,{})
 def do_GET(self): self.route()
 def do_POST(self): self.route()
 def do_PATCH(self): self.route()
 def do_DELETE(self): self.route()
 def route(self):
  path=urlparse(self.path).path; method=self.command; data=self.body() if method in ('POST','PATCH','DELETE') else {}; q=parse_qs(urlparse(self.path).query)
  if not path.startswith('/api/') and method=='GET':
   return super().do_GET()
  c=db()
  try:
   if path=='/api/health': return self.sendj(200,{'status':'ok','database':'connected','encryption':'AES-256-GCM' if AESGCM else 'fallback','ai':'scikit-learn' if IsolationForest else 'heuristic'})
   if path=='/api/auth/register' and method=='POST':
    name=data.get('name','').strip(); email=data.get('email','').lower().strip(); pw=data.get('password',''); role=data.get('role','patient')
    if not name or not re.match(r'^[^@]+@[^@]+\.[^@]+$',email) or len(pw)<8 or role not in ('patient','hospital','ambulance'): return self.sendj(400,{'error':'Enter a name, valid email, password (8+ characters) and allowed role.'})
    try: uid=c.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',(name,email,pbkdf(pw),role,now())).lastrowid; c.commit()
    except sqlite3.IntegrityError:return self.sendj(409,{'error':'An account with this email already exists.'})
    u={'sub':uid,'role':role,'email':email}; self.audit(u,'REGISTER','account'); return self.sendj(201,{'token':token(uid,role),'user':{'id':uid,'name':name,'email':email,'role':role}})
   if path=='/api/auth/login' and method=='POST':
    email=data.get('email','').lower().strip(); row=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone(); ok=bool(row and verify(data.get('password',''),row['password_hash']))
    self.audit({'sub':row['id'] if row else None,'email':email},'LOGIN','authentication',int(ok),anomaly_risk(not ok, sensitive=not ok))
    fails=c.execute("SELECT COUNT(*) n FROM audit_logs WHERE email=? AND action='LOGIN' AND success=0 AND created_at>datetime('now','-15 minutes')",(email,)).fetchone()['n']
    if fails>=5:
     c.execute("INSERT INTO security_alerts(severity,title,detail,created_at,user_id) VALUES('High','Repeated failed login attempts',?,?,?)",(f'{fails} failed login attempts for {email}',now(),row['id'] if row else None)); c.commit(); return self.sendj(429,{'error':'Account temporarily throttled after repeated failed attempts.'})
    if not ok:return self.sendj(401,{'error':'Invalid email or password.'})
    return self.sendj(200,{'token':token(row['id'],row['role']),'user':{'id':row['id'],'name':row['name'],'email':row['email'],'role':row['role']}})
   if path=='/api/auth/me':
    u=self.auth();
    if not u:return self.sendj(401,{'error':'Authentication required'})
    row=c.execute('SELECT id,name,email,role FROM users WHERE id=?',(u['sub'],)).fetchone(); return self.sendj(200,{'user':asdict(row)})
   if path=='/api/dashboard':
    u=self.auth();
    if not u:return self.sendj(401,{'error':'Authentication required'})
    stats={'hospitals':c.execute('SELECT COUNT(*) n FROM hospitals').fetchone()['n'],'icu_available':c.execute("SELECT COALESCE(SUM(available),0) n FROM beds WHERE bed_type='ICU'").fetchone()['n'],'general_available':c.execute("SELECT COALESCE(SUM(available),0) n FROM beds WHERE bed_type='General'").fetchone()['n'],'ambulances_available':c.execute("SELECT COUNT(*) n FROM ambulances WHERE status='Available'").fetchone()['n'],'available_donors':c.execute('SELECT COUNT(*) n FROM donors WHERE available=1 AND verified=1').fetchone()['n'],'open_alerts':c.execute("SELECT COUNT(*) n FROM security_alerts WHERE status='Open'").fetchone()['n']}
    if u['role']=='admin': stats['recent_events']=[dict(x) for x in c.execute('SELECT action,email,success,risk,created_at FROM audit_logs ORDER BY id DESC LIMIT 8')]
    return self.sendj(200,stats)
   if path=='/api/hospitals' and method=='GET':
    city=q.get('city',[''])[0].lower(); rows=c.execute('SELECT * FROM hospitals WHERE verified=1 AND lower(city) LIKE ? ORDER BY city,name',('%'+city+'%',)).fetchall(); out=[]
    for h in rows:
     d=asdict(h); d['specialties']=d['specialties'].split(','); d['beds']=[dict(x) for x in c.execute('SELECT bed_type,total,available,updated_at FROM beds WHERE hospital_id=?',(h['id'],))]; out.append(d)
    return self.sendj(200,out)
   if path=='/api/hospitals' and method=='POST': pass
   if path=='/api/beds' and method=='PATCH':
    u=self.auth(['hospital','admin']);
    if not u:return self.sendj(403,{'error':'Hospital staff or admin access required'})
    hid=int(data.get('hospital_id',0)); typ=data.get('bed_type'); total=int(data.get('total',0)); available=int(data.get('available',0))
    if typ not in ('ICU','General','Oxygen') or total<0 or available<0 or available>total:return self.sendj(400,{'error':'Invalid bed type or counts.'})
    if u['role']=='hospital' and not c.execute('SELECT 1 FROM hospitals WHERE id=?',(hid,)).fetchone():return self.sendj(404,{'error':'Hospital not found'})
    c.execute('INSERT INTO beds(hospital_id,bed_type,total,available,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(hospital_id,bed_type) DO UPDATE SET total=excluded.total,available=excluded.available,updated_at=excluded.updated_at',(hid,typ,total,available,now())); c.commit(); self.audit(u,'UPDATE_BEDS',f'{hid}:{typ}'); return self.sendj(200,{'message':'Bed availability updated'})
   if path=='/api/ambulances':
    rows=c.execute('SELECT * FROM ambulances WHERE lower(city) LIKE ? ORDER BY status,provider',('%'+q.get('city',[''])[0].lower()+'%',)).fetchall(); return self.sendj(200,[asdict(x) for x in rows])
   if path=='/api/ambulance-requests' and method=='GET':
    u=self.auth();
    if not u:return self.sendj(401,{'error':'Authentication required'})
    sql='SELECT * FROM ambulance_requests'; args=[]
    if u['role']=='patient':sql+=' WHERE user_id=?';args=[u['sub']]
    rows=c.execute(sql+' ORDER BY id DESC',args).fetchall();return self.sendj(200,[asdict(x) for x in rows])
   if path=='/api/donors' and method=='GET':
    bg=q.get('blood_group',[''])[0].upper(); city=q.get('city',[''])[0].lower(); rows=c.execute('SELECT id,name,blood_group,city,phone,available,verified FROM donors WHERE verified=1 AND available=1 AND blood_group LIKE ? AND lower(city) LIKE ? ORDER BY city,name',('%'+bg+'%','%'+city+'%')).fetchall(); return self.sendj(200,[asdict(x) for x in rows])
   if path=='/api/donors' and method=='POST': pass
   if path=='/api/contacts':return self.sendj(200,[asdict(x) for x in c.execute('SELECT * FROM emergency_contacts ORDER BY category')])
   if path=='/api/records' and method=='GET':
    u=self.auth();
    if not u:return self.sendj(401,{'error':'Authentication required'})
    if u['role'] not in ('patient','hospital','admin'):return self.sendj(403,{'error':'Not authorized'})
    if u['role']=='patient': rows=c.execute('SELECT id,title,created_at,patient_id FROM records WHERE patient_id=? ORDER BY id DESC',(u['sub'],)).fetchall()
    else: rows=c.execute('SELECT id,title,created_at,patient_id FROM records ORDER BY id DESC').fetchall()
    self.audit(u,'VIEW_RECORD_INDEX','medical_records');return self.sendj(200,[asdict(x) for x in rows])
   if path=='/api/records' and method=='POST':
    u=self.auth(['patient','hospital','admin']);
    if not u:return self.sendj(403,{'error':'Not authorized'})
    patient=int(data.get('patient_id',u['sub']))
    if u['role']=='patient' and patient!=u['sub']:return self.sendj(403,{'error':'Patients may only create their own records'})
    if not data.get('title') or not data.get('content'):return self.sendj(400,{'error':'Title and record content are required'})
    rid=c.execute('INSERT INTO records(patient_id,title,encrypted_blob,created_by,created_at) VALUES(?,?,?,?,?)',(patient,data['title'],encrypt(data['content']),u['sub'],now())).lastrowid;c.commit();self.audit(u,'CREATE_ENCRYPTED_RECORD',str(rid));return self.sendj(201,{'id':rid,'message':'Record encrypted and saved'})
   if path.startswith('/api/records/') and method=='GET':
    u=self.auth(['patient','hospital','admin']);
    if not u:return self.sendj(403,{'error':'Not authorized'})
    rid=path.rsplit('/',1)[-1]; row=c.execute('SELECT * FROM records WHERE id=?',(rid,)).fetchone()
    if not row:return self.sendj(404,{'error':'Record not found'})
    if u['role']=='patient' and row['patient_id']!=u['sub']:return self.sendj(403,{'error':'Access denied'})
    self.audit(u,'DECRYPT_MEDICAL_RECORD',str(rid));return self.sendj(200,{'id':row['id'],'title':row['title'],'content':decrypt(row['encrypted_blob']),'created_at':row['created_at']})
   if path=='/api/ambulance-requests' and method=='POST':
    u=self.auth(['patient','admin']);
    if not u:return self.sendj(403,{'error':'Patient login required'})
    if not data.get('pickup') or not data.get('destination'):return self.sendj(400,{'error':'Pickup and destination are required'})
    a=c.execute("SELECT id FROM ambulances WHERE status='Available' AND lower(city) LIKE ? ORDER BY id LIMIT 1",('%'+data.get('city','').lower()+'%',)).fetchone(); aid=a['id'] if a else None
    rid=c.execute('INSERT INTO ambulance_requests(user_id,ambulance_id,pickup,destination,notes,status,created_at) VALUES(?,?,?,?,?,?,?)',(u['sub'],aid,data['pickup'],data['destination'],data.get('notes',''),'Dispatched' if aid else 'Requested',now())).lastrowid
    if aid:c.execute("UPDATE ambulances SET status='Busy' WHERE id=?",(aid,))
    c.commit();self.audit(u,'CREATE_AMBULANCE_REQUEST',str(rid));return self.sendj(201,{'id':rid,'status':'Dispatched' if aid else 'Requested','ambulance_id':aid,'message':'Request submitted'})
   if path.startswith('/api/ambulance-requests/') and method=='PATCH':
    u=self.auth(['ambulance','admin']);
    if not u:return self.sendj(403,{'error':'Operator or admin access required'})
    rid=path.rsplit('/',1)[-1]; status=data.get('status')
    if status not in ('Accepted','En Route','Arrived','Completed','Cancelled'):return self.sendj(400,{'error':'Invalid status'})
    c.execute('UPDATE ambulance_requests SET status=? WHERE id=?',(status,rid)); c.commit();self.audit(u,'UPDATE_AMBULANCE_STATUS',str(rid));return self.sendj(200,{'message':'Request status updated'})
   if path=='/api/donor-requests' and method=='POST':
    u=self.auth(['patient','admin']);
    if not u:return self.sendj(403,{'error':'Patient login required'})
    bg=data.get('blood_group','').upper();city=data.get('city','');
    if bg not in ('A+','A-','B+','B-','AB+','AB-','O+','O-') or not city:return self.sendj(400,{'error':'Valid blood group and city required'})
    d=c.execute('SELECT id FROM donors WHERE blood_group=? AND available=1 AND lower(city) LIKE ? ORDER BY id LIMIT 1',(bg,'%'+city.lower()+'%')).fetchone();rid=c.execute('INSERT INTO donor_requests(user_id,donor_id,blood_group,city,created_at) VALUES(?,?,?,?,?)',(u['sub'],d['id'] if d else None,bg,city,now())).lastrowid;c.commit();self.audit(u,'CREATE_DONOR_REQUEST',str(rid));return self.sendj(201,{'id':rid,'status':'Requested','matched':bool(d)})
   if path=='/api/security/overview':
    u=self.auth(['admin']);
    if not u:return self.sendj(403,{'error':'Admin access required'})
    logs=[dict(x) for x in c.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 60')]; alerts=[dict(x) for x in c.execute('SELECT * FROM security_alerts ORDER BY id DESC LIMIT 40')]; users=c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']; sessions=users
    return self.sendj(200,{'logs':logs,'alerts':alerts,'metrics':{'events':c.execute('SELECT COUNT(*) n FROM audit_logs').fetchone()['n'],'failed_logins':c.execute("SELECT COUNT(*) n FROM audit_logs WHERE action='LOGIN' AND success=0").fetchone()['n'],'high_risk':c.execute('SELECT COUNT(*) n FROM audit_logs WHERE risk>=0.7').fetchone()['n'],'users':users,'registered_users':sessions}})
   if path.startswith('/api/security/alerts/') and method=='PATCH':
    u=self.auth(['admin']);
    if not u:return self.sendj(403,{'error':'Admin access required'})
    aid=path.rsplit('/',1)[-1];c.execute("UPDATE security_alerts SET status='Resolved' WHERE id=?",(aid,));c.commit();self.audit(u,'RESOLVE_SECURITY_ALERT',aid);return self.sendj(200,{'message':'Alert resolved'})
   if path=='/api/security/simulate' and method=='POST':
    u=self.auth(['admin']);
    if not u:return self.sendj(403,{'error':'Admin access required'})
    title=data.get('type','Suspicious endpoint probing');detail='Controlled demo simulation generated by administrator. Risk score: 0.97.';c.execute("INSERT INTO security_alerts(severity,title,detail,created_at,user_id) VALUES('Critical',?,?,?,?)",(title,detail,now(),u['sub']));c.execute('INSERT INTO audit_logs(user_id,action,resource,ip,success,risk,created_at) VALUES(?,?,?,?,?,?,?)',(u['sub'],'SIMULATED_INTRUSION',title,self.client_address[0],0,0.97,now()));c.commit();return self.sendj(201,{'message':'Security alert generated','risk':0.97})
   if path=='/api/hospitals' and method=='POST':
    u=self.auth(['hospital','admin']);
    if not u:return self.sendj(403,{'error':'Hospital staff access required'})
    required=['name','city','address','specialties','phone']
    if not all(data.get(k) for k in required):return self.sendj(400,{'error':'All hospital fields are required'})
    hid=c.execute('INSERT INTO hospitals(name,city,address,specialties,phone,created_at) VALUES(?,?,?,?,?,?)',(data['name'],data['city'],data['address'],data['specialties'],data['phone'],now())).lastrowid;c.commit();self.audit(u,'CREATE_HOSPITAL',str(hid));return self.sendj(201,{'id':hid})
   if path=='/api/donors' and method=='POST':
    u=self.auth(['patient','admin']);
    if not u:return self.sendj(403,{'error':'Patient login required'})
    if not all(data.get(k) for k in ('name','blood_group','city','phone')):return self.sendj(400,{'error':'Name, blood group, city and phone are required'})
    did=c.execute('INSERT INTO donors(name,blood_group,city,phone,user_id) VALUES(?,?,?,?,?)',(data['name'],data['blood_group'],data['city'],data['phone'],u['sub'])).lastrowid;c.commit();self.audit(u,'REGISTER_DONOR',str(did));return self.sendj(201,{'id':did})
   return self.sendj(404,{'error':'API endpoint not found'})
  except Exception as e:
   return self.sendj(500,{'error':'Internal server error','detail':str(e) if os.getenv('DEBUG')=='1' else 'Please check server logs.'})
  finally:c.close()
if __name__=='__main__':
 init_db(); port=int(os.getenv('PORT','8000')); print(f'MRITYUNJAY running at http://localhost:{port}'); ThreadingHTTPServer(('0.0.0.0',port),Handler).serve_forever()
