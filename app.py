import os, json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from backend.mongo import init_app as init_mongo
from backend import signer

app = Flask(__name__)
app.secret_key = 'dev-change-me'
app.config['MONGO_URI'] = os.environ.get('MONGO_URI','mongodb://localhost:27017/code_signing_portal')
mongo = init_mongo(app)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(APP_DIR, 'uploads')
CERTS_DIR = os.path.join(APP_DIR, 'backend', 'certs')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CERTS_DIR, exist_ok=True)

users = mongo.db.users
files_col = mongo.db.files
certs_col = mongo.db.certs
logs_col = mongo.db.logs

# create default admin
if users.count_documents({}) == 0:
    users.insert_one({'username':'admin','password_hash':generate_password_hash('admin'),'role':'admin','created_at':datetime.utcnow().isoformat()})
    print('Default admin created: admin/admin')

def current_user():
    uname = session.get('username')
    if not uname:
        return None
    return users.find_one({'username':uname})

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **k):
        if not session.get('username'):
            return redirect(url_for('login'))
        return fn(*a, **k)
    return wrapper

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **k):
        u = current_user()
        if not u or u.get('role')!='admin':
            flash('Admin access required.')
            return redirect(url_for('index'))
        return fn(*a, **k)
    return wrapper

# ------------------- Routes -------------------

@app.route('/')
def index():
    has_cert = certs_col.count_documents({})>0
    return render_template('index.html', has_cert=has_cert, user=current_user())

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        uname = request.form.get('username'); pwd = request.form.get('password')
        u = users.find_one({'username':uname})
        if u and check_password_hash(u['password_hash'], pwd):
            session['username']=uname; flash('Logged in'); return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html', user=current_user())

@app.route('/logout')
def logout():
    session.clear(); flash('Logged out'); return redirect(url_for('index'))

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        uname = request.form.get('username')
        pwd = request.form.get('password')
        pwd2 = request.form.get('password2')

        if not uname or not pwd or not pwd2:
            flash('All fields are required')
            return redirect(url_for('signup'))

        if pwd != pwd2:
            flash('Passwords do not match')
            return redirect(url_for('signup'))

        if users.find_one({'username': uname}):
            flash('Username already exists')
            return redirect(url_for('signup'))

        users.insert_one({
            'username': uname,
            'password_hash': generate_password_hash(pwd),
            'role': 'user',
            'created_at': datetime.utcnow().isoformat()
        })
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))

    return render_template('signup.html', user=current_user())

# ------------------- Certificates -------------------

@app.route('/certs')
@login_required
def certs():
    u = current_user()
    if u.get('role')=='admin':
        certs = list(certs_col.find({}))
    else:
        certs = list(certs_col.find({'created_by': u['username']}))
    return render_template('certs.html', certs=certs, user=u)

@app.route('/certs/generate', methods=['POST'])
@login_required
def certs_generate():
    u = current_user()
    body = {
        'C':request.form.get('C','IN'),
        'ST':request.form.get('ST','State'),
        'L':request.form.get('L','City'),
        'O':request.form.get('O','MyCompany'),
        'OU':request.form.get('OU',''),
        'CN':request.form.get('CN','MyCompany'),
        'days':int(request.form.get('days',730))
    }
    pfx_password = request.form.get('pfx_password','')
    if not pfx_password:
        flash('PFX password required'); return redirect(url_for('certs'))

    ok,res = signer.generate_self_signed(body, pfx_password)
    if not ok: flash('Cert generation failed: '+str(res)); return redirect(url_for('certs'))

    doc={'cn':body['CN'],'meta':body,'pfx_path':res['pfx_path'],'crt_path':res['crt_path'],
         'valid_from':res['valid_from'],'valid_to':res['valid_to'],'created_by':u['username'],
         'created_at':res['created_at']}
    certs_col.insert_one(doc)
    logs_col.insert_one({'username':u['username'],'action':'generate_cert','cert_cn':body['CN'],'timestamp':datetime.utcnow().isoformat()})
    flash('Certificate generated'); return redirect(url_for('certs'))

@app.route('/certs/download/<id>/<kind>')
@login_required
def certs_download(id, kind):
    import bson
    doc = certs_col.find_one({'_id':bson.ObjectId(id)})
    if not doc: flash('Not found'); return redirect(url_for('certs'))

    u = current_user()
    if u.get('role')!='admin' and doc['created_by'] != u['username']:
        flash('You can only download your own certificates'); return redirect(url_for('certs'))

    path = doc['pfx_path'] if kind=='pfx' else doc['crt_path']
    if not os.path.exists(path): flash('Missing on disk'); return redirect(url_for('certs'))
    return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True)

# ------------------- Files -------------------

@app.route('/files')
@login_required
def files_page():
    u = current_user()
    uploaded = list(files_col.find({}).sort('uploaded_at', -1))
    certs_list = list(certs_col.find({})) if u.get('role')=='admin' else list(certs_col.find({'created_by': u['username']}))
    return render_template('files.html', files=uploaded, certs=certs_list, user=u)

@app.route('/files/upload', methods=['POST'])
@login_required
def files_upload():
    filesx = request.files.getlist('files'); saved=[]
    u = current_user()
    for f in filesx:
        if not f or f.filename=='': continue
        filename = secure_filename(f.filename)
        dest = os.path.join(UPLOAD_DIR, filename); f.save(dest)
        files_col.insert_one({
            'filename':filename,
            'uploader':u['username'],
            'status':'uploaded',
            'uploaded_at':datetime.utcnow().isoformat()
        })
        logs_col.insert_one({'username':u['username'],'action':'upload','filename':filename,'timestamp':datetime.utcnow().isoformat()})
        saved.append(filename)
    flash('Uploaded: '+', '.join(saved) if saved else 'No files uploaded'); return redirect(url_for('files_page'))

@app.route('/files/sign', methods=['POST'])
@login_required
def files_sign():
    cert_id = request.form.get('cert_id')
    pfx_password = request.form.get('pfx_password')
    selected = request.form.getlist('selected_files')

    import bson
    cert_doc = certs_col.find_one({'_id':bson.ObjectId(cert_id)}) if cert_id else None
    if not cert_doc: flash('Select a certificate'); return redirect(url_for('files_page'))

    u = current_user()
    # Users can only use their own certificates
    if u.get('role')!='admin' and cert_doc['created_by'] != u['username']:
        flash('You can only use your own certificates'); return redirect(url_for('files_page'))

    results=[]
    for fname in selected:
        path = os.path.join(UPLOAD_DIR, fname)
        if not os.path.exists(path): results.append(f'❌ {fname}: not found'); continue
        ok,out = signer.sign_file(cert_doc['pfx_path'], pfx_password, path)
        results.append(('✅' if ok else '❌')+f' Sign {fname}:\n{out}')
        files_col.update_one({'filename':fname},{"$set":{
            'status':'signed' if ok else 'failed',
            'signed_at':datetime.utcnow().isoformat(),
            'signed_with':cert_doc['_id']
        }})
        logs_col.insert_one({
            'username':u['username'],
            'action':'sign',
            'filename':fname,
            'cert_cn':cert_doc['cn'],
            'success':ok,
            'timestamp':datetime.utcnow().isoformat()
        })
    for r in results: flash(r)
    return redirect(url_for('files_page'))

@app.route('/files/verify', methods=['POST'])
@login_required
def files_verify():
    selected = request.form.getlist('selected_files')
    results=[]
    u = current_user()
    for fname in selected:
        path = os.path.join(UPLOAD_DIR, fname)
        if not os.path.exists(path): results.append(f'❌ {fname}: not found'); continue
        ok,out = signer.verify_file(path)
        results.append(('✅' if ok else '❌')+f' Verify {fname}:\n{out}')
        logs_col.insert_one({
            'username':u['username'],
            'action':'verify',
            'filename':fname,
            'success':ok,
            'timestamp':datetime.utcnow().isoformat()
        })
    for r in results: flash(r)
    return redirect(url_for('files_page'))

# ------------------- Logs -------------------

@app.route('/logs')
@admin_required
def logs_page():
    q = list(logs_col.find({}).sort('timestamp', -1).limit(500))
    # Convert ObjectId fields to strings
    for log in q:
        log['_id'] = str(log['_id'])
        if 'signed_with' in log:
            log['signed_with'] = str(log['signed_with'])
    return render_template('logs.html', logs=q, user=current_user())

# ------------------- Downloads -------------------

@app.route('/uploads/<path:filename>')
@login_required
def download_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)

# ------------------- Main -------------------

if __name__=='__main__':
    app.run(debug=True)
