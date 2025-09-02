import os, json, hashlib
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

# ------------------- Helper -------------------
def compute_sha256(path):
    """Compute SHA-256 hash of a file at given path."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

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
    if u.get('role') == 'admin':
        uploaded = list(files_col.find({}).sort('uploaded_at', -1))
    else:
        uploaded = list(files_col.find({'uploader': u['username']}).sort('uploaded_at', -1))
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
        dest = os.path.join(UPLOAD_DIR, filename)
        f.save(dest)

        checksum_orig = compute_sha256(dest)

        files_col.insert_one({
            'filename': filename,
            'uploader': u['username'],
            'status': 'uploaded',
            'uploaded_at': datetime.utcnow().isoformat(),
            'checksum_original': checksum_orig
        })

        logs_col.insert_one({
            'username': u['username'],
            'action': 'upload',
            'filename': filename,
            'timestamp': datetime.utcnow().isoformat()
        })
        saved.append(filename)
    flash('Uploaded: '+', '.join(saved) if saved else 'No files uploaded')
    return redirect(url_for('files_page'))

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
    if u.get('role')!='admin' and cert_doc['created_by'] != u['username']:
        flash('You can only use your own certificates'); return redirect(url_for('files_page'))

    results=[]
    for fname in selected:
        path = os.path.join(UPLOAD_DIR, fname)
        if not os.path.exists(path):
            results.append(f'❌ {fname}: not found'); continue

        if u.get('role')!='admin':
            file_doc = files_col.find_one({'filename': fname})
            if not file_doc or file_doc.get('uploader') != u['username']:
                results.append(f'❌ {fname}: you can only sign files you uploaded')
                continue

        ok,out = signer.sign_file(cert_doc['pfx_path'], pfx_password, path)

        # Compute signed checksum
        signed_path = path
        if ok:
            if isinstance(out, dict) and out.get('signed_path'):
                signed_path = out.get('signed_path')
            elif isinstance(out, str) and os.path.exists(out):
                signed_path = out

        checksum_signed = compute_sha256(signed_path) if os.path.exists(signed_path) else None

        update_fields = {
            'status': 'signed' if ok else 'failed',
            'signed_at': datetime.utcnow().isoformat(),
            'signed_with': cert_doc['_id']
        }
        if checksum_signed:
            update_fields['checksum_signed'] = checksum_signed

        files_col.update_one({'filename': fname}, {"$set": update_fields})

        logs_col.insert_one({
            'username': u['username'],
            'action': 'sign',
            'filename': fname,
            'cert_cn': cert_doc['cn'],
            'success': ok,
            'timestamp': datetime.utcnow().isoformat(),
            'checksum_signed': checksum_signed if ok else None
        })

        results.append(('✅' if ok else '❌')+f' Sign {fname}:\n{out}')

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
        if not os.path.exists(path):
            results.append(f'❌ {fname}: not found'); continue

        if u.get('role')!='admin':
            file_doc = files_col.find_one({'filename': fname})
            if not file_doc or file_doc.get('uploader') != u['username']:
                results.append(f'❌ {fname}: you can only verify files you uploaded')
                continue

        ok,out = signer.verify_file(path)

        # Checksum verification
        file_doc = files_col.find_one({'filename': fname})
        current_hash = compute_sha256(path)
        expected_hash = file_doc.get('checksum_signed') if file_doc.get('status')=='signed' else file_doc.get('checksum_original')

        if expected_hash:
            checksum_ok = current_hash.lower() == expected_hash.lower()
            checksum_msg = ' | Checksum OK' if checksum_ok else f' | Checksum MISMATCH (expected {expected_hash[:12]}..., got {current_hash[:12]}...)'
        else:
            checksum_ok = False
            checksum_msg = ' | No stored checksum to compare'

        results.append(('✅' if ok else '❌')+f' Verify {fname}:\n{out}' + checksum_msg)

        logs_col.insert_one({
            'username': u['username'],
            'action': 'verify',
            'filename': fname,
            'success': ok,
            'checksum_ok': checksum_ok,
            'timestamp': datetime.utcnow().isoformat()
        })

    for r in results: flash(r)
    return redirect(url_for('files_page'))

# ------------------- Logs -------------------

@app.route('/logs')
@admin_required
def logs_page():
    q = list(logs_col.find({}).sort('timestamp', -1).limit(500))
    for log in q:
        log['_id'] = str(log['_id'])
        if 'signed_with' in log:
            log['signed_with'] = str(log['signed_with'])
    return render_template('logs.html', logs=q, user=current_user())

# ------------------- Downloads -------------------

@app.route('/uploads/<path:filename>')
@login_required
def download_upload(filename):
    u = current_user()
    if u.get('role') != 'admin':
        file_doc = files_col.find_one({'filename': filename})
        if not file_doc or file_doc.get('uploader') != u['username']:
            flash('You can only download files you uploaded')
            return redirect(url_for('files_page'))
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)

@app.route('/files/compare', methods=['POST'])
@login_required
def files_compare():
    local_file = request.files.get('local_file')
    signed_filename = request.form.get('signed_filename')
    results = []
    u = current_user()

    if not local_file or not signed_filename:
        flash('Please select both local file and signed file'); 
        return redirect(url_for('files_page'))

    # Save uploaded local file temporarily
    temp_path = os.path.join(UPLOAD_DIR, f"temp_{secure_filename(local_file.filename)}")
    local_file.save(temp_path)
    local_hash = compute_sha256(temp_path)

    # Fetch the signed file info
    file_doc = files_col.find_one({'filename': signed_filename})
    if not file_doc:
        flash('Selected signed file not found'); 
        os.remove(temp_path)
        return redirect(url_for('files_page'))

    expected_hash = file_doc.get('checksum_signed')
    if not expected_hash:
        flash('Signed checksum not available for this file'); 
        os.remove(temp_path)
        return redirect(url_for('files_page'))

    # Compare
    if local_hash.lower() == expected_hash.lower():
        flash(f'✅ Local file matches signed checksum for {signed_filename}')
    else:
        flash(f'❌ MISMATCH! Local file does not match signed checksum of {signed_filename} '
              f'(expected {expected_hash[:12]}..., got {local_hash[:12]}...)')

    # Clean up temp file
    os.remove(temp_path)
    return redirect(url_for('files_page'))

@app.route('/verify-integrity')
@login_required
def verify_integrity_page():
    u = current_user()
    # Show only signed files user can access
    if u.get('role') == 'admin':
        signed_files = list(files_col.find({'status':'signed'}))
    else:
        signed_files = list(files_col.find({'status':'signed','uploader': u['username']}))
    return render_template('verify_integrity.html', signed_files=signed_files, user=u)

@app.route('/verify-integrity', methods=['POST'])
@login_required
def verify_integrity():
    u = current_user()
    local_file = request.files.get('local_file')
    signed_filename = request.form.get('signed_filename')

    if not local_file or not signed_filename:
        flash('Please select a local file and a signed file.')
        return redirect(url_for('verify_integrity_page'))

    # Save local file temporarily
    temp_path = os.path.join(UPLOAD_DIR, secure_filename(local_file.filename))
    local_file.save(temp_path)

    # Get signed file from DB
    signed_doc = files_col.find_one({'filename': signed_filename})
    if not signed_doc or signed_doc.get('status') != 'signed':
        flash('Signed file not found.')
        os.remove(temp_path)
        return redirect(url_for('verify_integrity_page'))

    # Compute SHA-256 hashes
    local_hash = compute_sha256(temp_path)
    signed_hash = signed_doc.get('checksum_signed') or signed_doc.get('checksum_original')

    if local_hash.lower() == signed_hash.lower():
        flash(f'✅ Integrity OK! Hash: {local_hash[:16]}...')
    else:
        flash(f'❌ Integrity MISMATCH! Local: {local_hash[:16]}..., Expected: {signed_hash[:16]}...')

    os.remove(temp_path)
    return redirect(url_for('verify_integrity_page'))


# ------------------- Main -------------------

if __name__=='__main__':
    app.run(debug=True)
