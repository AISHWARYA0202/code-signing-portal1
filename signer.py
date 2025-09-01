import os, subprocess
from datetime import datetime
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(APP_DIR, 'backend', 'certs')
UPLOADS_DIR = os.path.join(APP_DIR, 'uploads')
os.makedirs(CERTS_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

def run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or '') + (proc.stderr or '')
    return proc.returncode == 0, out.strip()

def generate_self_signed(meta, pfx_pass):
    priv = os.path.join(CERTS_DIR, f"{meta['CN']}.key")
    crt = os.path.join(CERTS_DIR, f"{meta['CN']}.crt")
    pfx = os.path.join(CERTS_DIR, f"{meta['CN']}.pfx")
    cnf = os.path.join(CERTS_DIR, f"{meta['CN']}_openssl.cnf")
    cfg = f"""[ req ]\ndistinguished_name = req_distinguished_name\nx509_extensions = v3_req\nprompt = no\n\n[ req_distinguished_name ]\nC = {meta.get('C','IN')}\nST = {meta.get('ST','State')}\nL = {meta.get('L','City')}\nO = {meta.get('O','MyCompany')}\nOU = {meta.get('OU','')}\nCN = {meta.get('CN','MyCompany')}\n\n[ v3_req ]\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature\nextendedKeyUsage = codeSigning\n"""
    with open(cnf,'w') as fh:
        fh.write(cfg)
    if not (os.path.exists(priv) and os.path.exists(crt)):
        ok, out = run(["openssl","req","-x509","-newkey","rsa:2048","-keyout",priv,"-out",crt,"-days",str(meta.get('days',730)),'-config',cnf,'-extensions','v3_req','-nodes'])
        if not ok:
            return False, out
    ok, out = run(["openssl","pkcs12","-export","-out",pfx,'-inkey',priv,'-in',crt,'-passout',f'pass:{pfx_pass}'])
    if not ok:
        return False, out
    ok, out = run(["openssl","x509","-in",crt,"-noout","-dates"])
    valid_from = valid_to = None
    if ok:
        for line in out.splitlines():
            if line.startswith('notBefore='): valid_from = line.split('=',1)[1].strip()
            if line.startswith('notAfter='): valid_to = line.split('=',1)[1].strip()
    return True, {'key_path':priv,'crt_path':crt,'pfx_path':pfx,'valid_from':valid_from,'valid_to':valid_to,'created_at':datetime.utcnow().isoformat()}

def sign_file(pfx, pfx_pass, target, signtool_path='signtool'):
    cmd = [signtool_path,'sign','/f',pfx,'/p',pfx_pass,'/fd','SHA256','/tr','http://timestamp.digicert.com','/td','SHA256', target]
    return run(cmd)

def verify_file(target, signtool_path='signtool'):
    return run([signtool_path,'verify','/pa', target])
