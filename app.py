from flask import Flask, render_template, abort, request, redirect, url_for, session, send_file, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import re
import os
import random
import qrcode
import io
import json
import string
from itsdangerous import URLSafeTimedSerializer
from email_utils import send_verification_email, send_notification_email
import base64
import stripe



app = Flask(__name__)
app.secret_key = 'supersegreto'
DB_PATH = 'qr.db'
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_MINUTES = 10

stripe.api_key = "sk_test_51RaOFfRxgvcW18MKxc3viUTswrl71pvrfJbNzexuKaSJ7RkafxBSSlMnt86lkIHDRRSbSUw8iO4tSIrTEFm4NllW00khK2Arkj"  # La tua secret key Stripe
STRIPE_PUBLISHABLE_KEY = "pk_test_51RaOFfRxgvcW18MKRVjW7UmUZD28DNwrNGBjhZYAUQaPQv6sc54uQLUtxHxJTNaKVvYroffWkP41x46qhvJV0Lsh00DH0fGcnf" 

app.jinja_env.filters['b64encode'] = lambda data: base64.b64encode(data).decode('utf-8')

# Serializer per token email
s = URLSafeTimedSerializer(app.secret_key)

def send_zone_access_notification(qr_id, zone_name):
    # Recupera email del proprietario del QR dal database
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('''
        SELECT users.email, users.nome, users.cognome
        FROM qr_codes
        JOIN users ON qr_codes.user_id = users.id
        WHERE qr_codes.id = ?
    ''', (qr_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return  # Nessun proprietario trovato, non inviare nulla

    email_dest, nome, cognome = row
    subject = f"[HouseQR] Accesso a zona privata '{zone_name}'"
    body = (
        f"Ciao {nome} {cognome},\n\n"
        f"La zona privata '{zone_name}' del tuo QR code (ID: {qr_id}) è stata appena consultata.\n\n"
        "Se non sei stato tu, verifica subito la sicurezza del tuo account.\n\n"
        "HouseQR"
    )
    send_notification_email(email_dest, subject, body)


def genera_codice_verifica():
    return ''.join(random.choices(string.digits, k=6))

# --- Funzioni di utilità ---

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, password FROM users WHERE username = ?', (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {'id': row[0], 'username': row[1], 'password': row[2]}
    return None

def get_user_by_email(email):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE email = ?', (email,))
    row = c.fetchone()
    conn.close()
    return row
    
def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, password, is_admin FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'id': row[0],
            'username': row[1],
            'password': row[2],
            'is_admin': row[3]
        }
    return None

    
def is_admin():
    # Sostituisci con il tuo controllo di sessione/admin
    return session.get('is_admin', False)

def get_user_by_identifier(identifier):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, password, email, email_verificata FROM users WHERE username = ? OR email = ?', (identifier, identifier))
    row = c.fetchone()
    conn.close()
    if row:
        return {'id': row[0], 'username': row[1], 'password': row[2], 'email': row[3], 'email_verificata': row[4]}
    return None
    

def get_qr_data(qr_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT qr_codes.pubblico, qr_codes.privato, qr_codes.privato_password, users.nome, users.cognome
        FROM qr_codes
        LEFT JOIN users ON qr_codes.user_id = users.id
        WHERE qr_codes.id = ?
    ''', (qr_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'pubblico': row[0],
            'privato': row[1],
            'privato_password': row[2],
            'nome': row[3] or '',
            'cognome': row[4] or ''
        }
    else:
        return None
        
def send_order_confirmation(email, order_id, prodotti, totale):
    subject = f"Conferma ordine HouseQR {order_id}"
    body = f"Ciao!\n\nGrazie per il tuo acquisto su HouseQR.\n\n"
    body += f"Codice ordine: {order_id}\n\n"
    body += "Riepilogo ordine:\n"
    for p in prodotti:
        body += f"- {p['nome']} x {p['quantita']} = €{p['prezzo']*p['quantita']:.2f}\n"
    body += f"\nTotale ordine: €{totale:.2f}\n\n"
    body += "Riceverai presto ulteriori dettagli per la spedizione o l’attivazione.\n\n"
    body += "Grazie!\nIl team HouseQR"
    send_notification_email(email, subject, body)
    
def update_qr_data(qr_id, pubblico, privato):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE qr_codes SET pubblico = ?, privato = ? WHERE id = ?', (pubblico, privato, qr_id))
    conn.commit()
    conn.close()

def get_qr_stats(qr_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*), MAX(data_ora) FROM scansioni WHERE qr_id = ?', (qr_id,))
    count, last_scan = c.fetchone()
    conn.close()
    return {'scansioni': count, 'ultima_scansione': last_scan}

def registra_scansione(qr_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO scansioni (qr_id, data_ora, user_agent, ip) VALUES (?, ?, ?, ?)',
              (qr_id, datetime.now(), request.headers.get('User-Agent'), request.remote_addr))
    conn.commit()
    conn.close()

def log_access(user_id, action, qr_id=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO audit_log (user_id, action, qr_id, timestamp, ip) VALUES (?, ?, ?, ?, ?)',
              (user_id, action, qr_id, datetime.now(), request.remote_addr))
    conn.commit()
    conn.close()

def password_valida(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password)
    )
    
def genera_id_qr(length=6):
    return ''.join(random.choices(string.digits, k=length))

def genera_codice_segreto(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

def send_2fa_email(to_email, code):
    subject = "Il tuo codice di accesso HouseQR"
    body = f"Il tuo codice di accesso è: {code}\n\nSe non hai richiesto l'accesso, ignora questa email."
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = to_email

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, [to_email], msg.as_string())
    except Exception as e:
        print("Errore invio email 2FA:", e)

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/add_qr', methods=['GET', 'POST'])
def add_qr():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = None
    error = None
    if request.method == 'POST':
        codice = request.form['codice_segreto'].strip()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, user_id FROM qr_codes WHERE codice_segreto = ?', (codice,))
        row = c.fetchone()
        if not row:
            error = "Codice segreto non valido."
        elif row[1] is not None:
            error = "Questo QR code è già stato associato a un altro account."
        else:
            # Associa il QR code all'utente loggato
            c.execute('UPDATE qr_codes SET user_id = ? WHERE codice_segreto = ?', (session['user_id'], codice))
            conn.commit()
            message = "QR code aggiunto correttamente al tuo account!"
        conn.close()
    return render_template('add_qr.html', message=message, error=error)

    
@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    error = None
    if 'pending_2fa' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        code = request.form['code']
        if code == session.get('2fa_code'):
            user_id = session['pending_2fa']
            # Recupera l'utente dal database
            user = get_user_by_id(user_id)
            if not user:
                error = "Utente non trovato."
                return render_template('two_factor.html', error=error)
            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])
            session['username'] = session.get('pending_2fa_username')
            # Pulisci la sessione temporanea
            session.pop('pending_2fa')
            session.pop('pending_2fa_username')
            session.pop('2fa_code')
            return redirect(url_for('user_dashboard'))
        else:
            error = "Codice errato. Riprova."
    return render_template('two_factor.html', error=error)



@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    now = datetime.now(timezone.utc)
    blocked_until = session.get('login_blocked_until')
    if blocked_until and isinstance(blocked_until, str):
        blocked_until = datetime.fromisoformat(blocked_until)
    if blocked_until and now < blocked_until:
        minutes = int((blocked_until - now).total_seconds() // 60) + 1
        error = f"Troppi tentativi falliti. Riprova tra {minutes} minuti."
        return render_template('login.html', error=error)

    if request.method == 'POST':
        identifier = request.form.get('identifier')
        password = request.form.get('password')
        user = get_user_by_identifier(identifier)
        if user and check_password_hash(user['password'], password):
            # 2FA: invia codice a 6 cifre
            code = ''.join(random.choices(string.digits, k=6))
            session['pending_2fa'] = user['id']
            session['pending_2fa_username'] = user['username']
            session['2fa_code'] = code
            from email_utils import send_2fa_email
            send_2fa_email(user['email'], code)
            # Puoi aggiungere qui un messaggio di successo opzionale
            return redirect(url_for('two_factor'))
        else:
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                session['login_blocked_until'] = (now + timedelta(minutes=LOGIN_BLOCK_MINUTES)).isoformat()
                error = f"Troppi tentativi falliti. Riprova tra {LOGIN_BLOCK_MINUTES} minuti."
                log_access(user['id'] if user else None, 'login_blocked')
            else:
                error = "Credenziali errate!"
                log_access(user['id'] if user else None, 'login_failed')
    return render_template('login.html', error=error)



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        nome = request.form['nome']
        cognome = request.form['cognome']
        indirizzo = request.form['indirizzo']
        telefono = request.form['telefono']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        if get_user_by_username(username):
            error = "Username già registrato."
            return render_template('register.html', error=error)
        if get_user_by_email(email):
            error = "Email già registrata."
            return render_template('register.html', error=error)
        hashed_pw = generate_password_hash(password)
        # Salva i dati temporaneamente nel token per la verifica email
        token = s.dumps({
            'nome': nome,
            'cognome': cognome,
            'indirizzo': indirizzo,
            'telefono': telefono,
            'email': email,
            'username': username,
            'password': hashed_pw
        }, salt='email-confirm')
        verify_url = url_for('verify_email_token', token=token, _external=True)
        send_verification_email(email, verify_url)
        flash("Controlla la tua email e clicca sul link di verifica per completare la registrazione.", "success")
        return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email_form():
    # (Implementa qui la verifica via codice se vuoi)
    return render_template('verify_email.html')
    
@app.route('/admin/qr-list')
def admin_qr_list():
    if not session.get('is_admin'):
        abort(403)
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Prendi la mail invece dello username
    c.execute('''
        SELECT q.id, q.codice_segreto, u.email
        FROM qr_codes q
        LEFT JOIN users u ON q.user_id = u.id
        ORDER BY q.id DESC
    ''')
    qr_list = [
        {
            'id': row[0],
            'codice_segreto': row[1],
            'email': row[2] if row[2] else '-'
        }
        for row in c.fetchall()
    ]
    conn.close()
    return render_template('admin_qr_list.html', qr_list=qr_list)

@app.route('/account/delete', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        abort(403)
    user_id = session['user_id']
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Recupera email prima di eliminare
    c.execute('SELECT email FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    email = row[0] if row else None

    # Elimina l'utente
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    # Se vuoi anche eliminare i QR associati all'utente, decommenta la riga sotto:
    # c.execute('DELETE FROM qr_codes WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    session.clear()

    # Invia email di conferma eliminazione
    if email:
        subject = "Eliminazione account HouseQR"
        body = (
            "Ciao,\n\n"
            "Il tuo account su HouseQR è stato eliminato con successo.\n"
            "Se non sei stato tu a richiedere questa azione, contattaci immediatamente.\n\n"
            "Grazie per aver utilizzato HouseQR!\n"
            "Il team HouseQR"
        )
        try:
            send_notification_email(email, subject, body)
        except Exception as e:
            print("Errore invio email:", e)

    flash("Il tuo account è stato eliminato con successo.", "success")
    return redirect(url_for('index'))

    
@app.route('/admin/user-delete/<int:user_id>', methods=['POST'])
def admin_user_delete(user_id):
    if not session.get('is_admin'):
        abort(403)
    # Proteggi: non permettere di eliminare se stesso o l'ultimo admin
    if user_id == session.get('user_id'):
        flash("Non puoi eliminare il tuo stesso account admin!", "error")
        return redirect(url_for('admin_users'))
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Opzionale: controlla se è l'ultimo admin
    c.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1')
    admin_count = c.fetchone()[0]
    c.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
    row = c.fetchone()
    if row and row[0] == 1 and admin_count <= 1:
        conn.close()
        flash("Non puoi eliminare l'ultimo account admin!", "error")
        return redirect(url_for('admin_users'))
    # Elimina l'utente
    c.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash("Account eliminato con successo.", "success")
    return redirect(url_for('admin_users'))
    
@app.route('/admin/users')
def admin_users():
    if not session.get('is_admin'):
        abort(403)
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Prendi tutti gli utenti, senza password
    c.execute('SELECT id, username, email, is_admin FROM users ORDER BY id')
    users = [
        {
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'is_admin': bool(row[3])
        }
        for row in c.fetchall()
    ]
    conn.close()
    return render_template('admin_users.html', users=users)


@app.route('/admin/qr-delete/<qr_id>', methods=['POST'])
def admin_qr_delete(qr_id):
    if not session.get('is_admin'):
        abort(403)
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('DELETE FROM qr_codes WHERE id = ?', (qr_id,))
    conn.commit()
    conn.close()
    flash(f"QR {qr_id} eliminato con successo.", "success")
    return redirect(url_for('admin_qr_list'))

@app.route('/admin/qr', methods=['GET', 'POST'])
def admin_qr():
    if not session.get('is_admin'):
        abort(403)

    qr_img_data = None
    qr_id = None
    codice_segreto = None
    qr_link = None

    if request.method == 'POST' and session.get('user_id'):
        # Genera ID e codice segreto unici
        while True:
            qr_id = genera_id_qr(6)
            codice_segreto = genera_codice_segreto(12)
            conn = sqlite3.connect('qr.db')
            c = conn.cursor()
            c.execute('SELECT 1 FROM qr_codes WHERE id = ?', (qr_id,))
            exists = c.fetchone()
            conn.close()
            if not exists:
                break  # ID unico trovato

        # Salva nel database
        conn = sqlite3.connect('qr.db')
        c = conn.cursor()
        c.execute('INSERT INTO qr_codes (id, codice_segreto, user_id) VALUES (?, ?, NULL)', (qr_id, codice_segreto))
        conn.commit()
        conn.close()

        # Crea link HouseQR
        qr_link = url_for('view_qr', qr_id=qr_id, _external=True)

        # Genera QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qr_img_data = base64.b64encode(buf.read()).decode('utf-8')

    return render_template('admin_qr_auto.html',
                           qr_img_data=qr_img_data,
                           qr_id=qr_id,
                           codice_segreto=codice_segreto,
                           qr_link=qr_link)


@app.route('/qr/<qr_id>/private', methods=['GET', 'POST'])
def qr_privato(qr_id):
    error = None
    privato = None
    if request.method == 'POST':
        password_inserita = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT privato, privato_password FROM qr_codes WHERE id = ?', (qr_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            error = "QR code non trovato."
        else:
            privato, hash_pw = row
            if check_password_hash(hash_pw, password_inserita):
                # Mostra il messaggio privato
                return render_template('qr_privato.html', privato=privato)
            else:
                error = "Password errata."
    return render_template('qr_privato_login.html', error=error)
    
@app.route('/verify_email/<token>')
def verify_email_token(token):
    try:
        data = s.loads(token, salt='email-confirm', max_age=3600)
    except Exception:
        flash("Link di verifica non valido o scaduto.", "danger")
        return redirect(url_for('register'))
    nome = data['nome']
    cognome = data['cognome']
    indirizzo = data['indirizzo']
    telefono = data['telefono']
    email = data['email']
    username = data['username']
    hashed_pw = data['password']

    # Controlla che l'utente non sia già registrato
    if get_user_by_username(username) or get_user_by_email(email):
        flash("Utente già registrato.", "danger")
        return redirect(url_for('login'))

    # Inserisci nel database con is_admin = 0
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute(
        "INSERT INTO users (nome, cognome, indirizzo, telefono, email, username, password, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        (nome, cognome, indirizzo, telefono, email, username, hashed_pw)
    )
    conn.commit()
    conn.close()
    flash("Registrazione completata! Ora puoi accedere.", "success")
    return redirect(url_for('login'))



@app.route('/account', methods=['GET', 'POST'])
def account_panel():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT nome, cognome, email, telefono, indirizzo, username FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    c.execute('SELECT COUNT(*) FROM qr_codes WHERE user_id = ?', (user_id,))
    qr_count = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM scansioni WHERE qr_id IN (SELECT id FROM qr_codes WHERE user_id = ?)', (user_id,))
    scansioni_totali = c.fetchone()[0]
    c.execute('SELECT MAX(data_ora) FROM scansioni WHERE qr_id IN (SELECT id FROM qr_codes WHERE user_id = ?)', (user_id,))
    ultima_attivita = c.fetchone()[0]
    conn.close()
    success = None
    error = None
    if request.method == 'POST' and request.form.get('action') == 'update_personal':
        nuovo_nome = request.form['nome']
        nuovo_cognome = request.form['cognome']
        nuovo_telefono = request.form['telefono']
        nuovo_indirizzo = request.form['indirizzo']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE users SET nome=?, cognome=?, telefono=?, indirizzo=? WHERE id=?',
                  (nuovo_nome, nuovo_cognome, nuovo_telefono, nuovo_indirizzo, user_id))
        conn.commit()
        conn.close()
        success = "Dati personali aggiornati con successo!"
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT nome, cognome, email, telefono, indirizzo, username FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
    if request.method == 'POST' and request.form.get('action') == 'change_password':
        old_pw = request.form['old_password']
        new_pw = request.form['new_password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE id = ?', (user_id,))
        current_pw_hash = c.fetchone()[0]
        if not check_password_hash(current_pw_hash, old_pw):
            error = "La password attuale non è corretta."
        elif not password_valida(new_pw):
            error = "La nuova password deve essere lunga almeno 8 caratteri, contenere una maiuscola, una minuscola e un numero."
        else:
            new_pw_hash = generate_password_hash(new_pw)
            c.execute('UPDATE users SET password=? WHERE id=?', (new_pw_hash, user_id))
            conn.commit()
            success = "Password aggiornata con successo!"
        conn.close()
    return render_template(
        'account_panel.html',
        user=user,
        qr_count=qr_count,
        scansioni_totali=scansioni_totali,
        ultima_attivita=ultima_attivita,
        success=success,
        error=error
    )

@app.route('/chi-siamo')
def chi_siamo():
    return render_template('chi_siamo.html', current_year=datetime.now().year)

@app.route('/checkout/address', methods=['GET', 'POST'])
def checkout_address():
    if request.method == 'POST':
        dati = {
            'nome': request.form.get('nome', '').strip(),
            'cognome': request.form.get('cognome', '').strip(),
            'via': request.form.get('via', '').strip(),
            'civico': request.form.get('civico', '').strip(),
            'citta': request.form.get('citta', '').strip(),
            'cap': request.form.get('cap', '').strip(),
            'provincia': request.form.get('provincia', '').strip(),
            'stato': request.form.get('stato', '').strip(),
        }
        # Validazione base
        if not all(dati.values()):
            flash("Compila tutti i campi!", "error")
            return render_template('checkout_address.html', dati=dati)
        session['indirizzo_spedizione'] = dati
        return redirect(url_for('checkout'))
    return render_template('checkout_address.html', dati={})


@app.route('/update_order_status/<order_id>', methods=['POST'])
def update_order_status(order_id):
    new_status = request.form.get('status')
    if new_status not in ['ricevuto', 'in elaborazione', 'spedito', 'completato']:
        flash('Status non valido.', 'error')
        return redirect(url_for('admin_orders'))

    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('UPDATE shop_orders SET status = ? WHERE order_id = ?', (new_status, order_id))
    conn.commit()

    # Recupera email, prodotti e indirizzo per invio email
    c.execute('SELECT email, prodotti, indirizzo FROM shop_orders WHERE order_id = ?', (order_id,))
    row = c.fetchone()
    conn.close()

    if row:
        email, prodotti_json, indirizzo = row
        prodotti = json.loads(prodotti_json)
        subject = f"Aggiornamento stato ordine {order_id}"
        body = f"Ciao,\n\nIl tuo ordine {order_id} è stato aggiornato allo stato: {new_status.upper()}.\n\n"
        body += f"Indirizzo di spedizione:\n{indirizzo}\n\nDettagli ordine:\n"
        for p in prodotti:
            body += f"- {p['nome']} x {p['quantita']}\n"
        body += "\nGrazie per aver scelto HouseQR!"
        from email_utils import send_notification_email
        try:
            send_notification_email(email, subject, body)
            flash('Email di aggiornamento inviata con successo.', 'success')
        except Exception as e:
            flash(f'Errore invio email: {e}', 'error')
    else:
        flash('Ordine non trovato.', 'error')

    return redirect(url_for('admin_orders'))

@app.route('/qr/<qr_id>/zone/<int:zone_id>', methods=['GET', 'POST'])
def qr_zone(qr_id, zone_id):
    error = None
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('SELECT zone_name, password_hash, message FROM qr_zones WHERE id = ? AND qr_id = ?', (zone_id, qr_id))
    zone = c.fetchone()
    conn.close()
    if not zone:
        return "Zona privata non trovata", 404

    zone_name, hash_pw, message = zone

    if request.method == 'POST':
        password = request.form['password']
        if check_password_hash(hash_pw, password):
            # Accesso consentito: mostra il messaggio riservato
            send_zone_access_notification(qr_id, zone_name)
            return render_template('zone_privata.html', zone_name=zone_name, message=message, qr_id=qr_id)
        else:
            error = "Password errata per questa zona."

    # Primo accesso o errore
    return render_template('zone_login.html', qr_id=qr_id, zone_id=zone_id, zone_name=zone_name, error=error)
    
@app.route('/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('''
        SELECT id, pubblico, scansioni, ultima_scansione, ricevi_messaggi
        FROM qr_codes
        WHERE user_id = ?
    ''', (session['user_id'],))
    qr_codes = [
        {
            'id': row[0],
            'pubblico': row[1],
            'scansioni': row[2] or 0,
            'ultima_scansione': row[3],
            'ricevi_messaggi': row[4]
        }
        for row in c.fetchall()
    ]

    conn.close()
    return render_template('user_dashboard.html', qr_codes=qr_codes)

@app.route('/dashboard/<qr_id>', methods=['GET', 'POST'])
def dashboard(qr_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Recupera dati QR
    c.execute('SELECT pubblico FROM qr_codes WHERE id = ? AND user_id = ?', (qr_id, session['user_id']))
    qr = c.fetchone()
    if not qr:
        conn.close()
        return "QR code non trovato o non autorizzato", 404

    # Recupera zone private associate
    c.execute('SELECT id, zone_name, message FROM qr_zones WHERE qr_id = ?', (qr_id,))
    zones = c.fetchall()
    max_zones = 3
    max_zones_reached = len(zones) >= max_zones

    error = None

    if request.method == 'POST':
        pubblico = request.form['pubblico']
        c.execute('UPDATE qr_codes SET pubblico = ? WHERE id = ?', (pubblico, qr_id))

        # Gestione zone esistenti e nuove
        zone_ids = request.form.getlist('zone_id[]')
        zone_names = request.form.getlist('zone_name[]')
        zone_passwords = request.form.getlist('zone_password[]')
        zone_messages = request.form.getlist('zone_message[]')

        # Conta quante zone effettive si stanno gestendo (escludendo nuove zone vuote)
        zone_count = 0
        for i in range(len(zone_ids)):
            zone_id = zone_ids[i]
            zone_name = zone_names[i].strip()
            zone_password = zone_passwords[i].strip()
            zone_message = zone_messages[i].strip()

            if zone_id == 'new':
                # Nuova zona: aggiungi solo se non superi il limite e i campi sono compilati
                if not max_zones_reached and zone_name and zone_password and zone_message:
                    zone_count += 1
                    hash_pw = generate_password_hash(zone_password)
                    c.execute('INSERT INTO qr_zones (qr_id, zone_name, password_hash, message) VALUES (?, ?, ?, ?)',
                              (qr_id, zone_name, hash_pw, zone_message))
            else:
                # Zona esistente: aggiorna se i campi sono compilati
                if zone_name and zone_message:
                    zone_count += 1
                    if zone_password:
                        hash_pw = generate_password_hash(zone_password)
                        c.execute('UPDATE qr_zones SET zone_name = ?, password_hash = ?, message = ? WHERE id = ?',
                                  (zone_name, hash_pw, zone_message, zone_id))
                    else:
                        c.execute('UPDATE qr_zones SET zone_name = ?, message = ? WHERE id = ?',
                                  (zone_name, zone_message, zone_id))

        # Dopo l'elaborazione, riconta le zone per sicurezza
        c.execute('SELECT COUNT(*) FROM qr_zones WHERE qr_id = ?', (qr_id,))
        total_zones = c.fetchone()[0]
        if total_zones > max_zones:
            error = f"Puoi avere al massimo {max_zones} zone private per ogni QR code."
            conn.rollback()
        else:
            conn.commit()
            conn.close()
            return redirect(url_for('user_dashboard'))

    conn.close()
    return render_template(
        'edit_qr.html',
        qr={'pubblico': qr[0]},
        zones=zones,
        error=error,
        max_zones_reached=max_zones_reached,
        max_zones=max_zones
    )

@app.route('/qr/<qr_id>')
def view_qr(qr_id):
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Recupera anche user_id per prendere nome e cognome
    c.execute('''
        SELECT pubblico, user_id, ricevi_messaggi
        FROM qr_codes
        WHERE id = ?
    ''', (qr_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return "QR non trovato", 404

    messaggio_pubblico, user_id, ricevi_messaggi = row

    # Recupera nome e cognome del proprietario
    c.execute('SELECT nome, cognome FROM users WHERE id = ?', (user_id,))
    user_row = c.fetchone()
    if user_row:
        nome, cognome = user_row
    else:
        nome, cognome = "Proprietario", ""

    # Recupera le zone private
    c.execute('SELECT id, zone_name FROM qr_zones WHERE qr_id = ?', (qr_id,))
    zones = c.fetchall()
    conn.close()

    return render_template(
        'public_view.html',
        qr_id=qr_id,
        nome=nome,
        cognome=cognome,
        messaggio_pubblico=messaggio_pubblico,
        ricevi_messaggi=ricevi_messaggi,
        zones=zones
    )

@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    cart = session.get('cart', {})
    cart[str(product_id)] = cart.get(str(product_id), 0) + 1
    session['cart'] = cart
    flash("Prodotto aggiunto al carrello!", "success")
    return redirect(url_for('shop'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    # 1. Controlla che l'indirizzo sia stato inserito nella sessione
    indirizzo = session.get('indirizzo_spedizione')
    if not indirizzo:
        flash("Devi prima inserire l'indirizzo di spedizione.", "error")
        return redirect(url_for('checkout_address'))

    # 2. Recupera il carrello
    cart = session.get('cart', {})
    if not cart:
        flash("Il carrello è vuoto.", "error")
        return redirect(url_for('view_cart'))

    # 3. Recupera i prodotti dal database
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    ids = tuple(map(int, cart.keys()))
    placeholders = ','.join('?' for _ in ids)
    c.execute(f"SELECT id, nome, prezzo FROM shop_products WHERE id IN ({placeholders})", ids)
    prodotti_db = {str(row[0]): row for row in c.fetchall()}
    conn.close()

    prodotti = []
    totale = 0.0
    line_items = []
    for pid, qty in cart.items():
        if pid in prodotti_db:
            id, nome, prezzo = prodotti_db[pid]
            prodotti.append({'nome': nome, 'quantita': qty, 'prezzo': prezzo})
            totale += prezzo * qty
            line_items.append({
                'price_data': {
                    'currency': 'eur',
                    'product_data': {'name': nome},
                    'unit_amount': int(prezzo * 100),
                },
                'quantity': qty,
            })

    # 4. Salva il riepilogo ordine in sessione per la pagina di successo
    session['last_order_products'] = prodotti
    session['last_order_total'] = totale

    # 5. Crea la sessione Stripe Checkout
    stripe.api_key = "sk_test_51RaOFfRxgvcW18MKxc3viUTswrl71pvrfJbNzexuKaSJ7RkafxBSSlMnt86lkIHDRRSbSUw8iO4tSIrTEFm4NllW00khK2Arkj"  # Sostituisci con la tua chiave segreta
    session_stripe = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=line_items,
        mode='payment',
        success_url=url_for('checkout_success', _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
        cancel_url=url_for('view_cart', _external=True),
        customer_email=None,  # Stripe chiederà l'email all'utente
    )
    return redirect(session_stripe.url)




@app.route('/checkout/success')
def checkout_success():
    # Genera codice ordine
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    order_id = f"ORD-{datetime.now().strftime('%Y%m%d')}-{code}"

    prodotti = session.get('last_order_products', [])
    totale = session.get('last_order_total', 0.0)
    indirizzo = session.get('indirizzo_spedizione', {})

    # Recupera email dal checkout session Stripe
    session_id = request.args.get('session_id')
    email = None
    if session_id:
        stripe.api_key = "sk_test_51RaOFfRxgvcW18MKxc3viUTswrl71pvrfJbNzexuKaSJ7RkafxBSSlMnt86lkIHDRRSbSUw8iO4tSIrTEFm4NllW00khK2Arkj"  # tua chiave segreta
        session_stripe = stripe.checkout.Session.retrieve(session_id)
        if session_stripe.customer_details:
            email = session_stripe.customer_details.email

    # Prepara indirizzo in formato leggibile
    indirizzo_str = (
        f"{indirizzo.get('nome', '')} {indirizzo.get('cognome', '')}, "
        f"{indirizzo.get('via', '')} {indirizzo.get('civico', '')}, "
        f"{indirizzo.get('cap', '')} {indirizzo.get('citta', '')} ({indirizzo.get('provincia', '')}), "
        f"{indirizzo.get('stato', '')}"
    )

    # Salva l'ordine nel database
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('''
        INSERT INTO shop_orders (order_id, email, prodotti, totale, indirizzo, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (order_id, email, json.dumps(prodotti), totale, indirizzo_str, 'ricevuto'))
    conn.commit()
    conn.close()

    # Invia email di conferma
    if email:
        from email_utils import send_notification_email
        subject = f"Conferma ordine HouseQR {order_id}"
        body = f"Ciao!\n\nGrazie per il tuo acquisto su HouseQR.\n\n" \
               f"Codice ordine: {order_id}\n" \
               f"Indirizzo di spedizione:\n{indirizzo_str}\n\n" \
               f"Riepilogo ordine:\n"
        for p in prodotti:
            body += f"- {p['nome']} x {p['quantita']} = €{p['prezzo']*p['quantita']:.2f}\n"
        body += f"\nTotale ordine: €{totale:.2f}\n\n"
        body += "Riceverai presto ulteriori dettagli per la spedizione o l’attivazione.\n\nGrazie!\nIl team HouseQR"
        try:
            send_notification_email(email, subject, body)
        except Exception as e:
            print("Errore invio email conferma ordine:", e)

    # Svuota il carrello e la sessione ordine
    session.pop('cart', None)
    session.pop('last_order_products', None)
    session.pop('last_order_total', None)
    session.pop('indirizzo_spedizione', None)

    return render_template('checkout_success.html',
                           order_id=order_id,
                           prodotti=prodotti,
                           totale=totale,
                           indirizzo=indirizzo_str)

@app.route('/admin/orders/<order_id>', methods=['GET', 'POST'])
def admin_order_detail(order_id):
    import json
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('SELECT order_id, email, prodotti, totale, indirizzo, data, status FROM shop_orders WHERE order_id = ?', (order_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        flash("Ordine non trovato.", "error")
        return redirect(url_for('admin_orders'))

    ordine = {
        'order_id': row[0],
        'email': row[1],
        'prodotti': json.loads(row[2]),
        'totale': row[3],
        'indirizzo': row[4],
        'data': row[5],
        'status': row[6]
    }

    if request.method == 'POST':
        new_status = request.form.get('status')
        if new_status not in ['ricevuto', 'in elaborazione', 'spedito', 'completato']:
            flash('Status non valido.', 'error')
            return redirect(url_for('admin_order_detail', order_id=order_id))
        conn = sqlite3.connect('qr.db')
        c = conn.cursor()
        c.execute('UPDATE shop_orders SET status = ? WHERE order_id = ?', (new_status, order_id))
        conn.commit()
        conn.close()
        # Invia email di aggiornamento come già fatto prima...
        flash('Stato ordine aggiornato.', 'success')
        return redirect(url_for('admin_order_detail', order_id=order_id))

    return render_template('admin_order_detail.html', ordine=ordine)

@app.route('/shop/product/<int:product_id>/review', methods=['POST'])
def add_review(product_id):
    if not session.get('user_id'):
        flash("Devi essere loggato per lasciare una recensione.", "error")
        return redirect(url_for('product_detail', product_id=product_id))
    rating = int(request.form.get('rating', 0))
    comment = request.form.get('comment', '').strip()
    if rating < 1 or rating > 5 or not comment:
        flash("Valutazione e commento obbligatori.", "error")
        return redirect(url_for('product_detail', product_id=product_id))
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Controlla se già recensito da questo utente
    c.execute('SELECT id FROM shop_reviews WHERE product_id=? AND user_id=?', (product_id, session['user_id']))
    if c.fetchone():
        flash("Hai già recensito questo prodotto.", "error")
        conn.close()
        return redirect(url_for('product_detail', product_id=product_id))
    c.execute('INSERT INTO shop_reviews (product_id, user_id, username, rating, comment) VALUES (?, ?, ?, ?, ?)',
        (product_id, session['user_id'], session.get('username'), rating, comment))
    conn.commit()
    conn.close()
    flash("Recensione aggiunta con successo!", "success")
    return redirect(url_for('product_detail', product_id=product_id))
    

@app.route('/shop/product/<int:product_id>')
def product_detail(product_id):
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('SELECT id, nome, descrizione, prezzo, immagine FROM shop_products WHERE id = ?', (product_id,))
    prod = c.fetchone()
    # Carica recensioni
    c.execute('SELECT username, rating, comment, data FROM shop_reviews WHERE product_id=? ORDER BY data DESC', (product_id,))
    reviews = c.fetchall()
    # Calcola media stelle
    c.execute('SELECT AVG(rating) FROM shop_reviews WHERE product_id=?', (product_id,))
    avg_rating = c.fetchone()[0]
    conn.close()
    return render_template('product_detail.html', prodotto=prod, reviews=reviews, avg_rating=avg_rating)




@app.route('/admin/orders')
def admin_orders():
    # Filtro per status e ordinamento
    status_filter = request.args.get('status', 'tutti')
    order_by = request.args.get('order_by', 'data_desc')

    # Query base
    query = 'SELECT order_id, data, status FROM shop_orders'
    params = []
    if status_filter != 'tutti':
        query += ' WHERE status = ?'
        params.append(status_filter)
    # Ordinamento: per status e data, oppure solo data
    if order_by == 'status':
        query += ' ORDER BY CASE status ' \
                 "WHEN 'ricevuto' THEN 1 " \
                 "WHEN 'in elaborazione' THEN 2 " \
                 "WHEN 'spedito' THEN 3 " \
                 "WHEN 'completato' THEN 4 " \
                 'ELSE 5 END, data DESC'
    else:
        query += ' ORDER BY data DESC'

    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute(query, params)
    ordini = c.fetchall()

    # --- Sommario ---
    # Totale ordini
    c.execute('SELECT COUNT(*) FROM shop_orders')
    totale_ordini = c.fetchone()[0]

    # Ordini per stato
    c.execute("SELECT status, COUNT(*) FROM shop_orders GROUP BY status")
    ordini_per_stato = dict(c.fetchall())

    # Guadagno totale (tutti gli ordini)
    c.execute('SELECT SUM(totale) FROM shop_orders')
    guadagno_totale = c.fetchone()[0] or 0.0

    # Guadagno ordini completati
    c.execute("SELECT SUM(totale) FROM shop_orders WHERE status = 'completato'")
    guadagno_completati = c.fetchone()[0] or 0.0

    conn.close()

    # Prepara lista ordini per il template
    ordini_parsed = [
        {'order_id': o[0], 'data': o[1], 'status': o[2]}
        for o in ordini
    ]

    return render_template(
        'admin_orders.html',
        ordini=ordini_parsed,
        status_filter=status_filter,
        order_by=order_by,
        totale_ordini=totale_ordini,
        ordini_per_stato=ordini_per_stato,
        guadagno_totale=guadagno_totale,
        guadagno_completati=guadagno_completati
    )


    
@app.route('/cart')
def view_cart():
    cart = session.get('cart', {})
    prodotti = []
    totale = 0.0
    if cart:
        conn = sqlite3.connect('qr.db')
        c = conn.cursor()
        # Prendi tutti i prodotti presenti nel carrello
        ids = tuple(map(int, cart.keys()))
        placeholders = ','.join('?' for _ in ids)
        c.execute(f"SELECT id, nome, prezzo, immagine FROM shop_products WHERE id IN ({placeholders})", ids)
        prodotti_db = {str(row[0]): row for row in c.fetchall()}
        conn.close()
        for pid, qty in cart.items():
            if pid in prodotti_db:
                id, nome, prezzo, immagine = prodotti_db[pid]
                prodotti.append({
                    'id': id,
                    'nome': nome,
                    'prezzo': prezzo,
                    'immagine': immagine,
                    'quantita': qty,
                    'totale': prezzo * qty
                })
                totale += prezzo * qty
    return render_template('cart.html', prodotti=prodotti, totale=totale)

@app.route('/remove_from_cart/<int:product_id>')
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    pid = str(product_id)
    if pid in cart:
        del cart[pid]
        session['cart'] = cart
        flash("Prodotto rimosso dal carrello.", "success")
    return redirect(url_for('view_cart'))


@app.route('/user/messages')
def user_messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    # Prendi tutti i QR dell’utente
    c.execute('SELECT id, pubblico FROM qr_codes WHERE user_id = ?', (session['user_id'],))
    qr_list = c.fetchall()
    qr_ids = [row[0] for row in qr_list]
    qr_dict = {row[0]: row[1] for row in qr_list}
    messages = []
    if qr_ids:
        # Prendi tutti i messaggi relativi ai QR dell’utente
        placeholders = ','.join('?' for _ in qr_ids)
        c.execute(f'''
            SELECT qr_id, nome, messaggio, data_invio
            FROM qr_messages
            WHERE qr_id IN ({placeholders})
            ORDER BY data_invio DESC
        ''', qr_ids)
        messages = c.fetchall()
    conn.close()
    return render_template('user_messages.html', messages=messages, qr_dict=qr_dict)

@app.route('/shop')
def shop():
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('SELECT id, nome, descrizione, prezzo, immagine FROM shop_products WHERE disponibile = 1')
    prodotti = c.fetchall()
    conn.close()
    return render_template('shop.html', prodotti=prodotti)



@app.route('/qr/<qr_id>/send_message', methods=['POST'])
def send_qr_message(qr_id):
    nome = request.form.get('nome', '').strip()
    messaggio = request.form.get('messaggio', '').strip()
    if not messaggio:
        flash("Il messaggio non può essere vuoto.", "error")
        return redirect(url_for('view_qr', qr_id=qr_id))

    # Prendi l'email del proprietario solo se ricezione messaggi è attiva
    conn = sqlite3.connect('qr.db')
    c = conn.cursor()
    c.execute('''
        SELECT u.email
        FROM qr_codes q
        JOIN users u ON q.user_id = u.id
        WHERE q.id = ? AND q.ricevi_messaggi = 1
    ''', (qr_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        flash("Impossibile inviare il messaggio.", "error")
        return redirect(url_for('view_qr', qr_id=qr_id))

    to_email = row[0]
    subject = f"Nuovo messaggio ricevuto dal tuo QR {qr_id}"
    body = (
        f"Hai ricevuto un nuovo messaggio tramite il tuo QR HouseQR:\n\n"
        f"Nome mittente: {nome if nome else 'Anonimo'}\n"
        f"Messaggio:\n{messaggio}\n\n"
        f"Rispondi direttamente a questa email se vuoi contattare chi ha lasciato il messaggio (se ha lasciato i suoi dati)."
    )

    try:
        send_notification_email(to_email, subject, body)
        flash("Messaggio inviato con successo!", "success")
        # Salva il messaggio nel database
        conn = sqlite3.connect('qr.db')
        c = conn.cursor()
        c.execute('INSERT INTO qr_messages (qr_id, nome, messaggio) VALUES (?, ?, ?)', (qr_id, nome, messaggio))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Errore invio messaggio:", e)
        flash("Errore nell'invio del messaggio.", "error")

    return redirect(url_for('view_qr', qr_id=qr_id))


@app.route('/qr/<qr_id>/private', methods=['GET', 'POST'])
def view_qr_private(qr_id):
    qr = get_qr_data(qr_id)
    if not qr:
        abort(404, description="QR code non trovato")
    error = None
    if request.method == 'POST':
        user = get_user_by_username(session['username']) if 'username' in session else None
        password = request.form.get('password')
        if user and check_password_hash(user['password'], password):
            return render_template('private_view.html',
                                   messaggio_privato=qr['privato'],
                                   qr_id=qr_id)
        else:
            error = "Password errata!"
    return render_template('private_login.html', error=error, qr_id=qr_id)

@app.route('/download_qr/<qr_id>')
def download_qr(qr_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    qr = get_qr_data(qr_id)
    if not qr or qr['user_id'] != session['user_id']:
        abort(403)
    log_access(session['user_id'], 'download_qr', qr_id)
    color = request.args.get('color', 'black')
    bgcolor = request.args.get('bgcolor', 'white')
    from qr_utils import generate_custom_qr
    filename = f"qr_{qr_id}_{color}_{bgcolor}.png"
    path = os.path.join("temp_qr", filename)
    os.makedirs("temp_qr", exist_ok=True)
    generate_custom_qr(f"http://127.0.0.1:5000/qr/{qr_id}", path, fill_color=color, back_color=bgcolor)
    return send_file(path, as_attachment=True)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    error = None
    message = None
    username = session.get('pending_reset')
    if not username:
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        code = request.form['code']
        new_password = request.form['password']
        password2 = request.form.get('password2')
        if new_password != password2:
            error = "Le password non coincidono."
        elif not password_valida(new_password):
            error = "La password deve essere lunga almeno 8 caratteri e contenere una maiuscola, una minuscola e un numero."
        else:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT password_reset_code FROM users WHERE username = ?', (username,))
            row = c.fetchone()
            if row is None:
                error = "Utente non trovato."
            else:
                db_code = row[0]
                if db_code is None:
                    error = "Nessuna richiesta di reset attiva."
                elif code != db_code:
                    error = "Codice errato."
                else:
                    hashed_pw = generate_password_hash(new_password)
                    c.execute('UPDATE users SET password = ?, password_reset_code = NULL WHERE username = ?', (hashed_pw, username))
                    conn.commit()
                    session.pop('pending_reset', None)
                    conn.close()
                    message = "Password aggiornata con successo! Ora puoi accedere."
                    return render_template('reset_password.html', message=message)
            conn.close()
    return render_template('reset_password.html', error=error)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None
    message = None
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE email = ?', (email,))
        row = c.fetchone()
        if row:
            username = row[0]
            reset_code = genera_codice_verifica()
            c.execute('UPDATE users SET password_reset_code = ? WHERE email = ?', (reset_code, email))
            conn.commit()
            conn.close()
            send_notification_email(
                to_email=email,
                subject="Reset password HouseQR",
                body=f"Ciao, il tuo codice per il reset della password è: {reset_code}"
            )
            session['pending_reset'] = username
            message = "Codice di reset inviato alla tua email."
            return redirect(url_for('reset_password'))
        else:
            error = "Email non trovata."
            conn.close()
    return render_template('forgot_password.html', error=error, message=message)

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

if __name__ == '__main__':
    app.run(debug=True)
