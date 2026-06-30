import os
from dotenv import load_dotenv
load_dotenv()  # .env dosyasını yükle

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import secrets
import random
from datetime import datetime, timedelta

from mailer import send_email, verification_email, reminder_email

app = Flask(__name__)

_secret = os.getenv('SECRET_KEY') or ('dev-' + secrets.token_hex(16))
# Flask-Login cookie'leri latin-1 ile encode eder; Türkçe karakter çökmeye yol açar.
try:
    _secret.encode('latin1')
except (UnicodeEncodeError, AttributeError):
    print("[UYARI] SECRET_KEY latin-1 uyumlu değil (Türkçe karakter olabilir). "
          "Geçici güvenli bir anahtar üretildi. Lütfen .env içindeki SECRET_KEY'i "
          "sadece İngilizce harf ve rakamlardan oluşan bir değerle değiştirin: "
          "python -c \"import secrets; print(secrets.token_hex(32))\"")
    _secret = secrets.token_hex(32)
app.config['SECRET_KEY'] = _secret

DB = 'tasks.db'
APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://localhost:5000')
# Birden fazla admin: virgülle ayır (örn: admin1@x.com,admin2@y.com)
ADMIN_EMAILS = [e.strip().lower() for e in (os.getenv('ADMIN_EMAIL') or '').split(',') if e.strip()]


def is_admin():
    """Giriş yapan kullanıcı admin mi?"""
    return (current_user.is_authenticated
            and ADMIN_EMAILS
            and current_user.email.strip().lower() in ADMIN_EMAILS)


def admin_required(f):
    """Sadece admin erişebilir; değilse ana sayfaya yönlendir."""
    from functools import wraps
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if not is_admin():
            flash('Bu sayfaya erişim yetkiniz yok.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Lütfen önce giriş yapın.'


# ─────────────────────────────────────────────────────────────
#  DB
# ─────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            verified INTEGER DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS email_verifications (
            user_id INTEGER PRIMARY KEY,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS sent_reminders (
            task_id INTEGER PRIMARY KEY,
            sent_at TEXT NOT NULL
        )
    ''')
    try:
        conn.execute("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0")
    except Exception:
        pass
    conn.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task_text TEXT NOT NULL,
            completed INTEGER DEFAULT 0,
            created_at TEXT,
            completed_at TEXT,
            due_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS subtasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            sub_text TEXT NOT NULL,
            sub_done INTEGER DEFAULT 0,
            created_at TEXT,
            due_at TEXT,
            FOREIGN KEY(task_id) REFERENCES tasks(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            note_text TEXT NOT NULL,
            note_date TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS plan_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category_id INTEGER,
            plan_text TEXT NOT NULL,
            completed INTEGER DEFAULT 0,
            created_at TEXT,
            completed_at TEXT,
            start_at TEXT,
            due_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(category_id) REFERENCES plan_categories(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS plan_subtasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id INTEGER NOT NULL,
            sub_text TEXT NOT NULL,
            sub_done INTEGER DEFAULT 0,
            created_at TEXT,
            due_at TEXT,
            FOREIGN KEY(plan_id) REFERENCES plans(id)
        )
    ''')
    # Eski tablolara user_id eklemeye çalış (eski db varsa)
    try:
        conn.execute("ALTER TABLE tasks ADD COLUMN user_id INTEGER")
    except Exception:
        pass
    for tbl in ('tasks', 'subtasks'):
        try:
            conn.execute(f"ALTER TABLE {tbl} ADD COLUMN due_at TEXT")
        except Exception:
            pass
    try:
        conn.execute("ALTER TABLE subtasks ADD COLUMN created_at TEXT")
    except Exception:
        pass
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────
#  USER
# ─────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email


@login_manager.user_loader
def load_user(uid):
    conn = get_db()
    row = conn.execute('SELECT id, email FROM users WHERE id=?', (uid,)).fetchone()
    conn.close()
    return User(row['id'], row['email']) if row else None


# ─────────────────────────────────────────────────────────────
#  AUTH SAYFALARI
# ─────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        conn = get_db()
        row = conn.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        conn.close()
        if row and check_password_hash(row['password_hash'], password):
            # Doğrulanmamışsa verify'e yönlendir
            if not row['verified']:
                session['pending_verify_uid'] = row['id']
                session['pending_verify_email'] = row['email']
                # Yeni kod gönder
                code = f"{random.randint(0, 999999):06d}"
                expires = (datetime.now() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
                conn2 = get_db()
                conn2.execute(
                    'INSERT OR REPLACE INTO email_verifications (user_id, code, expires_at, attempts) VALUES (?,?,?,0)',
                    (row['id'], code, expires)
                )
                conn2.commit()
                conn2.close()
                subject, html = verification_email(code)
                send_email(row['email'], subject, html)
                flash('Hesabınız henüz doğrulanmamış. E-postanıza yeni kod gönderildi.', 'info')
                return redirect(url_for('verify'))
            login_user(User(row['id'], row['email']), remember=True)
            return redirect(url_for('index'))
        flash('E-posta veya şifre hatalı.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if not email or '@' not in email or '.' not in email:
            flash('Geçerli bir e-posta girin.', 'error')
            return render_template('register.html')
        if len(password) < 6:
            flash('Şifre en az 6 karakter olmalı.', 'error')
            return render_template('register.html')
        if password != password2:
            flash('Şifreler eşleşmiyor.', 'error')
            return render_template('register.html')

        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        if existing:
            conn.close()
            flash('Bu e-posta zaten kayıtlı.', 'error')
            return render_template('register.html')

        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cur = conn.execute(
            'INSERT INTO users (email, password_hash, created_at, verified) VALUES (?, ?, ?, 0)',
            (email, generate_password_hash(password), now)
        )
        conn.commit()
        uid = cur.lastrowid

        # Doğrulama kodu üret ve gönder
        code = f"{random.randint(0, 999999):06d}"
        expires = (datetime.now() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
        conn.execute(
            'INSERT OR REPLACE INTO email_verifications (user_id, code, expires_at, attempts) VALUES (?,?,?,0)',
            (uid, code, expires)
        )
        conn.commit()
        conn.close()

        subject, html = verification_email(code)
        send_email(email, subject, html)

        # Doğrulama bekleyen kullanıcıyı session'a al (henüz login değil)
        session['pending_verify_uid'] = uid
        session['pending_verify_email'] = email
        return redirect(url_for('verify'))
    return render_template('register.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    uid = session.get('pending_verify_uid')
    email = session.get('pending_verify_email')
    if not uid:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = (request.form.get('code') or '').strip()
        conn = get_db()
        row = conn.execute(
            'SELECT * FROM email_verifications WHERE user_id=?', (uid,)
        ).fetchone()

        if not row:
            conn.close()
            flash('Doğrulama kaydı bulunamadı. Tekrar kayıt olun.', 'error')
            return redirect(url_for('register'))

        # Süre kontrolü
        if datetime.strptime(row['expires_at'], '%Y-%m-%d %H:%M:%S') < datetime.now():
            conn.close()
            flash('Kodun süresi doldu. Yeni kod isteyin.', 'error')
            return render_template('verify.html', email=email, expired=True)

        # Deneme limiti (5 yanlış)
        if row['attempts'] >= 5:
            conn.close()
            flash('Çok fazla yanlış deneme. Yeni kod isteyin.', 'error')
            return render_template('verify.html', email=email, expired=True)

        if code == row['code']:
            conn.execute('UPDATE users SET verified=1 WHERE id=?', (uid,))
            conn.execute('DELETE FROM email_verifications WHERE user_id=?', (uid,))
            conn.commit()
            user_row = conn.execute('SELECT id, email FROM users WHERE id=?', (uid,)).fetchone()
            conn.close()
            session.pop('pending_verify_uid', None)
            session.pop('pending_verify_email', None)
            login_user(User(user_row['id'], user_row['email']), remember=True)
            flash('E-posta doğrulandı! Hoş geldiniz.', 'success')
            return redirect(url_for('index'))
        else:
            conn.execute('UPDATE email_verifications SET attempts=attempts+1 WHERE user_id=?', (uid,))
            conn.commit()
            conn.close()
            flash('Kod hatalı. Tekrar deneyin.', 'error')

    return render_template('verify.html', email=email)


@app.route('/verify/resend', methods=['POST'])
def verify_resend():
    uid = session.get('pending_verify_uid')
    email = session.get('pending_verify_email')
    if not uid:
        return redirect(url_for('login'))

    code = f"{random.randint(0, 999999):06d}"
    expires = (datetime.now() + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    conn.execute(
        'INSERT OR REPLACE INTO email_verifications (user_id, code, expires_at, attempts) VALUES (?,?,?,0)',
        (uid, code, expires)
    )
    conn.commit()
    conn.close()

    subject, html = verification_email(code)
    send_email(email, subject, html)
    flash('Yeni doğrulama kodu gönderildi.', 'success')
    return redirect(url_for('verify'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    """Şifre sıfırlama isteği — token üretir ve sayfada gösterir."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        conn = get_db()
        row = conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        if row:
            token = secrets.token_urlsafe(32)
            expires = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            conn.execute(
                'INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)',
                (token, row['id'], expires)
            )
            conn.commit()
            reset_url = url_for('reset', token=token, _external=True)
            conn.close()
            # E-posta yerine ekrana göster (basit kurulum için)
            return render_template('forgot.html', reset_url=reset_url, sent=True)
        conn.close()
        # Bilgi sızdırmamak için "varmış gibi" davran
        return render_template('forgot.html', sent=True, fake=True)
    return render_template('forgot.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    conn = get_db()
    row = conn.execute(
        'SELECT user_id, expires_at FROM password_resets WHERE token=?', (token,)
    ).fetchone()
    if not row:
        conn.close()
        return render_template('reset.html', invalid=True)
    if datetime.strptime(row['expires_at'], '%Y-%m-%d %H:%M:%S') < datetime.now():
        conn.execute('DELETE FROM password_resets WHERE token=?', (token,))
        conn.commit()
        conn.close()
        return render_template('reset.html', invalid=True, expired=True)

    if request.method == 'POST':
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        if len(password) < 6:
            flash('Şifre en az 6 karakter olmalı.', 'error')
        elif password != password2:
            flash('Şifreler eşleşmiyor.', 'error')
        else:
            conn.execute(
                'UPDATE users SET password_hash=? WHERE id=?',
                (generate_password_hash(password), row['user_id'])
            )
            conn.execute('DELETE FROM password_resets WHERE token=?', (token,))
            conn.commit()
            conn.close()
            flash('Şifre başarıyla değiştirildi. Giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
    conn.close()
    return render_template('reset.html')


# ─────────────────────────────────────────────────────────────
#  ANA SAYFA
# ─────────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    return render_template('index.html', user_email=current_user.email, is_admin=is_admin())


# ─────────────────────────────────────────────────────────────
#  GÖREV API (her zaman user_id ile filtre)
# ─────────────────────────────────────────────────────────────
def _own_task(conn, task_id):
    row = conn.execute('SELECT user_id FROM tasks WHERE id=?', (task_id,)).fetchone()
    return row and row['user_id'] == current_user.id


def _own_sub(conn, sub_id):
    row = conn.execute(
        'SELECT t.user_id FROM subtasks s JOIN tasks t ON s.task_id=t.id WHERE s.id=?',
        (sub_id,)
    ).fetchone()
    return row and row['user_id'] == current_user.id


@app.route('/api/tasks', methods=['GET'])
@login_required
def get_tasks():
    conn = get_db()
    tasks = conn.execute(
        'SELECT * FROM tasks WHERE user_id=? ORDER BY created_at DESC',
        (current_user.id,)
    ).fetchall()
    result = []
    for t in tasks:
        subs = conn.execute(
            'SELECT * FROM subtasks WHERE task_id=? ORDER BY id', (t['id'],)
        ).fetchall()
        result.append({
            'id': t['id'], 'task_text': t['task_text'],
            'completed': bool(t['completed']),
            'created_at': t['created_at'], 'completed_at': t['completed_at'],
            'due_at': t['due_at'],
            'subtasks': [dict(s) for s in subs]
        })
    conn.close()
    return jsonify(result)


@app.route('/api/tasks', methods=['POST'])
@login_required
def add_task():
    data = request.json
    text = data.get('task_text', '').strip()
    if not text:
        return jsonify({'error': 'Görev boş olamaz'}), 400
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO tasks (user_id, task_text, created_at) VALUES (?, ?, ?)',
        (current_user.id, text, now)
    )
    conn.commit()
    tid = cur.lastrowid
    conn.close()
    return jsonify({'id': tid, 'task_text': text, 'completed': False,
                    'created_at': now, 'completed_at': None, 'due_at': None, 'subtasks': []})


@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@login_required
def delete_task(task_id):
    conn = get_db()
    if not _own_task(conn, task_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('DELETE FROM subtasks WHERE task_id=?', (task_id,))
    conn.execute('DELETE FROM tasks WHERE id=?', (task_id,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})


@app.route('/api/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def toggle_task(task_id):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    if not _own_task(conn, task_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    task = conn.execute('SELECT * FROM tasks WHERE id=?', (task_id,)).fetchone()
    if task['completed']:
        conn.execute('UPDATE tasks SET completed=0, completed_at=NULL WHERE id=?', (task_id,))
        ca, completed = None, False
    else:
        conn.execute('UPDATE tasks SET completed=1, completed_at=? WHERE id=?', (now, task_id))
        ca, completed = now, True
    conn.commit(); conn.close()
    return jsonify({'completed': completed, 'completed_at': ca})


@app.route('/api/tasks/<int:task_id>/due', methods=['POST'])
@login_required
def set_task_due(task_id):
    data = request.json
    due = data.get('due_at')
    if due and len(due) == 10:
        due = due + ' 23:59:59'
    conn = get_db()
    if not _own_task(conn, task_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('UPDATE tasks SET due_at=? WHERE id=?', (due, task_id))
    conn.commit(); conn.close()
    return jsonify({'due_at': due})


@app.route('/api/tasks/<int:task_id>/created', methods=['POST'])
@login_required
def set_task_created(task_id):
    """Görevin başlangıç (created_at) tarihini değiştir."""
    data = request.json
    start = data.get('created_at')
    if not start:
        return jsonify({'error': 'Tarih gerekli'}), 400
    if len(start) == 10:
        start = start + ' 09:00:00'
    conn = get_db()
    if not _own_task(conn, task_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('UPDATE tasks SET created_at=? WHERE id=?', (start, task_id))
    conn.commit(); conn.close()
    return jsonify({'created_at': start})


# ── Alt görev ────────────────────────────────────────────────
@app.route('/api/tasks/<int:task_id>/subtasks', methods=['POST'])
@login_required
def add_subtask(task_id):
    data = request.json
    text = data.get('sub_text', '').strip()
    if not text:
        return jsonify({'error': 'Boş olamaz'}), 400
    conn = get_db()
    if not _own_task(conn, task_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cur = conn.execute(
        'INSERT INTO subtasks (task_id, sub_text, sub_done, created_at) VALUES (?,?,0,?)',
        (task_id, text, now)
    )
    sid = cur.lastrowid

    row = conn.execute(
        'SELECT COUNT(*), SUM(sub_done) FROM subtasks WHERE task_id=?', (task_id,)
    ).fetchone()
    t_total, t_done = row[0] or 0, row[1] or 0
    if t_total > 0 and t_done == t_total:
        conn.execute('UPDATE tasks SET completed=1, completed_at=? WHERE id=?', (now, task_id))
    conn.commit(); conn.close()
    return jsonify({'id': sid, 'sub_text': text, 'sub_done': False, 'created_at': now, 'due_at': None})


@app.route('/api/subtasks/<int:sub_id>/toggle', methods=['POST'])
@login_required
def toggle_subtask(sub_id):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    if not _own_sub(conn, sub_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    sub = conn.execute('SELECT * FROM subtasks WHERE id=?', (sub_id,)).fetchone()
    new_done = 0 if sub['sub_done'] else 1
    conn.execute('UPDATE subtasks SET sub_done=? WHERE id=?', (new_done, sub_id))

    tid = sub['task_id']
    row = conn.execute(
        'SELECT COUNT(*), SUM(sub_done) FROM subtasks WHERE task_id=?', (tid,)
    ).fetchone()
    t_total, t_done = row[0] or 0, row[1] or 0
    if t_total > 0 and t_done == t_total:
        conn.execute('UPDATE tasks SET completed=1, completed_at=? WHERE id=?', (now, tid))
        task_completed = True
    elif t_total > 0 and t_done < t_total:
        conn.execute('UPDATE tasks SET completed=0, completed_at=NULL WHERE id=?', (tid,))
        task_completed = False
    else:
        task_completed = bool(conn.execute(
            'SELECT completed FROM tasks WHERE id=?', (tid,)
        ).fetchone()['completed'])
    conn.commit(); conn.close()
    return jsonify({'sub_done': bool(new_done), 'task_completed': task_completed,
                    'task_completed_at': now if task_completed else None})


@app.route('/api/subtasks/<int:sub_id>', methods=['DELETE'])
@login_required
def delete_subtask(sub_id):
    conn = get_db()
    if not _own_sub(conn, sub_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    sub = conn.execute('SELECT task_id FROM subtasks WHERE id=?', (sub_id,)).fetchone()
    tid = sub['task_id']
    conn.execute('DELETE FROM subtasks WHERE id=?', (sub_id,))
    row = conn.execute(
        'SELECT COUNT(*), SUM(sub_done) FROM subtasks WHERE task_id=?', (tid,)
    ).fetchone()
    t_total, t_done = row[0] or 0, row[1] or 0
    if t_total == 0 or t_done < t_total:
        conn.execute('UPDATE tasks SET completed=0, completed_at=NULL WHERE id=?', (tid,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})


@app.route('/api/subtasks/<int:sub_id>/due', methods=['POST'])
@login_required
def set_sub_due(sub_id):
    data = request.json
    due = data.get('due_at')
    if due and len(due) == 10:
        due = due + ' 23:59:59'
    conn = get_db()
    if not _own_sub(conn, sub_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('UPDATE subtasks SET due_at=? WHERE id=?', (due, sub_id))
    conn.commit(); conn.close()
    return jsonify({'due_at': due})


# ── Stat & Calendar ──────────────────────────────────────────
@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    conn = get_db()
    toplam = conn.execute(
        'SELECT COUNT(*) FROM tasks WHERE user_id=?', (current_user.id,)
    ).fetchone()[0]
    tamam = conn.execute(
        'SELECT COUNT(*) FROM tasks WHERE user_id=? AND completed=1', (current_user.id,)
    ).fetchone()[0]
    conn.close()
    return jsonify({'toplam': toplam, 'tamamlanan': tamam, 'aktif': toplam - tamam})


# ── Notlar ───────────────────────────────────────────────────
@app.route('/api/notes/<date>', methods=['GET'])
@login_required
def get_notes(date):
    """Belirli bir tarihteki notları getir. date formatı: YYYY-MM-DD"""
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM notes WHERE user_id=? AND note_date=? ORDER BY created_at',
        (current_user.id, date)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/notes', methods=['POST'])
@login_required
def add_note():
    data = request.json
    text = (data.get('note_text') or '').strip()
    date = (data.get('note_date') or '').strip()
    if not text or not date or len(date) != 10:
        return jsonify({'error': 'Geçersiz veri'}), 400
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO notes (user_id, note_text, note_date, created_at) VALUES (?,?,?,?)',
        (current_user.id, text, date, now)
    )
    conn.commit()
    nid = cur.lastrowid
    conn.close()
    return jsonify({'id': nid, 'note_text': text, 'note_date': date, 'created_at': now})


@app.route('/api/notes/<int:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    conn = get_db()
    row = conn.execute('SELECT user_id FROM notes WHERE id=?', (note_id,)).fetchone()
    if not row or row['user_id'] != current_user.id:
        conn.close()
        return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('DELETE FROM notes WHERE id=?', (note_id,))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# ── Planlamalar (Kategoriler + Planlar) ──────────────────────
def _own_plan(conn, pid):
    row = conn.execute('SELECT user_id FROM plans WHERE id=?', (pid,)).fetchone()
    return row and row['user_id'] == current_user.id

def _own_cat(conn, cid):
    row = conn.execute('SELECT user_id FROM plan_categories WHERE id=?', (cid,)).fetchone()
    return row and row['user_id'] == current_user.id

def _own_psub(conn, sid):
    row = conn.execute(
        'SELECT p.user_id FROM plan_subtasks s JOIN plans p ON s.plan_id=p.id WHERE s.id=?',
        (sid,)
    ).fetchone()
    return row and row['user_id'] == current_user.id


@app.route('/api/plan-categories', methods=['GET'])
@login_required
def get_plan_categories():
    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM plan_categories WHERE user_id=? ORDER BY id',
        (current_user.id,)
    ).fetchall()
    result = []
    for c in rows:
        cnt = conn.execute(
            'SELECT COUNT(*) FROM plans WHERE category_id=?', (c['id'],)
        ).fetchone()[0]
        result.append({'id': c['id'], 'name': c['name'], 'count': cnt})
    conn.close()
    return jsonify(result)


@app.route('/api/plan-categories', methods=['POST'])
@login_required
def add_plan_category():
    data = request.json
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'İsim boş olamaz'}), 400
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO plan_categories (user_id, name, created_at) VALUES (?,?,?)',
        (current_user.id, name, now)
    )
    conn.commit()
    cid = cur.lastrowid
    conn.close()
    return jsonify({'id': cid, 'name': name, 'count': 0})


@app.route('/api/plan-categories/<int:cid>', methods=['PUT'])
@login_required
def rename_plan_category(cid):
    data = request.json
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'İsim boş olamaz'}), 400
    conn = get_db()
    if not _own_cat(conn, cid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('UPDATE plan_categories SET name=? WHERE id=?', (name, cid))
    conn.commit(); conn.close()
    return jsonify({'ok': True, 'name': name})


@app.route('/api/plan-categories/<int:cid>', methods=['DELETE'])
@login_required
def delete_plan_category(cid):
    conn = get_db()
    if not _own_cat(conn, cid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    # Kategorideki tüm planları ve subtask'larını sil
    plan_ids = [r['id'] for r in conn.execute(
        'SELECT id FROM plans WHERE category_id=?', (cid,)
    ).fetchall()]
    for pid in plan_ids:
        conn.execute('DELETE FROM plan_subtasks WHERE plan_id=?', (pid,))
    conn.execute('DELETE FROM plans WHERE category_id=?', (cid,))
    conn.execute('DELETE FROM plan_categories WHERE id=?', (cid,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})


@app.route('/api/plans/<int:category_id>', methods=['GET'])
@login_required
def get_plans(category_id):
    conn = get_db()
    if not _own_cat(conn, category_id):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    plans = conn.execute(
        'SELECT * FROM plans WHERE category_id=? ORDER BY created_at DESC',
        (category_id,)
    ).fetchall()
    result = []
    for p in plans:
        subs = conn.execute(
            'SELECT * FROM plan_subtasks WHERE plan_id=? ORDER BY id', (p['id'],)
        ).fetchall()
        result.append({
            'id': p['id'], 'plan_text': p['plan_text'],
            'completed': bool(p['completed']),
            'created_at': p['created_at'], 'completed_at': p['completed_at'],
            'start_at': p['start_at'], 'due_at': p['due_at'],
            'subtasks': [dict(s) for s in subs]
        })
    conn.close()
    return jsonify(result)


@app.route('/api/plans', methods=['POST'])
@login_required
def add_plan():
    data = request.json
    cid = data.get('category_id')
    text = (data.get('plan_text') or '').strip()
    if not text or not cid:
        return jsonify({'error': 'Geçersiz veri'}), 400
    conn = get_db()
    if not _own_cat(conn, cid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cur = conn.execute(
        'INSERT INTO plans (user_id, category_id, plan_text, created_at) VALUES (?,?,?,?)',
        (current_user.id, cid, text, now)
    )
    conn.commit()
    pid = cur.lastrowid
    conn.close()
    return jsonify({'id': pid, 'plan_text': text, 'completed': False,
                    'created_at': now, 'completed_at': None,
                    'start_at': None, 'due_at': None, 'subtasks': []})


@app.route('/api/plans/<int:pid>', methods=['DELETE'])
@login_required
def delete_plan(pid):
    conn = get_db()
    if not _own_plan(conn, pid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('DELETE FROM plan_subtasks WHERE plan_id=?', (pid,))
    conn.execute('DELETE FROM plans WHERE id=?', (pid,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})


@app.route('/api/plans/<int:pid>/toggle', methods=['POST'])
@login_required
def toggle_plan(pid):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    if not _own_plan(conn, pid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    p = conn.execute('SELECT * FROM plans WHERE id=?', (pid,)).fetchone()
    if p['completed']:
        conn.execute('UPDATE plans SET completed=0, completed_at=NULL WHERE id=?', (pid,))
        ca, completed = None, False
    else:
        conn.execute('UPDATE plans SET completed=1, completed_at=? WHERE id=?', (now, pid))
        ca, completed = now, True
    conn.commit(); conn.close()
    return jsonify({'completed': completed, 'completed_at': ca})


@app.route('/api/plans/<int:pid>/dates', methods=['POST'])
@login_required
def set_plan_dates(pid):
    """Hem başlangıç hem bitiş tarihi - biri null olabilir."""
    data = request.json
    start = data.get('start_at')
    due = data.get('due_at')
    if start and len(start) == 10: start = start + ' 09:00:00'
    if due   and len(due)   == 10: due   = due   + ' 23:59:59'
    conn = get_db()
    if not _own_plan(conn, pid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('UPDATE plans SET start_at=?, due_at=? WHERE id=?', (start, due, pid))
    conn.commit(); conn.close()
    return jsonify({'start_at': start, 'due_at': due})


@app.route('/api/plans/<int:pid>/subtasks', methods=['POST'])
@login_required
def add_plan_subtask(pid):
    data = request.json
    text = (data.get('sub_text') or '').strip()
    if not text:
        return jsonify({'error': 'Boş olamaz'}), 400
    conn = get_db()
    if not _own_plan(conn, pid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cur = conn.execute(
        'INSERT INTO plan_subtasks (plan_id, sub_text, sub_done, created_at) VALUES (?,?,0,?)',
        (pid, text, now)
    )
    sid = cur.lastrowid

    row = conn.execute(
        'SELECT COUNT(*), SUM(sub_done) FROM plan_subtasks WHERE plan_id=?', (pid,)
    ).fetchone()
    t_total, t_done = row[0] or 0, row[1] or 0
    if t_total > 0 and t_done == t_total:
        conn.execute('UPDATE plans SET completed=1, completed_at=? WHERE id=?', (now, pid))
    conn.commit(); conn.close()
    return jsonify({'id': sid, 'sub_text': text, 'sub_done': False, 'created_at': now, 'due_at': None})


@app.route('/api/plan-subtasks/<int:sid>/toggle', methods=['POST'])
@login_required
def toggle_plan_subtask(sid):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_db()
    if not _own_psub(conn, sid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    s = conn.execute('SELECT * FROM plan_subtasks WHERE id=?', (sid,)).fetchone()
    new_done = 0 if s['sub_done'] else 1
    conn.execute('UPDATE plan_subtasks SET sub_done=? WHERE id=?', (new_done, sid))
    pid = s['plan_id']
    row = conn.execute(
        'SELECT COUNT(*), SUM(sub_done) FROM plan_subtasks WHERE plan_id=?', (pid,)
    ).fetchone()
    t_total, t_done = row[0] or 0, row[1] or 0
    if t_total > 0 and t_done == t_total:
        conn.execute('UPDATE plans SET completed=1, completed_at=? WHERE id=?', (now, pid))
        plan_completed = True
    elif t_total > 0 and t_done < t_total:
        conn.execute('UPDATE plans SET completed=0, completed_at=NULL WHERE id=?', (pid,))
        plan_completed = False
    else:
        plan_completed = bool(conn.execute('SELECT completed FROM plans WHERE id=?', (pid,)).fetchone()['completed'])
    conn.commit(); conn.close()
    return jsonify({'sub_done': bool(new_done), 'plan_completed': plan_completed,
                    'plan_completed_at': now if plan_completed else None})


@app.route('/api/plan-subtasks/<int:sid>', methods=['DELETE'])
@login_required
def delete_plan_subtask(sid):
    conn = get_db()
    if not _own_psub(conn, sid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    s = conn.execute('SELECT plan_id FROM plan_subtasks WHERE id=?', (sid,)).fetchone()
    pid = s['plan_id']
    conn.execute('DELETE FROM plan_subtasks WHERE id=?', (sid,))
    row = conn.execute(
        'SELECT COUNT(*), SUM(sub_done) FROM plan_subtasks WHERE plan_id=?', (pid,)
    ).fetchone()
    t_total, t_done = row[0] or 0, row[1] or 0
    if t_total == 0 or t_done < t_total:
        conn.execute('UPDATE plans SET completed=0, completed_at=NULL WHERE id=?', (pid,))
    conn.commit(); conn.close()
    return jsonify({'ok': True})


@app.route('/api/plan-subtasks/<int:sid>/due', methods=['POST'])
@login_required
def set_plan_sub_due(sid):
    data = request.json
    due = data.get('due_at')
    if due and len(due) == 10:
        due = due + ' 23:59:59'
    conn = get_db()
    if not _own_psub(conn, sid):
        conn.close(); return jsonify({'error': 'Yetki yok'}), 403
    conn.execute('UPDATE plan_subtasks SET due_at=? WHERE id=?', (due, sid))
    conn.commit(); conn.close()
    return jsonify({'due_at': due})


# ── Günlük görevler ──────────────────────────────────────────
@app.route('/api/today-tasks', methods=['GET'])
@login_required
def today_tasks():
    """Bugünün görevleri + dünden kalan tamamlanmayanlar."""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = get_db()
    # Bugün oluşturulanlar veya bitiş tarihi bugün olanlar
    rows = conn.execute("""
        SELECT * FROM tasks
        WHERE user_id=?
          AND (substr(created_at,1,10)=? OR substr(due_at,1,10)=?)
        ORDER BY completed ASC, created_at DESC
    """, (current_user.id, today, today)).fetchall()
    today_list = []
    for t in rows:
        subs = conn.execute(
            'SELECT * FROM plan_subtasks WHERE plan_id=? ORDER BY id', (0,)
        ).fetchall()  # placeholder boş
        subs2 = conn.execute(
            'SELECT * FROM subtasks WHERE task_id=? ORDER BY id', (t['id'],)
        ).fetchall()
        today_list.append({
            'id': t['id'], 'task_text': t['task_text'],
            'completed': bool(t['completed']),
            'created_at': t['created_at'], 'completed_at': t['completed_at'],
            'due_at': t['due_at'],
            'subtasks': [dict(s) for s in subs2]
        })

    # Geciken görevler: bitiş tarihi geçmiş ama tamamlanmamış
    overdue = conn.execute("""
        SELECT * FROM tasks
        WHERE user_id=?
          AND completed=0
          AND due_at IS NOT NULL
          AND due_at < ?
          AND substr(created_at,1,10) != ?
        ORDER BY due_at ASC
    """, (current_user.id, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), today)).fetchall()
    overdue_list = []
    for t in overdue:
        # bugünün listesinde varsa atla
        if any(x['id'] == t['id'] for x in today_list):
            continue
        subs2 = conn.execute(
            'SELECT * FROM subtasks WHERE task_id=? ORDER BY id', (t['id'],)
        ).fetchall()
        overdue_list.append({
            'id': t['id'], 'task_text': t['task_text'],
            'completed': bool(t['completed']),
            'created_at': t['created_at'], 'completed_at': t['completed_at'],
            'due_at': t['due_at'],
            'subtasks': [dict(s) for s in subs2]
        })

    # İstatistik
    toplam = len(today_list)
    tamam  = sum(1 for t in today_list if t['completed'])
    conn.close()
    return jsonify({
        'today': today_list,
        'overdue': overdue_list,
        'stats': {'toplam': toplam, 'tamamlanan': tamam, 'aktif': toplam - tamam}
    })


@app.route('/api/today-task', methods=['POST'])
@login_required
def add_today_task():
    """Bugüne özel görev ekle - bitiş tarihi otomatik bugün sonu."""
    data = request.json
    text = (data.get('task_text') or '').strip()
    if not text:
        return jsonify({'error': 'Boş olamaz'}), 400
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    today_end = datetime.now().strftime('%Y-%m-%d') + ' 23:59:59'
    conn = get_db()
    cur = conn.execute(
        'INSERT INTO tasks (user_id, task_text, created_at, due_at) VALUES (?,?,?,?)',
        (current_user.id, text, now, today_end)
    )
    conn.commit()
    tid = cur.lastrowid
    conn.close()
    return jsonify({'id': tid, 'task_text': text, 'completed': False,
                    'created_at': now, 'completed_at': None, 'due_at': today_end, 'subtasks': []})


@app.route('/api/notes-summary', methods=['GET'])
@login_required
def notes_summary():
    """Her tarihte kaç not var? Takvimde göstermek için."""
    conn = get_db()
    rows = conn.execute(
        'SELECT note_date, COUNT(*) as cnt FROM notes WHERE user_id=? GROUP BY note_date',
        (current_user.id,)
    ).fetchall()
    conn.close()
    return jsonify({r['note_date']: r['cnt'] for r in rows})


@app.route('/api/calendar', methods=['GET'])
@login_required
def get_calendar():
    conn = get_db()
    rows = conn.execute('''
        SELECT t.task_text, t.completed, t.created_at, t.due_at,
               COUNT(s.id) as sub_t, SUM(s.sub_done) as sub_d
        FROM tasks t
        LEFT JOIN subtasks s ON s.task_id = t.id
        WHERE t.created_at IS NOT NULL AND t.user_id=?
        GROUP BY t.id
    ''', (current_user.id,)).fetchall()

    result = {}
    for r in rows:
        sub_t = r['sub_t'] or 0; sub_d = r['sub_d'] or 0
        if r['completed']: done = True
        elif sub_t > 0:    done = sub_d == sub_t
        else:              done = False
        try:
            bt, bs = r['created_at'][:10], r['created_at'][11:16]
            result.setdefault(bt, []).append(
                {'text': r['task_text'], 'completed': done, 'saat': bs, 'tip': 'baslangic', 'kind': 'task'}
            )
            if r['due_at']:
                dt, ds = r['due_at'][:10], r['due_at'][11:16]
                result.setdefault(dt, []).append(
                    {'text': r['task_text'], 'completed': done, 'saat': ds, 'tip': 'bitis', 'kind': 'task'}
                )
        except Exception:
            pass

    # Planları da ekle (start_at veya due_at varsa)
    prows = conn.execute('''
        SELECT p.plan_text, p.completed, p.start_at, p.due_at, c.name as cat_name,
               COUNT(s.id) as sub_t, SUM(s.sub_done) as sub_d
        FROM plans p
        LEFT JOIN plan_categories c ON p.category_id = c.id
        LEFT JOIN plan_subtasks s ON s.plan_id = p.id
        WHERE p.user_id=? AND (p.start_at IS NOT NULL OR p.due_at IS NOT NULL)
        GROUP BY p.id
    ''', (current_user.id,)).fetchall()
    for r in prows:
        sub_t = r['sub_t'] or 0; sub_d = r['sub_d'] or 0
        if r['completed']: done = True
        elif sub_t > 0:    done = sub_d == sub_t
        else:              done = False
        prefix = f"[{r['cat_name']}] " if r['cat_name'] else ""
        try:
            if r['start_at']:
                bt, bs = r['start_at'][:10], r['start_at'][11:16]
                result.setdefault(bt, []).append({
                    'text': prefix + r['plan_text'], 'completed': done,
                    'saat': bs, 'tip': 'baslangic', 'kind': 'plan'
                })
            if r['due_at']:
                dt, ds = r['due_at'][:10], r['due_at'][11:16]
                result.setdefault(dt, []).append({
                    'text': prefix + r['plan_text'], 'completed': done,
                    'saat': ds, 'tip': 'bitis', 'kind': 'plan'
                })
        except Exception:
            pass

    conn.close()
    return jsonify(result)


# ─────────────────────────────────────────────────────────────
#  HATIRLATMA SİSTEMİ (APScheduler)
# ─────────────────────────────────────────────────────────────
def check_and_send_reminders():
    """
    Bitiş tarihi önümüzdeki 24 saat içinde olan, tamamlanmamış görevler için
    sahibine e-posta gönderir. Aynı görev için ikinci kez göndermez.
    """
    try:
        conn = get_db()
        now = datetime.now()
        limit = (now + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        now_str = now.strftime('%Y-%m-%d %H:%M:%S')

        print(f"[reminder] Kontrol başladı. Şimdi={now_str}, 24s sonrası={limit}")

        # Yaklaşan, tamamlanmamış, henüz hatırlatma gönderilmemiş görevler
        rows = conn.execute('''
            SELECT t.id, t.task_text, t.due_at, u.email, u.verified
            FROM tasks t
            JOIN users u ON t.user_id = u.id
            WHERE t.completed = 0
              AND t.due_at IS NOT NULL
              AND t.due_at > ?
              AND t.due_at <= ?
              AND u.verified = 1
              AND t.id NOT IN (SELECT task_id FROM sent_reminders)
        ''', (now_str, limit)).fetchall()

        print(f"[reminder] Gönderilecek görev sayısı: {len(rows)}")

        # Teşhis: hiç görev yoksa nedenini araştır
        if len(rows) == 0:
            all_due = conn.execute('''
                SELECT t.id, t.task_text, t.due_at, t.completed, u.email, u.verified,
                       (SELECT COUNT(*) FROM sent_reminders sr WHERE sr.task_id=t.id) as zaten_gonderildi
                FROM tasks t JOIN users u ON t.user_id=u.id
                WHERE t.due_at IS NOT NULL
            ''').fetchall()
            print(f"[reminder] Teşhis — bitiş tarihi olan tüm görevler ({len(all_due)} adet):")
            for r in all_due:
                neden = []
                if r['completed']: neden.append("tamamlanmış")
                if not r['verified']: neden.append("mail doğrulanmamış")
                if r['due_at'] <= now_str: neden.append("bitiş tarihi GEÇMİŞ")
                if r['due_at'] > limit: neden.append("bitiş 24 saatten UZAK")
                if r['zaten_gonderildi']: neden.append("zaten gönderilmiş")
                neden_str = ", ".join(neden) if neden else "GÖNDERİLMELİYDİ (?)"
                print(f"   - '{r['task_text']}' due={r['due_at']} → {neden_str}")

        # Kullanıcıya göre grupla
        by_user = {}
        for r in rows:
            by_user.setdefault(r['email'], []).append({
                'id': r['id'],
                'text': r['task_text'],
                'due': r['due_at'][:16]
            })

        for email, gorevler in by_user.items():
            subject, html = reminder_email(email, gorevler)
            ok = send_email(email, subject, html)
            if ok:
                for g in gorevler:
                    conn.execute(
                        'INSERT OR REPLACE INTO sent_reminders (task_id, sent_at) VALUES (?, ?)',
                        (g['id'], now_str)
                    )
                conn.commit()
                print(f"[reminder] ✅ {email} → {len(gorevler)} görev hatırlatması gönderildi")
            else:
                print(f"[reminder] ❌ {email} → e-posta gönderilemedi (SMTP hatası)")

        # Temizlik
        conn.execute('''
            DELETE FROM sent_reminders
            WHERE task_id NOT IN (SELECT id FROM tasks WHERE completed=0)
        ''')
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[reminder] Hata: {e}")


def start_scheduler():
    from apscheduler.schedulers.background import BackgroundScheduler
    scheduler = BackgroundScheduler(daemon=True)
    # Her 15 dakikada bir kontrol et
    scheduler.add_job(check_and_send_reminders, 'interval', minutes=15, id='reminders')
    # Uygulama açılır açılmaz bir kez de hemen çalıştır (10 sn sonra)
    scheduler.add_job(check_and_send_reminders, 'date',
                      run_date=datetime.now() + timedelta(seconds=10), id='reminders_initial')
    scheduler.start()
    print("[scheduler] Hatırlatma sistemi başladı (her 15 dk kontrol, 10 sn sonra ilk kontrol)")
    return scheduler


# Manuel test endpoint'i — sadece admin
@app.route('/admin/check-reminders')
@admin_required
def manual_check_reminders():
    check_and_send_reminders()
    flash('Hatırlatma kontrolü çalıştırıldı. Terminal çıktısına bakın.', 'success')
    return redirect(url_for('admin_panel'))


# ─────────────────────────────────────────────────────────────
#  ADMIN PANELİ
# ─────────────────────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    # Genel istatistikler
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    verified_count = conn.execute('SELECT COUNT(*) FROM users WHERE verified=1').fetchone()[0]
    task_count = conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0]
    done_count = conn.execute('SELECT COUNT(*) FROM tasks WHERE completed=1').fetchone()[0]
    plan_count = conn.execute('SELECT COUNT(*) FROM plans').fetchone()[0]
    note_count = conn.execute('SELECT COUNT(*) FROM notes').fetchone()[0]

    # Kullanıcı listesi + her birinin görev sayıları
    users = conn.execute('''
        SELECT u.id, u.email, u.created_at, u.verified,
               (SELECT COUNT(*) FROM tasks t WHERE t.user_id=u.id) as task_count,
               (SELECT COUNT(*) FROM tasks t WHERE t.user_id=u.id AND t.completed=1) as done_count,
               (SELECT COUNT(*) FROM plans p WHERE p.user_id=u.id) as plan_count
        FROM users u
        ORDER BY u.created_at DESC
    ''').fetchall()
    conn.close()

    stats = {
        'users': user_count, 'verified': verified_count,
        'tasks': task_count, 'done': done_count,
        'plans': plan_count, 'notes': note_count,
    }
    return render_template('admin.html',
                           stats=stats,
                           users=[dict(u) for u in users],
                           admin_emails=ADMIN_EMAILS)


@app.route('/admin/users/<int:uid>/delete', methods=['POST'])
@admin_required
def admin_delete_user(uid):
    conn = get_db()
    target = conn.execute('SELECT email FROM users WHERE id=?', (uid,)).fetchone()
    if not target:
        conn.close()
        flash('Kullanıcı bulunamadı.', 'error')
        return redirect(url_for('admin_panel'))
    # Admin kendini/diğer adminleri silemesin
    if target['email'].strip().lower() in ADMIN_EMAILS:
        conn.close()
        flash('Admin hesabı silinemez.', 'error')
        return redirect(url_for('admin_panel'))

    # Kullanıcının tüm verilerini sil
    task_ids = [r['id'] for r in conn.execute('SELECT id FROM tasks WHERE user_id=?', (uid,)).fetchall()]
    for tid in task_ids:
        conn.execute('DELETE FROM subtasks WHERE task_id=?', (tid,))
    conn.execute('DELETE FROM tasks WHERE user_id=?', (uid,))

    plan_ids = [r['id'] for r in conn.execute('SELECT id FROM plans WHERE user_id=?', (uid,)).fetchall()]
    for pid in plan_ids:
        conn.execute('DELETE FROM plan_subtasks WHERE plan_id=?', (pid,))
    conn.execute('DELETE FROM plans WHERE user_id=?', (uid,))
    conn.execute('DELETE FROM plan_categories WHERE user_id=?', (uid,))
    conn.execute('DELETE FROM notes WHERE user_id=?', (uid,))
    conn.execute('DELETE FROM email_verifications WHERE user_id=?', (uid,))
    conn.execute('DELETE FROM password_resets WHERE user_id=?', (uid,))
    conn.execute('DELETE FROM users WHERE id=?', (uid,))
    conn.commit()
    conn.close()
    flash(f"'{target['email']}' ve tüm verileri silindi.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/broadcast', methods=['POST'])
@admin_required
def admin_broadcast():
    subject = (request.form.get('subject') or '').strip()
    message = (request.form.get('message') or '').strip()
    only_verified = request.form.get('only_verified') == 'on'
    if not subject or not message:
        flash('Konu ve mesaj boş olamaz.', 'error')
        return redirect(url_for('admin_panel'))

    conn = get_db()
    q = 'SELECT email FROM users'
    if only_verified:
        q += ' WHERE verified=1'
    emails = [r['email'] for r in conn.execute(q).fetchall()]
    conn.close()

    # Basit HTML duyuru şablonu
    from mailer import _wrap, send_email as _send
    body_html = _wrap(f'''
        <h2 style="font-size:18px;margin:0 0 12px;">📢 Duyuru</h2>
        <div style="font-size:14px;color:#1a2332;line-height:1.7;white-space:pre-wrap;">{message}</div>
    ''')

    sent, failed = 0, 0
    for em in emails:
        if _send(em, subject, body_html):
            sent += 1
        else:
            failed += 1
    flash(f'Duyuru gönderildi: {sent} başarılı, {failed} başarısız.', 'success')
    return redirect(url_for('admin_panel'))


if __name__ == '__main__':
    init_db()
    # Scheduler'ı başlat (sadece bir kez)
    if os.getenv('MAIL_USERNAME'):
        start_scheduler()
    else:
        print("[scheduler] MAIL_USERNAME ayarlı değil, hatırlatmalar devre dışı.")
    print("\n✅  Uygulama başlatıldı!")
    print(f"🌐  Tarayıcı:  {APP_BASE_URL}")
    print("📡  Ağdaki diğer cihazlar için kendi IP adresinizi kullanın\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
