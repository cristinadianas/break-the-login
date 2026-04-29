"""
Authentication routes (V1 - VULNERABLE)
"""

import hashlib
from flask import (
    Blueprint, request, render_template, redirect, url_for,
    session, flash
)
from .db import get_db

bp = Blueprint('auth', __name__)


def weak_hash(password: str) -> str:
    """V1: MD5 fara salt. VULN 4.2"""
    return hashlib.md5(password.encode()).hexdigest()


def predictable_reset_token(email: str) -> str:
    """V1: Token determinist - oricine stie emailul poate reseta. VULN 4.6"""
    return hashlib.md5(email.encode()).hexdigest()


def log_action(user_id, action, resource=None, resource_id=None):
    """Audit logging - ramane neschimbat in v2."""
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, action, resource, resource_id, request.remote_addr)
    )
    db.commit()


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # VULN 4.1: doar verificare non-empty, nicio validare reala
        if not email or not password:
            flash('Email and password required')
            return render_template('register.html')

        db = get_db()

        # VULN 4.4: dezvaluim ca emailul exista deja (enumeration la register)
        existing = db.execute(
            'SELECT id FROM users WHERE email = ?', (email,)
        ).fetchone()
        if existing:
            flash(f'Email {email} is already registered. Try logging in.')
            return render_template('register.html')

        pwd_hash = weak_hash(password)
        cursor = db.execute(
            'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
            (email, pwd_hash, 'ANALYST')
        )
        db.commit()
        log_action(cursor.lastrowid, 'REGISTER', 'auth')
        flash('Account created. Please log in.')
        return redirect(url_for('auth.login'))

    return render_template('register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        db = get_db()

        user = db.execute(
            'SELECT * FROM users WHERE email = ?', (email,)
        ).fetchone()

        # VULN 4.4: mesaje DIFERITE + timing diferit (hash-ul calculat doar daca userul exista)
        if user is None:
            log_action(None, 'LOGIN_FAIL_USER_NOT_FOUND', 'auth')
            flash('User does not exist')
            return render_template('login.html')

        if user['password_hash'] != weak_hash(password):
            log_action(user['id'], 'LOGIN_FAIL_WRONG_PASSWORD', 'auth')
            flash('Wrong password')
            return render_template('login.html')

        # VULN 4.3: nicio limitare la incercari
        # VULN 4.5: session fara regenerare ID
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']

        log_action(user['id'], 'LOGIN_SUCCESS', 'auth')
        return redirect(url_for('main.dashboard'))

    return render_template('login.html')


@bp.route('/logout', methods=('POST', 'GET'))   # VULN: GET acceptat → CSRF logout
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_action(user_id, 'LOGOUT', 'auth')
    session.clear()
    flash('Logged out')
    return redirect(url_for('auth.login'))


@bp.route('/forgot-password', methods=('GET', 'POST'))
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        db = get_db()
        user = db.execute(
            'SELECT id FROM users WHERE email = ?', (email,)
        ).fetchone()

        if user:
            # VULN 4.6: token determinist, fara storage, fara expirare, reutilizabil
            token = predictable_reset_token(email)
            log_action(user['id'], 'RESET_REQUEST', 'auth')
            reset_url = url_for(
                'auth.reset_password', token=token, email=email, _external=True
            )
            flash(f'[DEV] Reset link: {reset_url}')
        else:
            # VULN 4.4: dezvaluim ca emailul nu exista
            flash('Email not found in our system')

    return render_template('forgot_password.html')


@bp.route('/reset-password', methods=('GET', 'POST'))
def reset_password():
    token = request.args.get('token') or request.form.get('token')
    email = request.args.get('email') or request.form.get('email')

    if not token or not email:
        flash('Missing token or email')
        return redirect(url_for('auth.login'))

    # VULN 4.6: doar verifica egalitatea cu md5(email) - nu se invalideaza niciodata
    if token != predictable_reset_token(email):
        flash('Invalid token')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        new_password = request.form.get('password', '')
        if not new_password:
            flash('Password required')
            return render_template('reset_password.html', token=token, email=email)

        db = get_db()
        user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            db.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (weak_hash(new_password), user['id'])
            )
            db.commit()
            log_action(user['id'], 'RESET_PASSWORD', 'auth')
            flash('Password updated. Please log in.')
            return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token, email=email)
