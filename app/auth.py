import re
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
from flask import (
    Blueprint, request, render_template, redirect, url_for,
    flash, session, current_app
)

from . import limiter
from .db import get_db


bp = Blueprint("auth", __name__)

PASSWORD_MIN_LEN = 12
PASSWORD_RULES = [
    (r"[A-Z]",        "o literă mare"),
    (r"[a-z]",        "o literă mică"),
    (r"[0-9]",        "o cifră"),
    (r"[^A-Za-z0-9]", "un caracter special"),
]

COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678",
    "qwerty", "qwerty123", "letmein", "admin", "admin123",
    "welcome", "monkey", "iloveyou", "abc123", "111111",
}


def validate_password(pw: str) -> tuple[bool, str]:
    if len(pw) < PASSWORD_MIN_LEN:
        return False, f"Parola trebuie să respecte cerințele (min {PASSWORD_MIN_LEN} caractere, complexitate)."
    for pattern, _descr in PASSWORD_RULES:
        if not re.search(pattern, pw):
            return False, "Parola trebuie să respecte cerințele de complexitate."
    if pw.lower() in COMMON_PASSWORDS:
        return False, "Parola este prea comună. Alege alta."
    return True, ""


_DUMMY_HASH = bcrypt.hashpw(b"dummy-uniform-timing-hash", bcrypt.gensalt(rounds=12))


def audit_log(user_id, action: str, resource: str = "auth", resource_id=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, action, resource,
         str(resource_id) if resource_id is not None else None,
         request.remote_addr),
    )
    db.commit()


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(ts: str | None) -> datetime | None:
    if ts is None:
        return None
    dt = datetime.fromisoformat(ts)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_locked(user_row) -> bool:
    until = _parse_iso(user_row["lockout_until"])
    return until is not None and until > _now_utc()


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", exempt_when=lambda: request.method != "POST")
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not re.match(r"^[\w.+\-]+@[\w\-]+(\.[\w\-]+)+$", email):
            flash("Date invalide.", "error")
            return render_template("auth/register.html"), 400

        ok, msg = validate_password(password)
        if not ok:
            flash(msg, "error")
            return render_template("auth/register.html"), 400

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        pw_hash = bcrypt.hashpw(password.encode("utf-8"),
                                bcrypt.gensalt(rounds=12)).decode("utf-8")

        if existing is None:
            db.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'ANALYST')",
                (email, pw_hash),
            )
            db.commit()
            new_id = db.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()["id"]
            audit_log(new_id, "REGISTER")
        else:
            audit_log(None, "REGISTER_DUPLICATE_BLOCKED", resource_id=email)

        flash("Dacă datele sunt valide, contul a fost creat. Te poți autentifica.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html",
                           min_len=PASSWORD_MIN_LEN)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", exempt_when=lambda: request.method != "POST")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user and _is_locked(user):
            audit_log(user["id"], "LOGIN_BLOCKED_LOCKOUT")
            flash("Invalid credentials.", "error")
            return render_template("auth/login.html"), 401

        stored_hash = (user["password_hash"].encode("utf-8")
                       if user else _DUMMY_HASH)
        valid = bcrypt.checkpw(password.encode("utf-8"), stored_hash)

        if not user or not valid:
            if user:
                new_count = (user["failed_attempts"] or 0) + 1
                lock_until = None
                if new_count >= MAX_FAILED_ATTEMPTS:
                    lock_until = (_now_utc() +
                                  timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                    audit_log(user["id"], "ACCOUNT_LOCKED")
                db.execute(
                    "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?",
                    (new_count, lock_until, user["id"]),
                )
                db.commit()
                audit_log(user["id"], "LOGIN_FAIL")
            else:
                audit_log(None, "LOGIN_FAIL_UNKNOWN", resource_id=email)

            flash("Invalid credentials.", "error")
            return render_template("auth/login.html"), 401

        db.execute(
            "UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?",
            (user["id"],),
        )
        db.commit()

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["email"] = user["email"]
        session["role"] = user["role"]
        session["fp"] = _ua_fingerprint()

        audit_log(user["id"], "LOGIN_SUCCESS")
        return redirect(url_for("main.dashboard"))

    return render_template("auth/login.html")


def _ua_fingerprint() -> str:
    """Hash al User-Agent + IP — defense in depth contra session hijacking."""
    raw = f"{request.remote_addr}|{request.headers.get('User-Agent', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@bp.route("/logout", methods=["POST", "GET"])
def logout():
    user_id = session.get("user_id")
    if user_id:
        audit_log(user_id, "LOGOUT")
    session.clear()
    flash("Te-ai delogat.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("3 per hour", exempt_when=lambda: request.method != "POST")
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        if user:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            expires_at = (_now_utc() + timedelta(minutes=15)).isoformat()

            db.execute(
                "UPDATE password_reset_tokens SET used_at = ? "
                "WHERE user_id = ? AND used_at IS NULL",
                (_now_utc().isoformat(), user["id"]),
            )
            db.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) "
                "VALUES (?, ?, ?)",
                (user["id"], token_hash, expires_at),
            )
            db.commit()
            audit_log(user["id"], "RESET_REQUEST")

            reset_url = url_for("auth.reset_password",
                                token=raw_token, _external=True)
            current_app.logger.info(f"[DEMO] Reset link pentru {email}: {reset_url}")
            print(f"\n[DEMO MODE] Reset link pentru {email}:\n  {reset_url}\n",
                  flush=True)
        else:
            audit_log(None, "RESET_REQUEST_UNKNOWN", resource_id=email)

        flash("Dacă email-ul este înregistrat, am trimis un link de resetare.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/forgot.html")


@bp.route("/reset-password", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def reset_password():
    raw_token = request.values.get("token", "")
    if not raw_token:
        flash("Link invalid sau expirat.", "error")
        return redirect(url_for("auth.login"))

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    db = get_db()
    rec = db.execute(
        "SELECT prt.id, prt.user_id, prt.expires_at, prt.used_at, u.email "
        "FROM password_reset_tokens prt "
        "JOIN users u ON u.id = prt.user_id "
        "WHERE prt.token_hash = ?",
        (token_hash,),
    ).fetchone()

    def _invalid_redirect():
        flash("Link invalid sau expirat.", "error")
        return redirect(url_for("auth.login"))

    if rec is None:
        return _invalid_redirect()

    if rec["used_at"] is not None:
        audit_log(rec["user_id"], "RESET_TOKEN_REUSE_BLOCKED")
        return _invalid_redirect()

    expires_at = _parse_iso(rec["expires_at"])
    if expires_at is None or expires_at < _now_utc():
        audit_log(rec["user_id"], "RESET_TOKEN_EXPIRED")
        return _invalid_redirect()

    if request.method == "POST":
        new_password = request.form.get("password", "")
        ok, msg = validate_password(new_password)
        if not ok:
            flash(msg, "error")
            return render_template("auth/reset.html", token=raw_token), 400

        new_hash = bcrypt.hashpw(new_password.encode("utf-8"),
                                 bcrypt.gensalt(rounds=12)).decode("utf-8")

        db.execute(
            "UPDATE users SET password_hash = ?, failed_attempts = 0, "
            "lockout_until = NULL WHERE id = ?",
            (new_hash, rec["user_id"]),
        )
        db.execute(
            "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
            (_now_utc().isoformat(), rec["id"]),
        )
        db.execute(
            "UPDATE password_reset_tokens SET used_at = ? "
            "WHERE user_id = ? AND used_at IS NULL AND id != ?",
            (_now_utc().isoformat(), rec["user_id"], rec["id"]),
        )
        db.commit()

        audit_log(rec["user_id"], "RESET_PASSWORD")
        flash("Parolă actualizată. Te poți autentifica.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset.html", token=raw_token)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        if session.get("fp") != _ua_fingerprint():
            audit_log(session.get("user_id"), "SESSION_FINGERPRINT_MISMATCH")
            session.clear()
            flash("Sesiune invalidată din motive de securitate.", "error")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped

