"""Rute generale (non-auth)."""
from flask import Blueprint, session, redirect, url_for, render_template

bp = Blueprint('main', __name__)


@bp.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@bp.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        return redirect(url_for('auth.login'))
    return render_template(
        'dashboard.html',
        email=session.get('email'),
        role=session.get('role')
    )
