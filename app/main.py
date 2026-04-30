from flask import Blueprint, render_template, session

from .auth import login_required, audit_log
from .db import get_db


bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("main/index.html")


@bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    logs = db.execute(
        "SELECT action, resource, timestamp, ip_address "
        "FROM audit_logs WHERE user_id = ? "
        "ORDER BY timestamp DESC LIMIT 20",
        (session["user_id"],),
    ).fetchall()
    return render_template("main/dashboard.html",
                           email=session.get("email"),
                           role=session.get("role"),
                           logs=logs)

