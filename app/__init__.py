import os
import secrets
import logging

from flask import Flask, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from . import db


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per hour"], 
    storage_uri="memory://", 
)


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    secret_key = os.environ.get("AUTHX_SECRET_KEY")
    if not secret_key:
        secret_key = secrets.token_hex(32)
        app.logger.warning(
            "AUTHX_SECRET_KEY not set — generated ephemeral key. "
            "Set it in env for stable sessions."
        )

    https_only = os.environ.get("AUTHX_HTTPS", "true").lower() != "false"

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE=os.path.join(app.instance_path, "authx.db"),

        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=https_only,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=1800,

        RATELIMIT_STORAGE_URI="memory://",
        RATELIMIT_HEADERS_ENABLED=True, 
    )

    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    limiter.init_app(app)

    from . import auth, main
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)

    @app.route("/health")
    def health():
        return {"status": "ok"}, 200

    @app.errorhandler(404)
    def err_404(e):
        return render_template("errors/error.html",
                               code=404, msg="Pagina nu a fost găsită."), 404

    @app.errorhandler(429)
    def err_429(e):
        try:
            from .auth import audit_log
            audit_log(None, "RATE_LIMIT_HIT",
                      resource="auth", resource_id=request.path)
        except Exception:
            pass
        return render_template("errors/error.html",
                               code=429,
                               msg="Prea multe încercări. Încearcă din nou peste un minut."), 429

    @app.errorhandler(500)
    def err_500(e):
        app.logger.exception("Unhandled server error")
        return render_template("errors/error.html",
                               code=500, msg="Eroare internă."), 500

    return app

