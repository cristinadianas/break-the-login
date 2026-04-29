"""Flask application factory (V1 - VULNERABLE)."""
import os
from datetime import timedelta
from flask import Flask


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.from_mapping(
        # VULN 4.5: secret hardcodat si slab
        SECRET_KEY='dev-secret-please-change',
        DATABASE=os.path.join(app.instance_path, 'authx.db'),
        # VULN 4.5: cookie session FARA flags de securitate
        SESSION_COOKIE_HTTPONLY=False,
        SESSION_COOKIE_SECURE=False,
        SESSION_COOKIE_SAMESITE=None,
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),
    )

    from . import db
    db.init_app(app)

    from . import auth, main
    app.register_blueprint(auth.bp)
    app.register_blueprint(main.bp)

    @app.route('/health')
    def health():
        return {'status': 'ok'}

    return app
