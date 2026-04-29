import os
from flask import Flask


def create_app():
    app = Flask(__name__, instance_relative_config=True)

    os.makedirs(app.instance_path, exist_ok=True)

    app.config.from_mapping(
        SECRET_KEY='dev-secret-please-change',
        DATABASE=os.path.join(app.instance_path, 'authx.db'),
    )

    from . import db
    db.init_app(app)

    @app.route('/health')
    def health():
        return {'status': 'ok'}
    return app
