import importlib
import logging

from flask import Flask

from app.config import config_by_name
from app.extensions import db, migrate


def create_app(config_name: str = "default") -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])
    if config_name == "production" and not app.config.get("SQLALCHEMY_DATABASE_URI"):
        raise RuntimeError("DATABASE_URL must be set for production config")

    db.init_app(app)
    migrate.init_app(app, db)

    # importlib: plain "import app.models" would rebind local name `app` to the package.
    importlib.import_module("app.models")

    from app.routes.api_v1 import bp as api_v1_bp

    app.register_blueprint(api_v1_bp)

    if not app.debug:
        logging.basicConfig(level=logging.INFO)

    return app
