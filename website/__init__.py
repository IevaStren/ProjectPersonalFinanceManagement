from flask import Flask, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.security import generate_password_hash
from flask_mail import Mail
import os
import dotenv
from flask_babel import Babel
from flask_login import current_user

dotenv.load_dotenv()
db = SQLAlchemy()
DB_NAME = "testdb.db"
mail = Mail()
babel = Babel()

def get_locale():
    if "lang" in session:
        return session["lang"]

    if current_user.is_authenticated:
        return current_user.language

    return request.accept_languages.best_match(["en", "lv"])

def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

    # DB setting
    BASEDIR = os.path.abspath(os.path.dirname(__file__))
    DB_PATH = os.path.join(BASEDIR, "instance", DB_NAME)
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "sqlite:///" + os.path.join(app.instance_path, DB_NAME)
    )

    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    
    # mail setting
    app.config["MAIL_SERVER"] = "smtp.gmail.com"
    app.config["MAIL_PORT"] = 587
    app.config["MAIL_USE_TLS"] = True
    app.config["MAIL_USERNAME"] = os.environ.get("EMAIL")
    app.config["MAIL_PASSWORD"] = os.environ.get("PASSWORD")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("EMAIL")


    app.config['BABEL_DEFAULT_LOCALE'] = 'en'
    app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'


    db.init_app(app)
    mail.init_app(app)   
    babel.init_app(app, locale_selector=get_locale)

    from .views import views
    from .auth import auth
    app.register_blueprint(views)
    app.register_blueprint(auth)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    from .models import User


    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()
        from .init_db import define_categories
        define_categories()
        if not User.query.filter_by(email="admin@test.lv").first():
            admin = User(
                email="admin@test.lv",
                first_name="Admin",
                last_name="Admin",
                password=generate_password_hash("admin123"),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()

    return app
