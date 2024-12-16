from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['DEBUG'] = True  # Vulnerable to exposing sensitive information
    app.config['SECRET_KEY'] = 'secret_key'  # Set a secret key # without these cookies canbe tampered
    
    # Initialize database setup
    from app.database import init_db
    init_db()

    #Routes
    from app.routes import main
    app.register_blueprint(main)
    return app
