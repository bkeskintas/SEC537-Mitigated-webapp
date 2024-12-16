import os
from flask import Flask
from flask_wtf import CSRFProtect

def create_app():
    app = Flask(__name__)
    
    # Load secret key securely from environment variables
    app.secret_key = os.environ.get('SECRET_KEY', 'fallback_key_for_development')
    
    if app.secret_key == 'fallback_key_for_development':
        print("Warning: Using fallback secret key. Set SECRET_KEY in environment variables!")

    # Enable CSRF Protection
    csrf = CSRFProtect(app)
    
    # Centralized error handling
    @app.errorhandler(500)
    def internal_error(e):
        return "An unexpected error occurred. Please try again later.", 500

    @app.errorhandler(404)
    def not_found(e):
        return "Page not found.", 404
    

    from app.database import init_db
    init_db()

    #Routes
    from app.routes import main
    app.register_blueprint(main)
    return app
