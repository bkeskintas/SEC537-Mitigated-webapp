import os
from flask import Flask, render_template_string, request
from datetime import timedelta
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from dotenv import load_dotenv

limiter = Limiter(
    key_func=get_remote_address,  # IP adresine göre sınırlandırma
    default_limits=["100 per hour"]  # Varsayılan limit
)

load_dotenv()

def create_app():
    app = Flask(__name__)

    # Security Configurations
    app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'  # Debug mode
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
    app.config['SESSION_COOKIE_SECURE'] = True  #Send cookies only over HTTPS
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session lifetime
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  #limit file uploads to 10 MB
    app.config['RECAPTCHA_SITE_KEY'] = os.getenv('RECAPTCHA_SITE_KEY')  # Recaptcha site key
    app.config['RECAPTCHA_SECRET_KEY'] = os.getenv('RECAPTCHA_SECRET_KEY')  # Recaptcha secret key
    app.config['VERIFY_URL'] = os.getenv('VERIFY_URL')  # Recaptcha verification URL


    limiter.init_app(app)  # Limiter ile Flask uygulamasını bağla


    # Initialize database setup
    from app.database import init_db
    init_db()

    # Configure Logging
    logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Register Routes
    from app.routes import main
    app.register_blueprint(main)

    # Global Error Handlers (Fail Securely)
    @app.errorhandler(404)
    def global_page_not_found(e):
        logging.warning(f"Page not found: {request.path}")  # Log 404 errors for auditing
        return render_template_string(f"The page '{request.path}' does not exist."), 404

    @app.errorhandler(500)
    def global_internal_server_error(e):
        logging.error("Internal server error occurred. Ensure detailed logs are reviewed securely.")
        return "An unexpected error occurred. Please try again later.", 500
    
    @app.errorhandler(RateLimitExceeded)
    def rate_limit_exceeded(e):
        logging.error(f"Too many attempts from user.")
        # Log 500 errors for auditing
        return render_template_string("Siteye aşırı seviyede istekte bulundunuz. Sonra tekrar deneyiniz."), 429

    # Default route for testing
    @app.route('/health', methods=['GET'])
    def health_check():
        return "Application is running securely!"
    
  
    return app
