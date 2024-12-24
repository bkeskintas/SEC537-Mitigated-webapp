import os
from flask import Flask, render_template_string, request
from datetime import timedelta
import logging

def create_app():
    app = Flask(__name__)

    # Security Configurations
    app.config['DEBUG'] = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'  # Use environment variable for debug mode
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))  # Use environment variable or secure random key
    app.config['UPLOAD_FOLDER'] = '/secure/uploads'  # Secure folder for uploads
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
    app.config['SESSION_COOKIE_SECURE'] = True  # Send cookies only over HTTPS
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes
    app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # Limit file uploads to 10 MB

    # Create upload folder if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

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
        logging.error(f"Internal server error: {str(e)}")  # Log 500 errors for auditing
        return "An unexpected error occurred. Please try again later.", 500

    # Default route for testing
    @app.route('/health', methods=['GET'])
    def health_check():
        return "Application is running securely!"

    return app
