import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'app', 'static', 'uploaded_files')
    ALLOWED_EXTENSIONS = {'txt', 'png', 'jpg', 'jpeg', 'gif'}