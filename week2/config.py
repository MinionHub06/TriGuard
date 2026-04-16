import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY              = os.environ.get('SECRET_KEY') or 'triguard-dev-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///triguard_logs.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    REDIS_URL               = os.environ.get('REDIS_URL') or 'redis://localhost:6379'
    ARTIFACTS_DIR           = os.environ.get('ARTIFACTS_DIR') or '../Week1/artifacts'
    DEBUG                   = os.environ.get('DEBUG', 'true').lower() == 'true'