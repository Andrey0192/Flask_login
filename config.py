import os


class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secret'
    SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://postgres:root@localhost:5432/test_bd'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    FLASK_DEBUG = 1