import os

base_dir = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.join(base_dir, 'data.db')
DEBUG = True
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = r'sqlite:///' + db_dir
