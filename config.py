import os

base_dir = os.path.abspath(os.path.dirname(__file__))
db_dir = os.path.join(base_dir, 'data.db')
DEBUG = True
SECRET_KEY = 'who can guess!'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SQLALCHEMY_DATABASE_URI = r'sqlite:///' + db_dir
print(SQLALCHEMY_DATABASE_URI)
