from flask import Flask
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app=app)
migrate = Migrate(app=app, db=db)
manager = Manager(app=app)
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    manager.run()
