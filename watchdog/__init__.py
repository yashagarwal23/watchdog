from flask import Flask
app = Flask(__name__)

from flask_socketio import SocketIO
socketio = SocketIO(app, cors_allowed_origins='*')

from flask_sqlalchemy import SQLAlchemy
import os
if os.name == "nt":
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
else:
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)

from watchdog import routes, schedulers
from watchdog.models import addToBlacklist