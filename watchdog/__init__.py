from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
CORS(app)

from flask_socketio import SocketIO
socketio = SocketIO(app, cors_allowed_origins='*')

from flask_sqlalchemy import SQLAlchemy
import os
if os.name == "nt":
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
else:
  app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)

from watchdog import routes
from watchdog.models import *
