from watchdog import socketio, app
from watchdog.routes import returnSystemUsage


thread = socketio.start_background_task(returnSystemUsage)
socketio.run(app, host='0.0.0.0')