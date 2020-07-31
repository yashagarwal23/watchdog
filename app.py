from watchdog import socketio, app
from watchdog.routes import returnSystemUsage
from watchdog.log_network import start_logger


system_usage_thread = socketio.start_background_task(returnSystemUsage)
packet_sniffer_thread = socketio.start_background_task(start_logger)

socketio.run(app, host='0.0.0.0')