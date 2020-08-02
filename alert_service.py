import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
import json
import time
import threading
import os

requests.adapters.DEFAULT_RETRIES = 2

alert_recipients = 'agarwal.yash.2304@gmail.com'
server_shut_down_message = "server is down"
server_anomaly_message = "cpu usage on the server is higher than optimal (90%)"

response = requests.get("https://mock-beml-servers.netlify.app/servers.json")
servers = response.json().get("servers")

cpu_usage_threshold = 85.0

def send_email(title, body, server):
    body += "\n\n Server Details :\n" + str(server)
    msg = MIMEMultipart()

    msg['Subject'] = title
    msg['From'] = 'watchdog.alert.service99@gmail.com'
    msg['To'] = (', ').join(alert_recipients.split(','))

    msg.attach(MIMEText(body,'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login('watchdog.alert.service99@gmail.com', 'watch@ares101')
    server.send_message(msg)
    server.quit()

def check_server(server):
    print("thread started")
    server_ip = server['stats_socket']
    while True:
        try:
            server_system_usage = requests.post("http://"+server_ip+'/getSystemUsage').json()
            if float(server_system_usage['cpu_usage']) > cpu_usage_threshold:
                send_email("High Server Usage", server_anomaly_message, server)
            time.sleep(2)
        except requests.ConnectionError:
            print("server down : ", server)
            send_email("Server Down", server_shut_down_message, server)
            exit(0)

print(servers)

for server in servers:
    thread = threading.Thread(target=check_server, args=(server,))
    thread.start()