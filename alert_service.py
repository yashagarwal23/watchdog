import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import requests
import json
import time
import threading
import os
from pywebpush import webpush

import urllib.request
import urllib.parse
import requests
import socketio

from elasticsearch import Elasticsearch

es=Elasticsearch([{'host':'52.152.170.162','port':9200}])

sio = socketio.Client()
print(sio)

requests.adapters.DEFAULT_RETRIES = 2

alert_recipients = 'agarwal.yash.2304@gmail.com,devanshbatra51@gmail.com'
server_shut_down_message = "server is down"
server_anomaly_message = "cpu usage on the server is higher than optimal (90%)"

response = requests.get("https://mock-beml-servers.netlify.app/servers.json")
servers = response.json().get("servers")

cpu_usage_threshold = 90.0

sms_api_key = 'r8boLSAcAds-AtyHq4P7s10iefTuRHmrdgyx3y4MLU'
# sms_numbers = '919729191021'
sms_numbers = '917988691391'

def sendSMS(server):
    message = server['name'] + ' is down'
    print(message)
    data =  urllib.parse.urlencode({'apikey': sms_api_key, 'numbers': sms_numbers,
        'message' : message})
    data = data.encode('utf-8')
    request = urllib.request.Request("https://api.textlocal.in/send/?")
    f = urllib.request.urlopen(request, data)
    fr = f.read()
    return(fr)
 
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

def send_notification(title, body):
    notif_urls = es.search(index='notif_url', size=20)['hits']['hits']
    for notif_url in notif_urls:
        data = {
            "title": title,
            "text": body
        }
        webpush(subInfo, json.dumps(data))

def check_server(server):
    print("thread started")
    server_ip = server['stats_socket']
    while True:
        try:
            server_system_usage = requests.post("http://"+server_ip+'/getSystemUsage').json()
            if float(server_system_usage['cpu_usage']) > cpu_usage_threshold:
                send_email("High Server Usage", server_anomaly_message, server)
                message = "high cpu usage[{}] on the server {}".format(server_system_usage['cpu_usage'], server['name'])
                send_notification("High Server Usage", message, server)
            time.sleep(2)
        except requests.ConnectionError:
            print("server down : ", server)
            send_email("Server Down", server_shut_down_message, server)
            resp =  sendSMS(server)
            print(resp)
            message = "server {}, IP : {} is down".format(server['name'], server['IP'])
            exit(0)

print(servers)

for server in servers:
    thread = threading.Thread(target=check_server, args=(server,))
    thread.start()


# @sio.on('push subscription')
# def get_file(endpoint):
#     saveFile = open('pushSubscription', 'w')
#     saveFile.write(endpoint)

# sio.connect(servers[2]['stats_socket'])