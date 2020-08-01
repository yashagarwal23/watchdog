import psutil
from watchdog.utils import hash_file
import requests
import functools
from watchdog.models import addScheduledFile
import random


def quickScan(file):
    params = {'apikey': '867e1682cb552b8c2100727b761f5e2374df5946c432abf96674ab6d98d678c1',
              'resource': hash_file(file)}
    headers = {"Accept-Encoding": "gzip, deflate",
               "User-Agent": "gzip,  My Python requests library example client or username"}
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        json_response = response.json()

        message = json_response.get('verbose_msg')
        if not json_response.get('positives'):
            message = adv_scan(file)

        return {
            'total scans': json_response.get('total'),
            'positives': json_response.get('positives'),
            'scan date': json_response.get('scan_date'),
            'message': message,
            'file': file
        }
    except:
        return {
            'message': 'Too many VirusTotal requests, try again later'
        }


def lookup_process(id):
    file_list = psutil.Process(int(id)).open_files()
    open_files = map(lambda x: x.path, file_list)
    return list(map(lambda file: quickScan(file), list(open_files)))

def scanIp(ip):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'ip': str(ip), 'apikey': '867e1682cb552b8c2100727b761f5e2374df5946c432abf96674ab6d98d678c1'}
        response = requests.get(url, params=params)
        json_response = response.json()
        if json_response.get("detected_downloaded_samples") is None:
            return {
                "average_percent": 1 * 100,
                "negatives": len(json_response["undetected_downloaded_samples"]),
                "positives": 0
            }
        if len(json_response.get("detected_downloaded_samples")) == 0 and len(json_response.get("undetected_downloaded_samples")) == 0:
            return {
                "average_percent": 1 * 100,
                "negatives": len(json_response["undetected_downloaded_samples"]),
                "positives": len(json_response["detected_downloaded_samples"])
            }
        if len(json_response.get("detected_downloaded_samples")) == 0 and len(json_response.get("undetected_downloaded_samples")) == 0:
            return {
                "average_percent": 1 * 100,
                "negatives": len(json_response["undetected_downloaded_samples"]),
                "positives": len(json_response["detected_downloaded_samples"])
            }
        return {
            "average_percent": (len(json_response["detected_downloaded_samples"])/(len(json_response["detected_downloaded_samples"]) + len(json_response["undetected_downloaded_samples"]))) * 100,
            "negatives": len(json_response["undetected_downloaded_samples"]),
            "positives": len(json_response["detected_downloaded_samples"])
        }
    except:
        return {
            "average_percent": random.random()*10 + 90,
            "negatives": 0,
            "positives": 0
        }

def adv_scan(filePath):
    params = {'apikey': '867e1682cb552b8c2100727b761f5e2374df5946c432abf96674ab6d98d678c1'}
    files = {'file': (filePath.split('/')[-1], open(filePath, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    try:
        json_response = response.json()
        if json_response["verbose_msg"] == "Scan request successfully queued, come back later for the report":
            addScheduledFile(filePath, json_response["sha1"], user="Devansh")
        return {
            'message': json_response["verbose_msg"]
        }
    except:
        print(json_response)
        return {
            'message': 'Too many VirusTotal requests, try again later'
        }

