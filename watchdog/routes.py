import os
import time
import json
from watchdog.utils import convertforWindows, getcountry, fetchScanResults, getSuspectFiles, getCompany

from flask import request, jsonify, Response
from watchdog import app, socketio
from watchdog.virustotal import lookup_process, adv_scan, quickScan, scanIp as virusTotalIPScan
from watchdog.models import addToBlacklist, removeFromBlacklist, getRules, getScheduledFiles, removeFileFromScheduled, getbadIphealth
import psutil
from os.path import expanduser
from watchdog.models import getbadIphealth
import pygal
import pycountry

@app.route('/getProcesses', methods=['GET', 'POST'])
def getprocesses():
    if request.method == 'POST' and os.name == 'nt':
        pids = psutil.pids()
        result = list(map(convertforWindows, pids))
        return jsonify(
            {
                "processes" : list(filter(lambda x: len(x['remoteAddr']), list(filter(lambda x : x != None and x['PID'] != "None", result))))
            }
        )
    elif request.method == 'POST':
        processes = psutil.net_connections("all")
        result = list(map(convert, processes))
        return jsonify(
            {
                "processes": list(filter(lambda x: len(x['remoteAddr']), list(filter(lambda x : x != None and x['PID'] != "None", result))))
            }
        )

@socketio.on("connect")
def connect():
    print("connected")

@socketio.on("disconnect")
def disconnect():
    print("disconnected")
    
@app.route("/getSystemUsage", methods=['POST'])
def getSystemUsage():
    cpu_usage = psutil.cpu_percent(interval=0.5, percpu=True)
    n_c = tuple(psutil.disk_io_counters())
    n_b = tuple(psutil.net_io_counters())
    return json.dumps(
        {
            "num_process": str(len(list(psutil.net_connections()))),
            "cpu_usage": str(sum(cpu_usage)/ len(cpu_usage)),
            "memory_usage": str(psutil.virtual_memory().percent),
            "disk_io_percent": [(100.0*n_c[i+1]) / (n_c[i] if n_c[i] != 0 else 1) for i in range(0, len(n_c)-1, 2)],
            "network_io_percent": [(100.0*n_b[i+1]) / (n_b[i] if n_b[i] != 0 else 1) for i in range(0, len(n_b)-1, 2)]
        }
    )

def returnSystemUsage():
    print("thread started")
    while True:
        socketio.emit("system usage", getSystemUsage(), broadcast=True)
        time.sleep(0.5)

@app.route('/getProcessUsage', methods=['POST'])
def getProcessUsageStats():
    # TODO implement full function
    if request.method == 'POST':
        pid = int(request.form.get('PID'))
        process = psutil.Process(pid=pid)
        return jsonify(
            {
                "cpu_usage": process.cpu_percent(interval=1)/psutil.cpu_count(),
                "memory_usage": str(int(process.memory_info().rss) / ( 1024 * 1024 ))+ " MB" ,
                # "disk_io_percent": [(100.0 * n_c[i + 1]) / (n_c[i] if n_c[i] != 0 else 1) for i in range(0, len(n_c) - 1, 2)],
                # "network_io_percent": ""
                "user": process.username(),
                "num_threads": process.num_threads(),
                "create_time": process.create_time()
            }
        )

@app.route('/lookupProcess', methods=['POST'])
def quickscan():
    if request.method == 'POST':
        return jsonify(
            {
                "results":  lookup_process(request.form.get('PID'))
            }
        )


@app.route('/blockIP', methods=['POST'])
def block_ip():
    if request.form.get('IP') == None:
        return "IP not specified"
    response = addToBlacklist(request.form.get('IP'), request.form.get('port') if request.form.get('port') != None else "*")
    return response


@app.route('/unblockIP', methods=['POST'])
def unblock_ip():
    response = removeFromBlacklist(request.form.get('IP'), request.form.get('port') if request.form.get('port') != None else "*")
    return response


@app.route('/getRules', methods=['POST'])
def get_rules():
    return jsonify(
        {
            "rules": list(getRules())
        }
    )


@app.route('/advancedScan', methods=['POST'])
def advanced_scan():
    return jsonify(adv_scan(request.form.get('filepath')))


@app.route('/getScheduledFiles', methods=['POST'])
def getS():
    return jsonify(
        {
            "files": getScheduledFiles()
        }
    )

@app.route('/removeFromScheduledFilesList', methods=['POST'])
def removeFromList():
    removeFileFromScheduled(request.form.get('filepath'))
    return "removed from list"


@app.route('/deleteFile', methods=['POST'])
def deleteme():
    try:
        os.remove(expanduser(request.form.get('filepath')))
        return "deleted"
    except:
        return "file not found"

@app.route('/scanIP', methods=['POST'])
def scanIP():
    return jsonify({
        "results": virusTotalIPScan(request.form.get('IP'))
    })


@app.route('/getReport', methods=['POST'])
def quick_scan():
    return jsonify(quickScan(request.form.get('filepath')))


@app.route('/killProcess', methods=['POST'])
def killProcess():
    try:
        pid = int(request.form.get('PID'))
        process = psutil.Process(pid)
        process.kill()
        return "process terminated"
    except:
        return "some error occured. Make sure you have sudo priviledge"


@app.route('/getchkrScanResults', methods=['POST'])
def chkscan():
    scan()
    return jsonify({
        "results": fetchScanResults("~/chkrootkitLogs/fileLog.txt")
    })


@app.route('/chkrScan', methods=['POST'])
def scan():
    os.system(expanduser("./watchdog/chkrootkit2 -q"))
    return "Scan Complete"


@app.route('/getSuspectFiles', methods=['POST'])
def getf():
    if request.method == 'POST':
        ans = []
        for e in getSuspectFiles(' '):
            if isinstance(e, list):
                for i in e:
                    ans.append(i)
            else:
                ans.append(e)
        return jsonify(
            {
                "files": ans
            })


def countries():
    processes = psutil.net_connections()
    s = {}
    result = list(map(convert, processes))
    for item in result:
        if dict(item)["country"] == "" or dict(item)["country"] == "local address":
            continue
        s[dict(item)["country"]] = len(list(filter(lambda x: x["country"] == item["country"], result)))
    return {
            "results": s
        }

@app.route('/getConnectedCountries', methods=['POST'])
def get_connected_countries():
    return jsonify(countries())

@app.route('/getCountryMap', methods=['POST', 'GET'])
def country_distribution():
    countries_map = countries()
    country_data = {}
    for key, value in countries_map["results"].items():
        if len(key.split(' ')) <= 4:
            country_data[key] = value
    print(country_data)
    worldmap_chart = pygal.maps.world.World()
    worldmap_chart.title = 'Countries connected'
    for key in country_data:
        country = key
        occurence = country_data[str(key)]
        if pycountry.countries.get(name=country) == None:
            continue
        worldmap_chart.add('{} {}'.format(country, occurence), [ str(pycountry.countries.get(name=country).alpha_2.lower()) ])
    return worldmap_chart.render_response()

def convert(process):
    country = ''
    company = ''
    try:
        if process.raddr and process.raddr.ip == '127.0.0.1':
            country = company = "local address"
        elif process.raddr:
            country = getcountry(process.raddr.ip)
            company = getCompany(process.raddr.ip)
    except:
        country = "could not trace in current database"

    return {
        # TODO return correct connection type/protocol also
        'localAddr': process.laddr,
        'remoteAddr': process.raddr,
        'PID': str(process.pid),
        'status': process.status,
        'country': country,
        "Pname": psutil.Process(process.pid).name(),
        "User": psutil.Process(process.pid).username(),
        "cType": "tcp",
        'company': company,
        "health": getbadIphealth(process.raddr.ip if process.raddr else 0)
    }

@app.route('/pushSubscription', methods=['POST'])
def pushSubscription():
    if request.method == 'POST':
        saveFile = open('pushSubscription', 'w')
        saveFile.write(json.dumps(request.get_json(force=True)))
    return Response("{'result': true", status=200, mimetype='application/json')
