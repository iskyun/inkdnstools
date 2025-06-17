#!/usr/bin/env python

from flask import Flask, render_template, jsonify, request
import udpping
import udpdns
import tcpdns
import httpsdns
import tcpping
import threading
import json

app = Flask(__name__)

# 存储测试结果的全局变量
ping_results = {}
ping_threads = {}
tcp_ping_results = {}
tcp_ping_threads = {}
dns_results = {}
dns_threads = {}
tcp_dns_results = {}
tcp_dns_threads = {}
https_dns_results = {}
https_dns_threads = {}

@app.route('/')
def index():
    return render_template('index.html')

# UDP Ping 相关API
@app.route('/api/ping', methods=['POST'])
def start_ping():
    data = request.json
    ip = data.get('ip')
    port = data.get('port')
    packet_len = data.get('packet_len', 64)
    interval = data.get('interval', 1000)
    count = data.get('count', 10)
    
    if not ip or not port:
        return jsonify({"error": "IP和端口是必须的"}), 400
    
    try:
        port = int(port)
        packet_len = int(packet_len)
        interval = int(interval)
        count = int(count)
    except ValueError:
        return jsonify({"error": "端口、包长度、间隔和计数必须是整数"}), 400
    
    # 创建一个唯一的测试ID
    test_id = f"{ip}:{port}_{threading.get_ident()}"
    
    # 启动一个新线程来执行ping测试
    def run_ping_test():
        try:
            result = udpping.udp_ping(ip, port, packet_len, interval, count)
            ping_results[test_id] = result
        except Exception as e:
            ping_results[test_id] = {"error": str(e)}
    
    thread = threading.Thread(target=run_ping_test)
    thread.daemon = True
    thread.start()
    ping_threads[test_id] = thread
    
    return jsonify({"test_id": test_id, "status": "started"})

@app.route('/api/ping/status/<test_id>')
def get_ping_status(test_id):
    if test_id in ping_results:
        # 如果测试已完成，返回结果
        return jsonify({"status": "completed", "result": ping_results[test_id]})
    elif test_id in ping_threads:
        # 如果测试正在进行中
        if ping_threads[test_id].is_alive():
            return jsonify({"status": "running"})
        else:
            # 线程已结束但没有结果，可能出错了
            return jsonify({"status": "error", "message": "测试异常终止"})
    else:
        # 找不到测试ID
        return jsonify({"status": "not_found"}), 404

@app.route('/api/ping/cancel/<test_id>', methods=['POST'])
def cancel_ping(test_id):
    if test_id in ping_threads and ping_threads[test_id].is_alive():
        # 无法直接终止线程，但可以从字典中移除
        del ping_threads[test_id]
        return jsonify({"status": "cancelled"})
    else:
        return jsonify({"status": "not_found"}), 404

# UDP DNS 测试相关API
@app.route('/api/dns', methods=['POST'])
def start_dns_test():
    data = request.json
    domain = data.get('domain')
    server = data.get('server')
    port = data.get('port', 53)
    query_type = data.get('query_type', 'A')
    count = data.get('count', 5)
    interval = data.get('interval', 1000)
    
    if not domain or not server:
        return jsonify({"error": "域名和DNS服务器是必须的"}), 400
    
    try:
        port = int(port)
        count = int(count)
        interval = int(interval)
    except ValueError:
        return jsonify({"error": "端口、查询次数和间隔必须是整数"}), 400
    
    # 创建一个唯一的测试ID
    test_id = f"{domain}@{server}:{port}_{threading.get_ident()}"
    
    # 启动一个新线程来执行DNS测试
    def run_dns_test():
        try:
            result = udpdns.dns_test(domain, server, port, query_type, count, interval)
            dns_results[test_id] = result
        except Exception as e:
            dns_results[test_id] = {"error": str(e)}
    
    thread = threading.Thread(target=run_dns_test)
    thread.daemon = True
    thread.start()
    dns_threads[test_id] = thread
    
    return jsonify({"test_id": test_id, "status": "started"})

@app.route('/api/dns/status/<test_id>')
def get_dns_status(test_id):
    if test_id in dns_results:
        # 如果测试已完成，返回结果
        return jsonify({"status": "completed", "result": dns_results[test_id]})
    elif test_id in dns_threads:
        # 如果测试正在进行中
        if dns_threads[test_id].is_alive():
            return jsonify({"status": "running"})
        else:
            # 线程已结束但没有结果，可能出错了
            return jsonify({"status": "error", "message": "测试异常终止"})
    else:
        # 找不到测试ID
        return jsonify({"status": "not_found"}), 404

@app.route('/api/dns/cancel/<test_id>', methods=['POST'])
def cancel_dns_test(test_id):
    if test_id in dns_threads and dns_threads[test_id].is_alive():
        # 无法直接终止线程，但可以从字典中移除
        del dns_threads[test_id]
        return jsonify({"status": "cancelled"})
    else:
        return jsonify({"status": "not_found"}), 404

# TCP DNS 测试相关API
@app.route('/api/tcpdns', methods=['POST'])
def start_tcp_dns_test():
    data = request.json
    domain = data.get('domain')
    server = data.get('server')
    port = data.get('port', 53)
    query_type = data.get('query_type', 'A')
    count = data.get('count', 5)
    interval = data.get('interval', 1000)
    
    if not domain or not server:
        return jsonify({"error": "域名和DNS服务器是必须的"}), 400
    
    try:
        port = int(port)
        count = int(count)
        interval = int(interval)
    except ValueError:
        return jsonify({"error": "端口、查询次数和间隔必须是整数"}), 400
    
    # 创建一个唯一的测试ID
    test_id = f"tcp_{domain}@{server}:{port}_{threading.get_ident()}"
    
    # 启动一个新线程来执行TCP DNS测试
    def run_tcp_dns_test():
        try:
            result = tcpdns.tcp_dns_test(domain, server, port, query_type, count, interval)
            tcp_dns_results[test_id] = result
        except Exception as e:
            tcp_dns_results[test_id] = {"error": str(e)}
    
    thread = threading.Thread(target=run_tcp_dns_test)
    thread.daemon = True
    thread.start()
    tcp_dns_threads[test_id] = thread
    
    return jsonify({"test_id": test_id, "status": "started"})

@app.route('/api/tcpdns/status/<test_id>')
def get_tcp_dns_status(test_id):
    if test_id in tcp_dns_results:
        # 如果测试已完成，返回结果
        return jsonify({"status": "completed", "result": tcp_dns_results[test_id]})
    elif test_id in tcp_dns_threads:
        # 如果测试正在进行中
        if tcp_dns_threads[test_id].is_alive():
            return jsonify({"status": "running"})
        else:
            # 线程已结束但没有结果，可能出错了
            return jsonify({"status": "error", "message": "测试异常终止"})
    else:
        # 找不到测试ID
        return jsonify({"status": "not_found"}), 404

@app.route('/api/tcpdns/cancel/<test_id>', methods=['POST'])
def cancel_tcp_dns_test(test_id):
    if test_id in tcp_dns_threads and tcp_dns_threads[test_id].is_alive():
        # 无法直接终止线程，但可以从字典中移除
        del tcp_dns_threads[test_id]
        return jsonify({"status": "cancelled"})
    else:
        return jsonify({"status": "not_found"}), 404

# HTTPS DNS (DoH) 测试相关API
@app.route('/api/httpsdns', methods=['POST'])
def start_https_dns_test():
    data = request.json
    domain = data.get('domain')
    doh_url = data.get('doh_url')
    query_type = data.get('query_type', 'A')
    count = data.get('count', 5)
    interval = data.get('interval', 1000)
    use_wire_format = data.get('use_wire_format', False)
    
    if not domain:
        return jsonify({"error": "域名是必须的"}), 400
    
    try:
        count = int(count)
        interval = int(interval)
    except ValueError:
        return jsonify({"error": "查询次数和间隔必须是整数"}), 400
    
    # 创建一个唯一的测试ID
    server_name = doh_url.split('//')[1].split('/')[0] if doh_url else 'default'
    test_id = f"https_{domain}@{server_name}_{threading.get_ident()}"
    
    # 启动一个新线程来执行HTTPS DNS测试
    def run_https_dns_test():
        try:
            result = httpsdns.https_dns_test(domain, doh_url, query_type, count, interval, use_wire_format)
            https_dns_results[test_id] = result
        except Exception as e:
            https_dns_results[test_id] = {"error": str(e)}
    
    thread = threading.Thread(target=run_https_dns_test)
    thread.daemon = True
    thread.start()
    https_dns_threads[test_id] = thread
    
    return jsonify({"test_id": test_id, "status": "started"})

@app.route('/api/httpsdns/status/<test_id>')
def get_https_dns_status(test_id):
    if test_id in https_dns_results:
        # 如果测试已完成，返回结果
        return jsonify({"status": "completed", "result": https_dns_results[test_id]})
    elif test_id in https_dns_threads:
        # 如果测试正在进行中
        if https_dns_threads[test_id].is_alive():
            return jsonify({"status": "running"})
        else:
            # 线程已结束但没有结果，可能出错了
            return jsonify({"status": "error", "message": "测试异常终止"})
    else:
        # 找不到测试ID
        return jsonify({"status": "not_found"}), 404

@app.route('/api/httpsdns/cancel/<test_id>', methods=['POST'])
def cancel_https_dns_test(test_id):
    if test_id in https_dns_threads and https_dns_threads[test_id].is_alive():
        # 无法直接终止线程，但可以从字典中移除
        del https_dns_threads[test_id]
        return jsonify({"status": "cancelled"})
    else:
        return jsonify({"status": "not_found"}), 404

# TCP Ping 相关API
@app.route('/api/tcpping', methods=['POST'])
def start_tcp_ping():
    data = request.json
    ip = data.get('ip')
    port = data.get('port')
    packet_len = data.get('packet_len', 64)
    interval = data.get('interval', 1000)
    count = data.get('count', 10)
    
    if not ip or not port:
        return jsonify({"error": "IP和端口是必须的"}), 400
    
    try:
        port = int(port)
        packet_len = int(packet_len)
        interval = int(interval)
        count = int(count)
    except ValueError:
        return jsonify({"error": "端口、包长度、间隔和计数必须是整数"}), 400
    
    # 创建一个唯一的测试ID
    test_id = f"tcp_{ip}:{port}_{threading.get_ident()}"
    
    # 启动一个新线程来执行ping测试
    def run_tcp_ping_test():
        try:
            result = tcpping.tcp_ping(ip, port, packet_len, interval, count)
            tcp_ping_results[test_id] = result
        except Exception as e:
            tcp_ping_results[test_id] = {"error": str(e)}
    
    thread = threading.Thread(target=run_tcp_ping_test)
    thread.daemon = True
    thread.start()
    tcp_ping_threads[test_id] = thread
    
    return jsonify({"test_id": test_id, "status": "started"})

@app.route('/api/tcpping/status/<test_id>')
def get_tcp_ping_status(test_id):
    if test_id in tcp_ping_results:
        # 如果测试已完成，返回结果
        return jsonify({"status": "completed", "result": tcp_ping_results[test_id]})
    elif test_id in tcp_ping_threads:
        # 如果测试正在进行中
        if tcp_ping_threads[test_id].is_alive():
            return jsonify({"status": "running"})
        else:
            # 线程已结束但没有结果，可能出错了
            return jsonify({"status": "error", "message": "测试异常终止"})
    else:
        # 找不到测试ID
        return jsonify({"status": "not_found"}), 404

@app.route('/api/tcpping/cancel/<test_id>', methods=['POST'])
def cancel_tcp_ping(test_id):
    if test_id in tcp_ping_threads and tcp_ping_threads[test_id].is_alive():
        # 无法直接终止线程，但可以从字典中移除
        del tcp_ping_threads[test_id]
        return jsonify({"status": "cancelled"})
    else:
        return jsonify({"status": "not_found"}), 404

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)