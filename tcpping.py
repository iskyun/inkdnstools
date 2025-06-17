#!/usr/bin/env python

from __future__ import print_function 

import socket
import sys
import time
import string
import random
import signal
import sys
import os

INTERVAL = 1000  # unit ms
LEN = 64
IP = ""
PORT = 0

count = 0
count_of_received = 0
rtt_sum = 0.0
rtt_min = 99999999.0
rtt_max = 0.0

def signal_handler(signal, frame):
	if count != 0 and count_of_received != 0:
		print('')
		print('--- ping statistics ---')
	if count != 0:
		print('%d packets transmitted, %d received, %.2f%% packet loss'%(count, count_of_received, (count-count_of_received)*100.0/count))
	if count_of_received != 0:
		print('rtt min/avg/max = %.2f/%.2f/%.2f ms'%(rtt_min, rtt_sum/count_of_received, rtt_max))
	os._exit(0)

def random_string(length):
        return ''.join(random.choice(string.ascii_letters + string.digits) for m in range(length))

# 添加一个函数，用于从web.py调用
def tcp_ping(target_ip, target_port, packet_len=64, interval=1000, count_limit=10):
    global IP, PORT, LEN, INTERVAL
    global count, count_of_received, rtt_sum, rtt_min, rtt_max
    
    # 重置全局变量
    count = 0
    count_of_received = 0
    rtt_sum = 0.0
    rtt_min = 99999999.0
    rtt_max = 0.0
    
    IP = target_ip
    PORT = int(target_port)
    LEN = packet_len
    INTERVAL = interval
    
    is_ipv6 = 0
    if IP.find(":") != -1:
        is_ipv6 = 1
    
    if LEN < 5:
        return {"error": "LEN must be >=5"}
    if INTERVAL < 50:
        return {"error": "INTERVAL must be >=50"}
    
    results = []
    
    for i in range(count_limit):
        payload = random_string(LEN)
        
        # 创建TCP套接字
        try:
            if not is_ipv6:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            
            # 设置连接超时
            sock.settimeout(INTERVAL/1000.0)
            
            # 记录发送时间
            time_of_send = time.time()
            
            # 尝试连接
            sock.connect((IP, PORT))
            
            # 发送数据
            sock.sendall(payload.encode())
            
            # 接收数据
            received_data = b""
            while len(received_data) < LEN:
                chunk = sock.recv(LEN - len(received_data))
                if not chunk:
                    break
                received_data += chunk
            
            # 计算RTT
            rtt = ((time.time() - time_of_send) * 1000)
            
            # 检查接收到的数据是否与发送的相同
            received = 0
            if received_data == payload.encode():
                received = 1
            
            # 关闭套接字
            sock.close()
            
        except socket.timeout:
            # 连接超时
            count += 1
            result = {"seq": count, "time": None, "status": "timeout"}
            results.append(result)
            
            # 等待下一次发送
            deadline = time_of_send + INTERVAL/1000.0
            time_remaining = deadline - time.time()
            if time_remaining > 0:
                time.sleep(time_remaining)
            
            continue
        except socket.error as e:
            # 连接错误
            count += 1
            result = {"seq": count, "time": None, "status": "error", "message": str(e)}
            results.append(result)
            
            # 等待下一次发送
            deadline = time_of_send + INTERVAL/1000.0
            time_remaining = deadline - time.time()
            if time_remaining > 0:
                time.sleep(time_remaining)
            
            continue
        
        count += 1
        result = {"seq": count, "time": None, "status": "timeout"}
        
        if received == 1:
            count_of_received += 1
            rtt_sum += rtt
            rtt_max = max(rtt_max, rtt)
            rtt_min = min(rtt_min, rtt)
            result["time"] = round(rtt, 2)
            result["status"] = "success"
        
        results.append(result)
        
        # 等待下一次发送
        deadline = time_of_send + INTERVAL/1000.0
        time_remaining = deadline - time.time()
        if time_remaining > 0:
            time.sleep(time_remaining)
    
    # 计算统计信息
    stats = {
        "transmitted": count,
        "received": count_of_received,
        "loss": round((count - count_of_received) * 100.0 / count, 2) if count > 0 else 0,
        "min": round(rtt_min, 2) if count_of_received > 0 else None,
        "avg": round(rtt_sum / count_of_received, 2) if count_of_received > 0 else None,
        "max": round(rtt_max, 2) if count_of_received > 0 else None
    }
    
    return {"results": results, "stats": stats}

# 主程序入口
if __name__ == "__main__":
    if len(sys.argv) != 3 and len(sys.argv) != 4:
        print(""" usage:""")
        print("""   this_program <dest_ip> <dest_port>""")
        print("""   this_program <dest_ip> <dest_port> \"<options>\" """)

        print()
        print(""" options:""")
        print("""   LEN         the length of payload, unit:byte""")
        print("""   INTERVAL    the seconds waited between sending each packet, as well as the timeout for reply packet, unit: ms""")

        print()
        print(" examples:")
        print("   ./tcpping.py 44.55.66.77 4000")
        print('   ./tcpping.py 44.55.66.77 4000 "LEN=400;INTERVAL=2000"')
        print("   ./tcpping.py fe80::5400:ff:aabb:ccdd 4000")
        print()

        exit()

    IP = sys.argv[1]
    PORT = int(sys.argv[2])

    is_ipv6 = 0

    if IP.find(":") != -1:
        is_ipv6 = 1

    if len(sys.argv) == 4:
        exec(sys.argv[3])
        
    if LEN < 5:
        print("LEN must be >=5")
        exit()
    if INTERVAL < 50:
        print("INTERVAL must be >=50")
        exit()

    signal.signal(signal.SIGINT, signal_handler)

    print("TCPping %s via port %d with %d bytes of payload"% (IP, PORT, LEN))
    sys.stdout.flush()

    while True:
        payload = random_string(LEN)
        
        # 创建TCP套接字
        try:
            if not is_ipv6:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            
            # 设置连接超时
            sock.settimeout(INTERVAL/1000.0)
            
            # 记录发送时间
            time_of_send = time.time()
            
            # 尝试连接
            sock.connect((IP, PORT))
            
            # 发送数据
            sock.sendall(payload.encode())
            
            # 接收数据
            received_data = b""
            while len(received_data) < LEN:
                chunk = sock.recv(LEN - len(received_data))
                if not chunk:
                    break
                received_data += chunk
            
            # 计算RTT
            rtt = ((time.time() - time_of_send) * 1000)
            
            # 检查接收到的数据是否与发送的相同
            if received_data == payload.encode():
                print("Reply from", IP, "seq=%d"%count, "time=%.2f"%(rtt), "ms")
                sys.stdout.flush()
                count_of_received += 1
                rtt_sum += rtt
                rtt_max = max(rtt_max, rtt)
                rtt_min = min(rtt_min, rtt)
            else:
                print("Reply from", IP, "seq=%d"%count, "invalid data received")
                sys.stdout.flush()
            
            # 关闭套接字
            sock.close()
            
        except socket.timeout:
            print("Request timed out")
            sys.stdout.flush()
        except socket.error as e:
            print(f"Connection error: {e}")
            sys.stdout.flush()
        
        count += 1
        
        # 等待下一次发送
        deadline = time_of_send + INTERVAL/1000.0
        time_remaining = deadline - time.time()
        if time_remaining > 0:
            time.sleep(time_remaining)