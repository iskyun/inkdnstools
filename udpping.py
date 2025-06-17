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

INTERVAL = 1000  #unit ms
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
def udp_ping(target_ip, target_port, packet_len=64, interval=1000, count_limit=10):
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
    
    if not is_ipv6:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    
    results = []
    
    for i in range(count_limit):
        payload = random_string(LEN)
        sock.sendto(payload.encode(), (IP, PORT))
        time_of_send = time.time()
        deadline = time.time() + INTERVAL/1000.0
        received = 0
        rtt = 0.0
        
        while True:
            timeout = deadline - time.time()
            if timeout < 0:
                break
            sock.settimeout(timeout)
            try:
                recv_data, addr = sock.recvfrom(65536)
                if recv_data == payload.encode() and addr[0] == IP and addr[1] == PORT:
                    rtt = ((time.time() - time_of_send) * 1000)
                    received = 1
                    break
            except socket.timeout:
                break
            except:
                pass
        
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
        print("   ./udpping.py 44.55.66.77 4000")
        print('   ./udpping.py 44.55.66.77 4000 "LEN=400;INTERVAL=2000"')
        print("   ./udpping.py fe80::5400:ff:aabb:ccdd 4000")
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

    if not is_ipv6:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    print("UDPping %s via port %d with %d bytes of payload"% (IP, PORT, LEN))
    sys.stdout.flush()

    while True:
        payload = random_string(LEN)
        sock.sendto(payload.encode(), (IP, PORT))
        time_of_send = time.time()
        deadline = time.time() + INTERVAL/1000.0
        received = 0
        rtt = 0.0
        
        while True:
            timeout = deadline - time.time()
            if timeout < 0:
                break
            #print "timeout=",timeout
            sock.settimeout(timeout)
            try:
                recv_data, addr = sock.recvfrom(65536)
                if recv_data == payload.encode() and addr[0] == IP and addr[1] == PORT:
                    rtt = ((time.time() - time_of_send) * 1000)
                    print("Reply from", IP, "seq=%d"%count, "time=%.2f"%(rtt), "ms")
                    sys.stdout.flush()
                    received = 1
                    break
            except socket.timeout:
                break
            except:
                pass
        count += 1
        if received == 1:
            count_of_received += 1
            rtt_sum += rtt
            rtt_max = max(rtt_max, rtt)
            rtt_min = min(rtt_min, rtt)
        else:
            print("Request timed out")
            sys.stdout.flush()

        time_remaining = deadline - time.time()
        if time_remaining > 0:
            time.sleep(time_remaining)
