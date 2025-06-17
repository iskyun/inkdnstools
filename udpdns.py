#!/usr/bin/env python

from __future__ import print_function

import socket
import sys
import time
import string
import random
import struct
import binascii

# DNS查询类型
QTYPE_A = 1      # IPv4地址
QTYPE_NS = 2     # 域名服务器
QTYPE_CNAME = 5  # 规范名称
QTYPE_SOA = 6    # 权威记录开始
QTYPE_PTR = 12   # 指针记录
QTYPE_MX = 15    # 邮件交换
QTYPE_TXT = 16   # 文本记录
QTYPE_AAAA = 28  # IPv6地址
QTYPE_ANY = 255  # 任何记录

# DNS查询类型名称映射
QTYPE_NAMES = {
    QTYPE_A: "A",
    QTYPE_NS: "NS",
    QTYPE_CNAME: "CNAME",
    QTYPE_SOA: "SOA",
    QTYPE_PTR: "PTR",
    QTYPE_MX: "MX",
    QTYPE_TXT: "TXT",
    QTYPE_AAAA: "AAAA",
    QTYPE_ANY: "ANY"
}

# DNS响应代码
RCODE_NOERROR = 0   # 没有错误
RCODE_FORMERR = 1   # 格式错误
RCODE_SERVFAIL = 2  # 服务器失败
RCODE_NXDOMAIN = 3  # 不存在的域名
RCODE_NOTIMP = 4    # 未实现
RCODE_REFUSED = 5   # 查询被拒绝

# DNS响应代码名称映射
RCODE_NAMES = {
    RCODE_NOERROR: "NOERROR",
    RCODE_FORMERR: "FORMERR",
    RCODE_SERVFAIL: "SERVFAIL",
    RCODE_NXDOMAIN: "NXDOMAIN",
    RCODE_NOTIMP: "NOTIMP",
    RCODE_REFUSED: "REFUSED"
}

# 生成随机DNS查询ID
def generate_query_id():
    return random.randint(0, 65535)

# 将域名转换为DNS查询格式
def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.split("."):
        encoded += struct.pack("B", len(part)) + part.encode()
    return encoded + b"\x00"

# 从DNS响应中解析域名
def decode_dns_name(message, offset):
    name_parts = []
    while True:
        length = message[offset]
        if length == 0:
            offset += 1
            break
        # 处理压缩指针 (0xC0 = 192)
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            offset += 2
            # 递归解析指针指向的域名
            pointed_parts, _ = decode_dns_name(message, pointer)
            name_parts.extend(pointed_parts)
            break
        else:
            offset += 1
            name_part = message[offset:offset + length].decode()
            name_parts.append(name_part)
            offset += length
    return name_parts, offset

# 解析DNS响应
def parse_dns_response(response):
    if len(response) < 12:
        return {"error": "响应太短，无法解析"}
    
    # 解析DNS头部
    header = struct.unpack("!HHHHHH", response[:12])
    query_id = header[0]
    flags = header[1]
    qdcount = header[2]  # 问题数
    ancount = header[3]  # 回答数
    nscount = header[4]  # 授权记录数
    arcount = header[5]  # 附加记录数
    
    # 解析响应代码
    rcode = flags & 0x0F
    rcode_name = RCODE_NAMES.get(rcode, f"未知({rcode})")
    
    # 检查是否为响应
    is_response = (flags & 0x8000) != 0
    if not is_response:
        return {"error": "不是DNS响应"}
    
    # 检查响应代码
    if rcode != RCODE_NOERROR:
        return {
            "id": query_id,
            "status": "error",
            "rcode": rcode,
            "rcode_name": rcode_name,
            "message": f"DNS服务器返回错误: {rcode_name}"
        }
    
    # 跳过问题部分
    offset = 12
    for _ in range(qdcount):
        # 跳过查询名称
        while offset < len(response):
            length = response[offset]
            if length == 0 or (length & 0xC0) == 0xC0:
                if (length & 0xC0) == 0xC0:
                    offset += 2
                else:
                    offset += 1
                break
            offset += length + 1
        # 跳过查询类型和类
        offset += 4
    
    # 解析回答部分
    answers = []
    for _ in range(ancount):
        try:
            # 解析记录名称
            name_parts, offset = decode_dns_name(response, offset)
            name = ".".join(name_parts)
            
            # 解析记录类型、类、TTL和数据长度
            if offset + 10 > len(response):
                break
            record_type, record_class, ttl, rdlength = struct.unpack("!HHIH", response[offset:offset+10])
            offset += 10
            
            # 解析记录数据
            record_data = ""
            if record_type == QTYPE_A and rdlength == 4:
                # IPv4地址
                ip_bytes = response[offset:offset+rdlength]
                record_data = ".".join(str(b) for b in ip_bytes)
            elif record_type == QTYPE_AAAA and rdlength == 16:
                # IPv6地址
                ip_bytes = response[offset:offset+rdlength]
                record_data = ":"
                for i in range(0, 16, 2):
                    record_data += f"{ip_bytes[i]:02x}{ip_bytes[i+1]:02x}"
                    if i < 14:
                        record_data += ":"
            elif record_type == QTYPE_MX:
                # 邮件交换记录
                preference = struct.unpack("!H", response[offset:offset+2])[0]
                mx_parts, _ = decode_dns_name(response, offset+2)
                record_data = f"{preference} {'.'.join(mx_parts)}"
            elif record_type in [QTYPE_NS, QTYPE_CNAME, QTYPE_PTR]:
                # 域名指针
                name_parts, _ = decode_dns_name(response, offset)
                record_data = ".".join(name_parts)
            elif record_type == QTYPE_TXT:
                # 文本记录
                txt_length = response[offset]
                record_data = response[offset+1:offset+1+txt_length].decode(errors='replace')
            else:
                # 其他记录类型，以十六进制显示
                record_data = binascii.hexlify(response[offset:offset+rdlength]).decode()
            
            answers.append({
                "name": name,
                "type": QTYPE_NAMES.get(record_type, str(record_type)),
                "class": record_class,
                "ttl": ttl,
                "data": record_data
            })
            
            offset += rdlength
        except Exception as e:
            answers.append({"error": f"解析记录时出错: {str(e)}"})
            break
    
    return {
        "id": query_id,
        "status": "success",
        "rcode": rcode,
        "rcode_name": rcode_name,
        "answers": answers,
        "answer_count": len(answers)
    }

# 创建DNS查询包
def create_dns_query(domain, query_type=QTYPE_A):
    # 生成随机查询ID
    query_id = generate_query_id()
    
    # 构建DNS头部
    # 标志: 标准查询，递归期望
    flags = 0x0100
    qdcount = 1  # 一个问题
    ancount = 0  # 没有回答
    nscount = 0  # 没有授权记录
    arcount = 0  # 没有附加记录
    
    header = struct.pack("!HHHHHH", query_id, flags, qdcount, ancount, nscount, arcount)
    
    # 构建问题部分
    question = encode_dns_name(domain)
    question += struct.pack("!HH", query_type, 1)  # 类型和类(1=IN)
    
    return query_id, header + question

# 执行DNS查询
def dns_query(domain, server_ip, server_port=53, query_type=QTYPE_A, timeout=5):
    try:
        # 创建UDP套接字
        is_ipv6 = server_ip.find(":") != -1
        if not is_ipv6:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        
        sock.settimeout(timeout)
        
        # 创建DNS查询包
        query_id, query_packet = create_dns_query(domain, query_type)
        
        # 发送查询
        start_time = time.time()
        sock.sendto(query_packet, (server_ip, server_port))
        
        # 接收响应
        response, addr = sock.recvfrom(4096)
        end_time = time.time()
        rtt = (end_time - start_time) * 1000  # 毫秒
        
        # 解析响应
        parsed = parse_dns_response(response)
        
        # 检查响应ID是否匹配
        if parsed.get("id") != query_id:
            return {
                "status": "error",
                "message": f"响应ID不匹配: 预期{query_id}，收到{parsed.get('id')}"
            }
        
        # 添加RTT信息
        parsed["rtt"] = round(rtt, 2)
        return parsed
        
    except socket.timeout:
        return {"status": "timeout", "message": "查询超时"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        sock.close()

# 执行多次DNS查询并返回统计信息
def dns_test(domain, server_ip, server_port=53, query_type=QTYPE_A, count=5, interval=1000):
    results = []
    success_count = 0
    total_rtt = 0
    min_rtt = float('inf')
    max_rtt = 0
    
    query_type_code = query_type
    if isinstance(query_type, str):
        # 将字符串类型转换为代码
        query_type_code = next((code for code, name in QTYPE_NAMES.items() if name == query_type), QTYPE_A)
    
    for i in range(count):
        result = dns_query(domain, server_ip, server_port, query_type_code)
        result["seq"] = i + 1
        
        if result["status"] == "success":
            success_count += 1
            rtt = result["rtt"]
            total_rtt += rtt
            min_rtt = min(min_rtt, rtt)
            max_rtt = max(max_rtt, rtt)
        
        results.append(result)
        
        # 等待指定的间隔时间
        if i < count - 1:
            time.sleep(interval / 1000.0)
    
    # 计算统计信息
    stats = {
        "transmitted": count,
        "received": success_count,
        "loss": round((count - success_count) * 100.0 / count, 2) if count > 0 else 0
    }
    
    if success_count > 0:
        stats["min_rtt"] = round(min_rtt, 2)
        stats["avg_rtt"] = round(total_rtt / success_count, 2)
        stats["max_rtt"] = round(max_rtt, 2)
    
    return {
        "domain": domain,
        "server": server_ip,
        "port": server_port,
        "query_type": QTYPE_NAMES.get(query_type_code, str(query_type_code)),
        "results": results,
        "stats": stats
    }

# 命令行入口
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python udpdns.py <域名> <DNS服务器IP> [端口] [查询类型] [查询次数] [间隔(ms)]")
        print("示例: python udpdns.py example.com 8.8.8.8")
        print("示例: python udpdns.py example.com 8.8.8.8 53 A 5 1000")
        sys.exit(1)
    
    domain = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = int(sys.argv[3]) if len(sys.argv) > 3 else 53
    query_type_str = sys.argv[4] if len(sys.argv) > 4 else "A"
    count = int(sys.argv[5]) if len(sys.argv) > 5 else 5
    interval = int(sys.argv[6]) if len(sys.argv) > 6 else 1000
    
    # 将查询类型字符串转换为代码
    query_type = next((code for code, name in QTYPE_NAMES.items() if name == query_type_str), QTYPE_A)
    
    print(f"正在查询 {domain} 的 {query_type_str} 记录，使用DNS服务器 {server_ip}:{server_port}...")
    
    results = dns_test(domain, server_ip, server_port, query_type, count, interval)
    
    # 打印结果
    for result in results["results"]:
        if result["status"] == "success":
            print(f"查询 {result['seq']}: 成功，RTT = {result['rtt']} ms，找到 {len(result['answers'])} 条记录")
            for answer in result["answers"]:
                print(f"  {answer['name']} {answer['ttl']} IN {answer['type']} {answer['data']}")
        else:
            print(f"查询 {result['seq']}: {result['status']} - {result.get('message', '')}")
    
    # 打印统计信息
    stats = results["stats"]
    print("\n--- DNS查询统计 ---")
    print(f"发送 = {stats['transmitted']}, 接收 = {stats['received']}, 丢包率 = {stats['loss']}%")
    
    if stats["received"] > 0:
        print(f"往返时间 (ms): 最小 = {stats['min_rtt']}, 平均 = {stats['avg_rtt']}, 最大 = {stats['max_rtt']}")