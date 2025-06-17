#!/usr/bin/env python

import socket
import struct
import random
import time
import sys
import json

# DNS查询类型常量
QTYPE_A = 1      # IPv4地址
QTYPE_NS = 2     # 域名服务器
QTYPE_CNAME = 5  # 规范名称
QTYPE_SOA = 6    # 权威记录开始
QTYPE_PTR = 12   # 指针记录
QTYPE_MX = 15    # 邮件交换
QTYPE_TXT = 16   # 文本记录
QTYPE_AAAA = 28  # IPv6地址
QTYPE_ANY = 255  # 任何记录

# DNS响应码
RCODE_NOERROR = 0    # 没有错误
RCODE_FORMERR = 1    # 格式错误
RCODE_SERVFAIL = 2   # 服务器失败
RCODE_NXDOMAIN = 3   # 不存在的域名
RCODE_NOTIMP = 4     # 未实现
RCODE_REFUSED = 5    # 查询被拒绝

# 查询类型映射
QTYPE_MAP = {
    'A': QTYPE_A,
    'NS': QTYPE_NS,
    'CNAME': QTYPE_CNAME,
    'SOA': QTYPE_SOA,
    'PTR': QTYPE_PTR,
    'MX': QTYPE_MX,
    'TXT': QTYPE_TXT,
    'AAAA': QTYPE_AAAA,
    'ANY': QTYPE_ANY
}

# 响应码映射
RCODE_MAP = {
    RCODE_NOERROR: "没有错误",
    RCODE_FORMERR: "格式错误",
    RCODE_SERVFAIL: "服务器失败",
    RCODE_NXDOMAIN: "不存在的域名",
    RCODE_NOTIMP: "未实现",
    RCODE_REFUSED: "查询被拒绝"
}

def generate_query_id():
    """生成随机的DNS查询ID"""
    return random.randint(0, 65535)

def encode_domain_name(domain):
    """将域名编码为DNS查询格式"""
    result = b''
    for part in domain.split('.'):
        result += struct.pack('B', len(part)) + part.encode('ascii')
    result += b'\x00'  # 以0字节结束
    return result

def decode_domain_name(message, offset):
    """从DNS响应中解码域名"""
    domain_parts = []
    while True:
        length = message[offset]
        offset += 1
        
        # 检查是否有压缩指针
        if (length & 0xC0) == 0xC0:
            # 这是一个指针，获取指向的位置
            pointer = ((length & 0x3F) << 8) | message[offset]
            offset += 1
            # 递归解析指针指向的域名
            pointed_domain, _ = decode_domain_name(message, pointer)
            domain_parts.append(pointed_domain)
            break
        elif length == 0:
            # 域名结束
            break
        else:
            # 正常的标签
            domain_parts.append(message[offset:offset+length].decode('ascii'))
            offset += length
    
    return '.'.join(domain_parts), offset

def parse_dns_response(response_data):
    """解析DNS响应数据"""
    # 解析DNS头部
    header = struct.unpack('!HHHHHH', response_data[:12])
    query_id = header[0]
    flags = header[1]
    qdcount = header[2]  # 问题数
    ancount = header[3]  # 回答数
    nscount = header[4]  # 授权记录数
    arcount = header[5]  # 附加记录数
    
    # 检查响应码
    rcode = flags & 0x0F
    if rcode != RCODE_NOERROR:
        return {
            'status': 'error',
            'message': f'DNS响应错误: {RCODE_MAP.get(rcode, "未知错误")}'
        }
    
    # 跳过问题部分
    offset = 12
    for _ in range(qdcount):
        # 跳过域名
        while True:
            length = response_data[offset]
            offset += 1
            if length == 0 or (length & 0xC0) == 0xC0:
                if (length & 0xC0) == 0xC0:
                    offset += 1  # 跳过指针的第二个字节
                break
            offset += length
        # 跳过查询类型和查询类
        offset += 4
    
    # 解析回答部分
    answers = []
    for _ in range(ancount):
        # 解析域名
        name, offset = decode_domain_name(response_data, offset)
        
        # 解析记录类型、类、TTL和数据长度
        record_type, record_class, ttl, data_length = struct.unpack('!HHIH', response_data[offset:offset+10])
        offset += 10
        
        # 根据记录类型解析数据
        record_data = ''
        if record_type == QTYPE_A:
            # A记录 - IPv4地址
            ip_bytes = response_data[offset:offset+data_length]
            record_data = '.'.join(str(b) for b in ip_bytes)
        elif record_type == QTYPE_AAAA:
            # AAAA记录 - IPv6地址
            ip_bytes = response_data[offset:offset+data_length]
            record_data = ':'.join(f'{ip_bytes[i*2:i*2+2].hex()}' for i in range(8))
        elif record_type == QTYPE_MX:
            # MX记录 - 邮件交换
            preference = struct.unpack('!H', response_data[offset:offset+2])[0]
            mx_name, _ = decode_domain_name(response_data, offset+2)
            record_data = f'{preference} {mx_name}'
        elif record_type == QTYPE_NS or record_type == QTYPE_CNAME or record_type == QTYPE_PTR:
            # NS, CNAME, PTR记录 - 域名
            record_data, _ = decode_domain_name(response_data, offset)
        elif record_type == QTYPE_TXT:
            # TXT记录 - 文本
            txt_length = response_data[offset]
            record_data = response_data[offset+1:offset+1+txt_length].decode('ascii', errors='ignore')
        else:
            # 其他记录类型
            record_data = response_data[offset:offset+data_length].hex()
        
        # 添加到回答列表
        answers.append({
            'name': name,
            'type': {v: k for k, v in QTYPE_MAP.items()}.get(record_type, str(record_type)),
            'class': 'IN' if record_class == 1 else str(record_class),
            'ttl': ttl,
            'data': record_data
        })
        
        offset += data_length
    
    return {
        'status': 'success',
        'answers': answers
    }

def create_dns_query(domain, query_type='A'):
    """创建DNS查询数据包"""
    # 获取查询类型的数值
    qtype_value = QTYPE_MAP.get(query_type, QTYPE_A)
    
    # 生成随机查询ID
    query_id = generate_query_id()
    
    # 构建DNS头部
    # ID, 标志, 问题数, 回答数, 授权记录数, 附加记录数
    header = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
    
    # 构建问题部分
    question = encode_domain_name(domain) + struct.pack('!HH', qtype_value, 1)  # 查询类型和查询类(IN)
    
    # 组合完整的查询包
    query_packet = header + question
    
    # 为TCP添加长度前缀
    tcp_packet = struct.pack('!H', len(query_packet)) + query_packet
    
    return query_id, tcp_packet

def tcp_dns_query(domain, server, port=53, query_type='A', timeout=5):
    """执行单次TCP DNS查询"""
    start_time = time.time()
    
    try:
        # 创建TCP套接字
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # 连接到DNS服务器
        try:
            sock.connect((server, port))
        except socket.error as e:
            return {
                'status': 'error',
                'message': f'连接DNS服务器失败: {str(e)}'
            }
        
        # 创建并发送DNS查询
        query_id, query_packet = create_dns_query(domain, query_type)
        try:
            sock.sendall(query_packet)
        except socket.error as e:
            sock.close()
            return {
                'status': 'error',
                'message': f'发送查询失败: {str(e)}'
            }
        
        # 接收响应长度
        try:
            length_bytes = sock.recv(2)
            if not length_bytes or len(length_bytes) < 2:
                sock.close()
                return {
                    'status': 'error',
                    'message': '接收响应长度失败'
                }
            
            response_length = struct.unpack('!H', length_bytes)[0]
            
            # 接收完整响应
            response_data = b''
            while len(response_data) < response_length:
                chunk = sock.recv(response_length - len(response_data))
                if not chunk:
                    break
                response_data += chunk
            
            # 检查是否接收到完整响应
            if len(response_data) < response_length:
                sock.close()
                return {
                    'status': 'error',
                    'message': f'接收不完整: 预期{response_length}字节，实际接收{len(response_data)}字节'
                }
        except socket.error as e:
            sock.close()
            return {
                'status': 'error',
                'message': f'接收响应失败: {str(e)}'
            }
        
        # 关闭套接字
        sock.close()
        
        # 计算往返时间
        rtt = (time.time() - start_time) * 1000  # 毫秒
        
        # 解析响应
        result = parse_dns_response(response_data)
        if result['status'] == 'success':
            result['rtt'] = rtt
        
        return result
    
    except socket.timeout:
        try:
            sock.close()
        except:
            pass
        return {
            'status': 'timeout',
            'message': 'DNS查询超时'
        }
    except socket.error as e:
        try:
            sock.close()
        except:
            pass
        return {
            'status': 'error',
            'message': f'套接字错误: {str(e)}'
        }
    except Exception as e:
        try:
            sock.close()
        except:
            pass
        return {
            'status': 'error',
            'message': f'查询错误: {str(e)}'
        }

def tcp_dns_test(domain, server, port=53, query_type='A', count=5, interval=1000):
    """执行多次TCP DNS查询测试"""
    results = []
    rtts = []
    transmitted = 0
    received = 0
    
    for i in range(count):
        transmitted += 1
        
        # 执行查询
        result = tcp_dns_query(domain, server, port, query_type)
        result['seq'] = i + 1
        
        # 添加到结果列表
        results.append(result)
        
        # 统计成功的查询
        if result['status'] == 'success':
            received += 1
            rtts.append(result['rtt'])
        
        # 等待指定的间隔时间
        if i < count - 1:
            time.sleep(interval / 1000)  # 转换为秒
    
    # 计算统计信息
    stats = {
        'transmitted': transmitted,
        'received': received,
        'loss': 0 if transmitted == 0 else round((transmitted - received) / transmitted * 100, 1)
    }
    
    if rtts:
        stats['min_rtt'] = round(min(rtts), 2)
        stats['avg_rtt'] = round(sum(rtts) / len(rtts), 2)
        stats['max_rtt'] = round(max(rtts), 2)
    
    return {
        'domain': domain,
        'server': server,
        'port': port,
        'query_type': query_type,
        'results': results,
        'stats': stats
    }

# 命令行接口
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='TCP DNS查询工具')
    parser.add_argument('domain', help='要查询的域名')
    parser.add_argument('--server', '-s', default='8.8.8.8', help='DNS服务器IP (默认: 8.8.8.8)')
    parser.add_argument('--port', '-p', type=int, default=53, help='DNS服务器端口 (默认: 53)')
    parser.add_argument('--type', '-t', default='A', choices=list(QTYPE_MAP.keys()), help='查询类型 (默认: A)')
    parser.add_argument('--count', '-c', type=int, default=5, help='查询次数 (默认: 5)')
    parser.add_argument('--interval', '-i', type=int, default=1000, help='查询间隔(毫秒) (默认: 1000)')
    parser.add_argument('--json', '-j', action='store_true', help='以JSON格式输出结果')
    
    args = parser.parse_args()
    
    result = tcp_dns_test(args.domain, args.server, args.port, args.type, args.count, args.interval)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"TCP DNS查询: {args.domain} ({args.type})")
        print(f"DNS服务器: {args.server}:{args.port}\n")
        
        for query in result['results']:
            if query['status'] == 'success':
                print(f"查询 {query['seq']}: 成功，RTT = {query['rtt']:.2f} ms，找到 {len(query['answers'])} 条记录")
                for answer in query['answers']:
                    print(f"  {answer['name']} {answer['ttl']} IN {answer['type']} {answer['data']}")
            else:
                print(f"查询 {query['seq']}: {query['status']} - {query.get('message', '未知错误')}")
        
        print("\n统计信息:")
        stats = result['stats']
        print(f"发送 = {stats['transmitted']}, 接收 = {stats['received']}, 丢包率 = {stats['loss']}%")
        
        if stats['received'] > 0:
            print(f"往返时间 (ms): 最小 = {stats.get('min_rtt', 0):.2f}, 平均 = {stats.get('avg_rtt', 0):.2f}, 最大 = {stats.get('max_rtt', 0):.2f}")