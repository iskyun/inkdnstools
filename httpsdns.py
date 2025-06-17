#!/usr/bin/env python

import requests
import json
import time
import sys
import base64
import struct
import socket

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

# 默认DoH服务器
DEFAULT_DOH_SERVERS = {
    'Google': 'https://dns.google/dns-query',
    'Cloudflare': 'https://cloudflare-dns.com/dns-query',
    'Quad9': 'https://dns.quad9.net/dns-query'
}

def encode_domain_name(domain):
    """将域名编码为DNS查询格式"""
    result = b''
    for part in domain.split('.'):
        result += struct.pack('B', len(part)) + part.encode('ascii')
    result += b'\x00'  # 以0字节结束
    return result

def create_dns_wire_format(domain, query_type='A'):
    """创建DNS查询的二进制格式（wire format）"""
    # 获取查询类型的数值
    qtype_value = QTYPE_MAP.get(query_type, QTYPE_A)
    
    # 生成随机查询ID
    query_id = 0x1234  # 固定ID，因为DoH服务器会忽略它
    
    # 构建DNS头部
    # ID, 标志, 问题数, 回答数, 授权记录数, 附加记录数
    header = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0)
    
    # 构建问题部分
    question = encode_domain_name(domain) + struct.pack('!HH', qtype_value, 1)  # 查询类型和查询类(IN)
    
    # 组合完整的查询包
    return header + question

def parse_json_response(json_data, query_type):
    """解析DoH JSON响应"""
    if 'Status' in json_data and json_data['Status'] != 0:
        return {
            'status': 'error',
            'message': f'DNS响应错误: 状态码 {json_data["Status"]}'
        }
    
    answers = []
    if 'Answer' in json_data:
        for answer in json_data['Answer']:
            record_type = answer.get('type', 0)
            record_data = answer.get('data', '')
            
            # 处理特定类型的数据格式
            if record_type == QTYPE_A or record_type == QTYPE_AAAA:
                # A或AAAA记录可能包含额外信息，只保留IP地址
                if ' ' in record_data:
                    record_data = record_data.split(' ')[0]
            
            answers.append({
                'name': answer.get('name', '').rstrip('.'),
                'type': {v: k for k, v in QTYPE_MAP.items()}.get(record_type, str(record_type)),
                'ttl': answer.get('TTL', 0),
                'data': record_data
            })
    
    return {
        'status': 'success',
        'answers': answers
    }

def https_dns_query(domain, doh_url=None, query_type='A', timeout=5):
    """执行单次HTTPS DNS查询"""
    start_time = time.time()
    
    # 如果没有提供DoH URL，使用Google的默认服务
    if not doh_url:
        doh_url = DEFAULT_DOH_SERVERS['Google']
    
    try:
        # 准备请求头
        headers = {
            'Accept': 'application/dns-json'
        }
        
        # 准备查询参数
        params = {
            'name': domain,
            'type': query_type
        }
        
        # 发送GET请求
        try:
            response = requests.get(doh_url, headers=headers, params=params, timeout=timeout)
        except requests.exceptions.ConnectionError as e:
            return {
                'status': 'error',
                'message': f'连接错误: {str(e)}'
            }
        except requests.exceptions.Timeout:
            return {
                'status': 'timeout',
                'message': 'DNS查询超时'
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'message': f'请求错误: {str(e)}'
            }
        
        # 检查响应状态
        if response.status_code != 200:
            return {
                'status': 'error',
                'message': f'HTTP错误: {response.status_code} - {response.reason}'
            }
        
        # 解析JSON响应
        try:
            json_data = response.json()
        except json.JSONDecodeError as e:
            return {
                'status': 'error',
                'message': f'无效的JSON响应: {str(e)}'
            }
            
        result = parse_json_response(json_data, query_type)
        
        # 计算往返时间
        rtt = (time.time() - start_time) * 1000  # 毫秒
        
        if result['status'] == 'success':
            result['rtt'] = rtt
        
        return result
    
    except Exception as e:
        return {
            'status': 'error',
            'message': f'查询错误: {str(e)}'
        }

def https_dns_query_wire_format(domain, doh_url=None, query_type='A', timeout=5):
    """使用二进制格式执行HTTPS DNS查询"""
    start_time = time.time()
    
    # 如果没有提供DoH URL，使用Google的默认服务
    if not doh_url:
        doh_url = DEFAULT_DOH_SERVERS['Google']
    
    try:
        # 创建DNS查询的二进制格式
        dns_wire = create_dns_wire_format(domain, query_type)
        
        # 准备请求头
        headers = {
            'Accept': 'application/dns-message',
            'Content-Type': 'application/dns-message'
        }
        
        # 发送POST请求
        try:
            response = requests.post(doh_url, headers=headers, data=dns_wire, timeout=timeout)
        except requests.exceptions.ConnectionError as e:
            return {
                'status': 'error',
                'message': f'连接错误: {str(e)}'
            }
        except requests.exceptions.Timeout:
            return {
                'status': 'timeout',
                'message': 'DNS查询超时'
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'message': f'请求错误: {str(e)}'
            }
        
        # 检查响应状态
        if response.status_code != 200:
            return {
                'status': 'error',
                'message': f'HTTP错误: {response.status_code} - {response.reason}'
            }
        
        # 解析二进制响应
        binary_response = response.content
        
        # 检查响应长度
        if len(binary_response) < 12:
            return {
                'status': 'error',
                'message': f'响应数据太短: 只有{len(binary_response)}字节'
            }
            
        try:
            header = struct.unpack('!HHHHHH', binary_response[:12])
            flags = header[1]
            rcode = flags & 0x0F
            
            if rcode != 0:
                return {
                    'status': 'error',
                    'message': f'DNS响应错误: 状态码 {rcode}'
                }
        except struct.error as e:
            return {
                'status': 'error',
                'message': f'解析DNS头部失败: {str(e)}'
            }
        
        # 计算往返时间
        rtt = (time.time() - start_time) * 1000  # 毫秒
        
        # 这里我们不解析完整的DNS响应，只返回成功状态和RTT
        # 实际应用中可能需要完整解析响应
        return {
            'status': 'success',
            'rtt': rtt,
            'answers': [{'name': domain, 'type': query_type, 'data': '(binary response)'}]
        }
    
    except Exception as e:
        return {
            'status': 'error',
            'message': f'查询错误: {str(e)}'
        }

def https_dns_test(domain, doh_url=None, query_type='A', count=5, interval=1000, use_wire_format=False):
    """执行多次HTTPS DNS查询测试"""
    results = []
    rtts = []
    transmitted = 0
    received = 0
    
    # 如果没有提供DoH URL，使用Google的默认服务
    if not doh_url:
        doh_url = DEFAULT_DOH_SERVERS['Google']
    
    for i in range(count):
        transmitted += 1
        
        # 执行查询
        if use_wire_format:
            result = https_dns_query_wire_format(domain, doh_url, query_type)
        else:
            result = https_dns_query(domain, doh_url, query_type)
        
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
        'doh_url': doh_url,
        'query_type': query_type,
        'results': results,
        'stats': stats
    }

# 命令行接口
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='HTTPS DNS查询工具 (DoH)')
    parser.add_argument('domain', help='要查询的域名')
    parser.add_argument('--server', '-s', choices=list(DEFAULT_DOH_SERVERS.keys()), default='Google', 
                        help=f'DoH服务器 (默认: Google)')
    parser.add_argument('--url', '-u', help='自定义DoH服务器URL')
    parser.add_argument('--type', '-t', default='A', choices=list(QTYPE_MAP.keys()), help='查询类型 (默认: A)')
    parser.add_argument('--count', '-c', type=int, default=5, help='查询次数 (默认: 5)')
    parser.add_argument('--interval', '-i', type=int, default=1000, help='查询间隔(毫秒) (默认: 1000)')
    parser.add_argument('--wire', '-w', action='store_true', help='使用二进制格式 (wire format)')
    parser.add_argument('--json', '-j', action='store_true', help='以JSON格式输出结果')
    
    args = parser.parse_args()
    
    # 确定DoH服务器URL
    doh_url = args.url if args.url else DEFAULT_DOH_SERVERS[args.server]
    
    result = https_dns_test(args.domain, doh_url, args.type, args.count, args.interval, args.wire)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"HTTPS DNS查询 (DoH): {args.domain} ({args.type})")
        print(f"DoH服务器: {doh_url}\n")
        
        for query in result['results']:
            if query['status'] == 'success':
                print(f"查询 {query['seq']}: 成功，RTT = {query['rtt']:.2f} ms，找到 {len(query['answers'])} 条记录")
                for answer in query['answers']:
                    print(f"  {answer['name']} {answer.get('ttl', 0)} IN {answer['type']} {answer['data']}")
            else:
                print(f"查询 {query['seq']}: {query['status']} - {query.get('message', '未知错误')}")
        
        print("\n统计信息:")
        stats = result['stats']
        print(f"发送 = {stats['transmitted']}, 接收 = {stats['received']}, 丢包率 = {stats['loss']}%")
        
        if stats['received'] > 0:
            print(f"往返时间 (ms): 最小 = {stats.get('min_rtt', 0):.2f}, 平均 = {stats.get('avg_rtt', 0):.2f}, 最大 = {stats.get('max_rtt', 0):.2f}")