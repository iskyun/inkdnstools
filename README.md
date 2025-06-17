# Ink 网络测试工具

一个功能强大的网络测试工具，提供多种网络诊断功能，包括UDP/TCP Ping和多种DNS查询方式，并提供友好的Web界面。

## 功能特点

- **UDP Ping**: 测试UDP连接性能和可靠性
- **TCP Ping**: 测试TCP连接性能和可靠性
- **UDP DNS查询**: 使用传统UDP协议进行DNS查询
- **TCP DNS查询**: 使用TCP协议进行DNS查询
- **HTTPS DNS查询**: 使用DoH(DNS over HTTPS)进行安全DNS查询
- **Web界面**: 提供直观的图形界面，方便用户操作和查看结果

## 技术栈

- **后端**: Python + Flask
- **前端**: HTML + CSS + JavaScript + Bootstrap
- **网络协议**: UDP, TCP, HTTPS

## 安装

### 环境要求

- Python 3.6+
- pip包管理器

### 安装步骤

1. 克隆或下载本项目到本地

2. 安装依赖包

```bash
pip install -r requirements.txt
```

## 使用方法

### 启动Web服务

```bash
python web.py
```

启动后，在浏览器中访问 `http://localhost:5000` 即可使用Web界面。

### 功能说明

#### UDP/TCP Ping

- **目标IP**: 要测试的服务器IP地址
- **端口**: 要测试的服务器端口
- **包长度**: 发送数据包的大小(字节)
- **间隔**: 发送数据包的时间间隔(毫秒)
- **次数**: 发送数据包的总次数

#### DNS查询

- **域名**: 要查询的域名
- **DNS服务器**: 用于查询的DNS服务器IP地址
- **端口**: DNS服务器端口(通常为53)
- **查询类型**: 支持A, AAAA, CNAME, MX, NS, TXT等多种记录类型
- **查询次数**: 执行查询的总次数

#### HTTPS DNS查询(DoH)

- **域名**: 要查询的域名
- **DoH服务器**: 支持Google, Cloudflare, Quad9等主流DoH服务提供商
- **查询类型**: 支持多种DNS记录类型
- **查询次数**: 执行查询的总次数

## 项目结构

- `web.py`: Web服务器和API接口
- `udpping.py`: UDP Ping实现
- `tcpping.py`: TCP Ping实现
- `udpdns.py`: UDP DNS查询实现
- `tcpdns.py`: TCP DNS查询实现
- `httpsdns.py`: HTTPS DNS(DoH)查询实现
- `templates/`: Web界面模板
- `requirements.txt`: 项目依赖

## 贡献

欢迎提交问题和功能请求。如果您想贡献代码，请提交拉取请求。

## 许可

本项目采用MIT许可证。详见LICENSE文件。
